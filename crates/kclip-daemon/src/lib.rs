use kclip_protocol::{
    DaemonStatus, ErrorCode, FrameError, Operation, PROTOCOL_VERSION, ProtocolError, Request,
    Response, ResponsePayload, read_frame_with_limit, write_frame,
};
use kclip_storage::{Storage, StorageError};
use std::{
    fs,
    future::Future,
    io,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
};
use thiserror::Error;
use tokio::{
    net::{UnixListener, UnixStream},
    sync::Semaphore,
    task::JoinSet,
};
use tracing::{debug, error, info, warn};

pub const DAEMON_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub socket_path: PathBuf,
    pub database_path: PathBuf,
    pub blob_directory: PathBuf,
    pub max_content_size: u64,
}

pub async fn run_until<F>(config: ServerConfig, shutdown: F) -> Result<(), DaemonError>
where
    F: Future<Output = ()>,
{
    prepare_private_directory(
        config
            .database_path
            .parent()
            .ok_or_else(|| DaemonError::Configuration("database path has no parent".into()))?,
    )?;
    prepare_private_directory(&config.blob_directory)?;

    let storage = Arc::new(Storage::open(
        &config.database_path,
        &config.blob_directory,
        config.max_content_size,
    )?);
    let (listener, socket_guard) = bind_socket(&config.socket_path).await?;
    let current_uid = unsafe { libc::geteuid() };
    let maximum_request_frame = usize::try_from(config.max_content_size)
        .unwrap_or(usize::MAX)
        .saturating_add(1024 * 1024);
    let concurrency = Arc::new(Semaphore::new(64));
    let mut clients = JoinSet::new();
    tokio::pin!(shutdown);

    info!(
        socket = %config.socket_path.display(),
        max_content_size = config.max_content_size,
        "kclipd ready"
    );

    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => {
                info!("shutdown requested");
                break;
            }
            Some(result) = clients.join_next(), if !clients.is_empty() => {
                if let Err(join_error) = result {
                    error!(error = %join_error, "client task failed");
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let credentials = match stream.peer_cred() {
                    Ok(credentials) => credentials,
                    Err(source) => {
                        warn!(error = %source, "could not inspect local client credentials");
                        continue;
                    }
                };
                if credentials.uid() != current_uid {
                    warn!(peer_uid = credentials.uid(), "rejected cross-user local client");
                    let mut stream = stream;
                    let response = Response::error(
                        0,
                        ProtocolError::new(ErrorCode::PermissionDenied, "client user does not own this daemon"),
                    );
                    let _ = write_frame(&mut stream, &response).await;
                    continue;
                }

                let storage = Arc::clone(&storage);
                let concurrency = Arc::clone(&concurrency);
                clients.spawn(async move {
                    let permit = concurrency.acquire_owned().await;
                    if permit.is_err() {
                        return;
                    }
                    if let Err(source) = handle_client(stream, storage, maximum_request_frame).await {
                        debug!(error = %source, "local client disconnected with an error");
                    }
                });
            }
        }
    }

    drop(listener);
    while let Some(result) = clients.join_next().await {
        if let Err(join_error) = result {
            error!(error = %join_error, "client task failed during shutdown");
        }
    }
    drop(socket_guard);
    info!("kclipd stopped");
    Ok(())
}

async fn handle_client(
    mut stream: UnixStream,
    storage: Arc<Storage>,
    maximum_request_frame: usize,
) -> Result<(), ClientError> {
    let request: Request = match read_frame_with_limit(&mut stream, maximum_request_frame).await {
        Ok(request) => request,
        Err(source) => {
            warn!(category = "malformed_frame", error = %source, "rejected malformed IPC frame");
            let response = Response::error(
                0,
                ProtocolError::new(ErrorCode::InvalidRequest, "malformed IPC request"),
            );
            let _ = write_frame(&mut stream, &response).await;
            return Err(ClientError::Frame(source));
        }
    };
    let operation_name = request.operation.name();
    debug!(
        request_id = request.request_id,
        operation = operation_name,
        "received local request"
    );

    if request.protocol_version != PROTOCOL_VERSION {
        let response = Response::error(
            request.request_id,
            ProtocolError::new(
                ErrorCode::ProtocolMismatch,
                format!(
                    "unsupported protocol version {}; expected {}",
                    request.protocol_version, PROTOCOL_VERSION
                ),
            )
            .for_operation(operation_name),
        );
        write_frame(&mut stream, &response).await?;
        return Ok(());
    }

    let request_id = request.request_id;
    let operation = request.operation;
    let result = tokio::task::spawn_blocking(move || process_operation(&storage, operation))
        .await
        .map_err(ClientError::Task)?;
    let response = match result {
        Ok(payload) => Response::success(request_id, payload),
        Err(error) => Response::error(request_id, error.for_operation(operation_name)),
    };
    write_frame(&mut stream, &response).await?;
    Ok(())
}

fn process_operation(
    storage: &Storage,
    operation: Operation,
) -> Result<ResponsePayload, ProtocolError> {
    match operation {
        Operation::Copy {
            slot,
            content,
            content_type,
        } => storage
            .copy(&slot, &content, content_type.as_deref())
            .map(ResponsePayload::Stored)
            .map_err(storage_error),
        Operation::Paste { slot } => storage
            .paste(&slot)
            .map(|(metadata, content)| ResponsePayload::Value { metadata, content })
            .map_err(storage_error),
        Operation::List => storage
            .list()
            .map(ResponsePayload::Slots)
            .map_err(storage_error),
        Operation::Clear { slot } => storage
            .clear(&slot)
            .map(ResponsePayload::Cleared)
            .map_err(storage_error),
        Operation::Status => Ok(ResponsePayload::Status(DaemonStatus {
            daemon_available: true,
            daemon_version: DAEMON_VERSION.into(),
            schema_version: storage.schema_version(),
            device_id: storage.device_id().map_err(storage_error)?,
            synchronization_enabled: false,
            plasma_enabled: false,
        })),
    }
}

fn storage_error(error: StorageError) -> ProtocolError {
    match error {
        StorageError::SlotNotFound(_) => {
            ProtocolError::new(ErrorCode::SlotNotFound, "slot is missing or cleared")
        }
        StorageError::InvalidSlot(message) => {
            ProtocolError::new(ErrorCode::InvalidSlotName, message)
        }
        StorageError::ContentTooLarge { actual, maximum } => ProtocolError::new(
            ErrorCode::ContentTooLarge,
            format!("content size {actual} exceeds configured maximum {maximum}"),
        ),
        StorageError::LockPoisoned => {
            let mut error = ProtocolError::new(
                ErrorCode::StorageFailure,
                "storage is temporarily unavailable",
            );
            error.retryable = true;
            error.category = Some("lock".into());
            error
        }
        _ => {
            error!(category = "storage", error = %error, "storage operation failed");
            ProtocolError {
                code: ErrorCode::StorageFailure,
                message: "local storage operation failed".into(),
                retryable: false,
                operation: None,
                category: Some("storage".into()),
            }
        }
    }
}

async fn bind_socket(path: &Path) -> Result<(UnixListener, SocketGuard), DaemonError> {
    let parent = path
        .parent()
        .ok_or_else(|| DaemonError::Configuration("socket path has no parent directory".into()))?;
    prepare_private_directory(parent)?;

    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_socket() {
            return Err(DaemonError::UnsafeSocket(
                "refusing to replace a non-socket filesystem entry".into(),
            ));
        }
        let current_uid = unsafe { libc::geteuid() };
        if metadata.uid() != current_uid {
            return Err(DaemonError::UnsafeSocket(
                "existing socket is owned by another user".into(),
            ));
        }
        if UnixStream::connect(path).await.is_ok() {
            return Err(DaemonError::AlreadyRunning(path.to_path_buf()));
        }
        fs::remove_file(path)?;
    }

    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    let metadata = fs::metadata(path)?;
    let guard = SocketGuard {
        path: path.to_path_buf(),
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    Ok((listener, guard))
}

fn prepare_private_directory(path: &Path) -> Result<(), DaemonError> {
    if !path.exists() {
        fs::create_dir_all(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() {
        return Err(DaemonError::UnsafeDirectory(
            "path is not a directory".into(),
        ));
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(DaemonError::UnsafeDirectory(
            "directory is owned by another user".into(),
        ));
    }
    if metadata.mode() & 0o077 != 0 {
        return Err(DaemonError::UnsafeDirectory(format!(
            "directory permissions {:o} allow access by other users; expected 0700",
            metadata.mode() & 0o777
        )));
    }
    Ok(())
}

struct SocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("invalid daemon configuration: {0}")]
    Configuration(String),
    #[error("unsafe daemon directory: {0}")]
    UnsafeDirectory(String),
    #[error("unsafe daemon socket: {0}")]
    UnsafeSocket(String),
    #[error("another daemon is already listening at {0}")]
    AlreadyRunning(PathBuf),
    #[error("daemon I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("daemon storage initialization failed: {0}")]
    Storage(#[from] StorageError),
}

#[derive(Debug, Error)]
enum ClientError {
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("request task failed: {0}")]
    Task(#[from] tokio::task::JoinError),
}
