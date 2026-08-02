use clap::{Parser, Subcommand};
use kclip_config::{Config, ConfigError};
use kclip_protocol::{
    DEFAULT_SLOT, ErrorCode, FrameError, MAX_FRAME_SIZE, Operation, PROTOCOL_VERSION,
    ProtocolError, Request, Response, ResponsePayload, ResponseResult, RevisionMetadata,
    read_frame, write_frame,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::net::UnixStream;

static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Parser)]
#[command(
    name = "kclip",
    version,
    about = "Command-line client for the local kclip daemon"
)]
pub struct Cli {
    /// Override the local daemon Unix socket path.
    #[arg(long, global = true)]
    pub socket: Option<PathBuf>,

    /// Emit stable machine-readable JSON where the command supports it.
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, Subcommand)]
pub enum Command {
    /// Read arbitrary bytes and store them in a slot.
    Copy {
        /// Destination slot name.
        #[arg(long, default_value = DEFAULT_SLOT)]
        slot: String,

        /// Read from this file instead of standard input.
        #[arg(long)]
        file: Option<PathBuf>,

        /// Explicit content type; otherwise the daemon safely detects UTF-8 text.
        #[arg(long)]
        content_type: Option<String>,
    },

    /// Write a slot's exact bytes without adding a newline.
    Paste {
        /// Source slot name.
        #[arg(long, default_value = DEFAULT_SLOT)]
        slot: String,

        /// Atomically write to this file instead of standard output.
        #[arg(long)]
        file: Option<PathBuf>,
    },

    /// List current, non-deleted slots.
    List,

    /// Clear a slot by creating a deletion revision.
    Clear {
        /// Slot to clear.
        #[arg(long, default_value = DEFAULT_SLOT)]
        slot: String,
    },
}

pub async fn execute(
    cli: &Cli,
    input: &mut dyn Read,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    let socket = match &cli.socket {
        Some(path) => path.clone(),
        None => Config::load(None)?.resolve_socket(None)?,
    };

    match &cli.command {
        Command::Copy {
            slot,
            file,
            content_type,
        } => {
            let content = read_copy_input(file.as_deref(), input)?;
            let response = send_request(
                &socket,
                Operation::Copy {
                    slot: slot.clone(),
                    content,
                    content_type: content_type.clone(),
                },
            )
            .await?;
            let ResponsePayload::Stored(metadata) = response else {
                return Err(CliError::UnexpectedResponse);
            };
            if cli.json {
                write_json(output, &metadata)?;
            }
        }
        Command::Paste { slot, file } => {
            if cli.json && file.is_none() {
                return Err(CliError::Remote(ProtocolError::new(
                    ErrorCode::UnsupportedOperation,
                    "--json for paste requires --file so clipboard bytes remain unmodified",
                )));
            }
            let response = send_request(&socket, Operation::Paste { slot: slot.clone() }).await?;
            let ResponsePayload::Value { metadata, content } = response else {
                return Err(CliError::UnexpectedResponse);
            };
            if let Some(path) = file {
                atomic_write(path, &content)?;
                if cli.json {
                    write_json(output, &metadata)?;
                }
            } else {
                output.write_all(&content)?;
                output.flush()?;
            }
        }
        Command::List => {
            let response = send_request(&socket, Operation::List).await?;
            let ResponsePayload::Slots(slots) = response else {
                return Err(CliError::UnexpectedResponse);
            };
            if cli.json {
                write_json(output, &slots)?;
            } else {
                write_human_list(output, &slots)?;
            }
        }
        Command::Clear { slot } => {
            let response = send_request(&socket, Operation::Clear { slot: slot.clone() }).await?;
            let ResponsePayload::Cleared(metadata) = response else {
                return Err(CliError::UnexpectedResponse);
            };
            if cli.json {
                write_json(output, &metadata)?;
            }
        }
    }
    Ok(())
}

pub async fn send_request(
    socket: &Path,
    operation: Operation,
) -> Result<ResponsePayload, CliError> {
    let request_id = next_request_id();
    let request = Request::new(request_id, operation);
    let mut stream = UnixStream::connect(socket)
        .await
        .map_err(|source| CliError::DaemonUnavailable(source.kind()))?;
    write_frame(&mut stream, &request).await?;
    let response: Response = read_frame(&mut stream).await?;
    if response.protocol_version != PROTOCOL_VERSION || response.request_id != request_id {
        return Err(CliError::ProtocolMismatch);
    }
    match response.result {
        ResponseResult::Success { payload } => Ok(payload),
        ResponseResult::Error { error } => Err(CliError::Remote(error)),
    }
}

fn read_copy_input(path: Option<&Path>, input: &mut dyn Read) -> Result<Vec<u8>, CliError> {
    let mut reader: Box<dyn Read + '_> = match path {
        Some(path) => Box::new(File::open(path)?),
        None => Box::new(input),
    };
    let mut content = Vec::new();
    reader
        .by_ref()
        .take(MAX_FRAME_SIZE as u64 + 1)
        .read_to_end(&mut content)?;
    if content.len() > MAX_FRAME_SIZE {
        return Err(CliError::Remote(ProtocolError::new(
            ErrorCode::ContentTooLarge,
            "input exceeds the hard IPC frame size limit",
        )));
    }
    Ok(content)
}

fn atomic_write(path: &Path, content: &[u8]) -> Result<(), CliError> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "output path has no file name")
    })?;
    let temporary = parent.join(format!(
        ".{}.kclip-{}-{}.tmp",
        file_name.to_string_lossy(),
        std::process::id(),
        next_request_id()
    ));
    let result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(content)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(CliError::Io)
}

fn write_json(output: &mut dyn Write, value: &impl serde::Serialize) -> Result<(), CliError> {
    serde_json::to_writer(&mut *output, value)?;
    output.write_all(b"\n")?;
    Ok(())
}

fn write_human_list(output: &mut dyn Write, slots: &[RevisionMetadata]) -> Result<(), CliError> {
    for slot in slots {
        let safe_name: String = slot.slot.chars().flat_map(char::escape_default).collect();
        writeln!(
            output,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            safe_name,
            slot.revision_id,
            slot.content_size,
            slot.content_type.as_deref().unwrap_or("-"),
            slot.origin_device_id,
            slot.created_at,
            slot.expires_at
                .map_or_else(|| "-".into(), |value| value.to_string()),
            slot.synchronization_state,
        )?;
    }
    Ok(())
}

fn next_request_id() -> u64 {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos() as u64);
    time ^ ((std::process::id() as u64) << 32) ^ REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
}

#[derive(Debug, Error)]
pub enum CliError {
    #[error("local daemon is unavailable")]
    DaemonUnavailable(io::ErrorKind),
    #[error("daemon returned an error: {0}")]
    Remote(ProtocolError),
    #[error("local IPC failed: {0}")]
    Frame(#[from] FrameError),
    #[error("local daemon returned a mismatched protocol response")]
    ProtocolMismatch,
    #[error("local daemon returned an unexpected response")]
    UnexpectedResponse,
    #[error("local file I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("configuration failed: {0}")]
    Config(#[from] ConfigError),
    #[error("could not encode JSON output: {0}")]
    Json(#[from] serde_json::Error),
}

impl CliError {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::DaemonUnavailable(_) => 3,
            Self::Remote(error) => error.code.exit_code(),
            Self::Config(_) => 2,
            Self::Frame(FrameError::Io(source))
                if matches!(
                    source.kind(),
                    io::ErrorKind::TimedOut
                        | io::ErrorKind::WouldBlock
                        | io::ErrorKind::ConnectionRefused
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::BrokenPipe
                ) =>
            {
                3
            }
            _ => 1,
        }
    }
}
