use clap::{Parser, Subcommand};
use kclip_config::{
    Config, ConfigError, default_pairing_path, default_sync_key_path, default_token_path,
};
use kclip_crypto::{
    atomic_write_secret, generate_sync_key, import_legacy_key, key_from_mnemonic, mnemonic_for_key,
    read_sync_key, write_sync_key,
};
use kclip_protocol::{
    DEFAULT_SLOT, ErrorCode, FrameError, MAX_FRAME_SIZE, Operation, PROTOCOL_VERSION,
    ProtocolError, Request, Response, ResponsePayload, ResponseResult, RevisionMetadata,
    read_frame, write_frame,
};
use kclip_sync::{
    AuthClient, SyncError, TokenFile, read_pairing, read_token, remove_pairing, remove_token,
    write_pairing_code, write_token,
};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
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

        /// Keep this revision on this device even when synchronization is enabled.
        #[arg(long)]
        local: bool,
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

        /// Create a local-only tombstone that is not uploaded.
        #[arg(long)]
        local: bool,
    },

    /// Show local daemon and synchronization health without exposing secrets.
    Status,

    /// Manage the PyPasteServer device credential.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },

    /// Manage the shared 32-byte account synchronization key.
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },

    /// Import the legacy Python client's token and key into kclip-owned paths.
    MigrateLegacy {
        #[arg(long)]
        token_file: Option<PathBuf>,
        #[arg(long)]
        key_file: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Subcommand)]
pub enum AuthCommand {
    /// Store a one-time pairing code entered through hidden input.
    Pair,
    Register {
        #[arg(long)]
        username: Option<String>,
        #[arg(long)]
        email: Option<String>,
    },
    Login {
        #[arg(long)]
        username: Option<String>,
    },
    Logout {
        /// Remove the local token without contacting the server.
        #[arg(long)]
        local: bool,
    },
    Status,
}

#[derive(Debug, Clone, Subcommand)]
pub enum KeyCommand {
    Generate {
        /// Replace an existing key. This disconnects the device from old ciphertext.
        #[arg(long)]
        force: bool,
    },
    Import {
        /// File containing a raw 32-byte key. Omit to enter a 24-word mnemonic securely.
        #[arg(long)]
        file: Option<PathBuf>,
    },
    Export {
        /// Required acknowledgement that the recovery mnemonic will be printed.
        #[arg(long)]
        show: bool,
    },
}

pub async fn execute(
    cli: &Cli,
    input: &mut dyn Read,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    match &cli.command {
        Command::Copy {
            slot,
            file,
            content_type,
            local,
        } => {
            let socket = local_socket(cli)?;
            let content = read_copy_input(file.as_deref(), input)?;
            let response = send_request(
                &socket,
                Operation::Copy {
                    slot: slot.clone(),
                    content,
                    content_type: content_type.clone(),
                    local: *local,
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
            let socket = local_socket(cli)?;
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
            let socket = local_socket(cli)?;
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
        Command::Clear { slot, local } => {
            let socket = local_socket(cli)?;
            let response = send_request(
                &socket,
                Operation::Clear {
                    slot: slot.clone(),
                    local: *local,
                },
            )
            .await?;
            let ResponsePayload::Cleared(metadata) = response else {
                return Err(CliError::UnexpectedResponse);
            };
            if cli.json {
                write_json(output, &metadata)?;
            }
        }
        Command::Status => {
            let socket = local_socket(cli)?;
            let response = send_request(&socket, Operation::Status).await?;
            let ResponsePayload::Status(status) = response else {
                return Err(CliError::UnexpectedResponse);
            };
            if cli.json {
                write_json(output, &status)?;
            } else {
                writeln!(output, "daemon: available ({})", status.daemon_version)?;
                writeln!(output, "device: {}", status.device_id)?;
                writeln!(output, "sync: {}", status.synchronization_state)?;
                writeln!(output, "authenticated: {}", status.authenticated)?;
                writeln!(output, "pending outbox: {}", status.pending_outbox_count)?;
                writeln!(output, "server cursor: {}", status.processed_server_cursor)?;
                writeln!(
                    output,
                    "quarantined events: {}",
                    status.quarantined_event_count
                )?;
                if let Some(category) = status.last_sync_error_category {
                    writeln!(output, "last sync error: {category}")?;
                }
            }
        }
        Command::Auth { command } => {
            execute_auth(command, input, output, cli.json).await?;
        }
        Command::Key { command } => execute_key(command, input, output, cli.json)?,
        Command::MigrateLegacy {
            token_file,
            key_file,
        } => migrate_legacy(token_file.as_deref(), key_file.as_deref(), output, cli.json)?,
    }
    Ok(())
}

fn local_socket(cli: &Cli) -> Result<PathBuf, CliError> {
    match &cli.socket {
        Some(path) => Ok(path.clone()),
        None => Ok(Config::load(None)?.resolve_socket(None)?),
    }
}

async fn execute_auth(
    command: &AuthCommand,
    input: &mut dyn Read,
    output: &mut dyn Write,
    json: bool,
) -> Result<(), CliError> {
    let config = Config::load(None)?;
    let token_path = config
        .sync
        .token_path
        .clone()
        .map(Ok)
        .unwrap_or_else(default_token_path)?;
    let pairing_path = config
        .sync
        .pairing_path
        .clone()
        .map(Ok)
        .unwrap_or_else(default_pairing_path)?;
    match command {
        AuthCommand::Status => {
            let (method, state) = match read_pairing(&pairing_path) {
                Ok(_) => ("noise_psk", "present"),
                Err(_) if pairing_path.exists() => ("noise_psk", "invalid_or_unsafe"),
                Err(_) => match read_token(&token_path) {
                    Ok(_) => ("legacy_bearer", "present"),
                    Err(_) if token_path.exists() => ("legacy_bearer", "invalid_or_unsafe"),
                    Err(_) => ("none", "missing"),
                },
            };
            if json {
                write_json(
                    output,
                    &serde_json::json!({
                        "authenticated": state == "present",
                        "method": method,
                        "state": state
                    }),
                )?;
            } else {
                writeln!(output, "authentication: {method} ({state})")?;
            }
        }
        AuthCommand::Pair => {
            let code = rpassword::prompt_password("Pairing code: ")?;
            if code.trim().is_empty() {
                return Err(CliError::Usage("pairing code must not be empty".into()));
            }
            write_pairing_code(&pairing_path, &code)?;
            // Never leave a bearer-token fallback behind after switching this
            // device to pairing authentication.
            remove_token(&token_path)?;
            write_success(output, json, "paired")?;
        }
        AuthCommand::Register { username, email } => {
            let relay = configured_relay(&config)?;
            let username = prompt_value(username.as_deref(), "Username", input, output)?;
            let email = prompt_value(email.as_deref(), "Email", input, output)?;
            let password = rpassword::prompt_password("Password: ")?;
            let confirmation = rpassword::prompt_password("Confirm password: ")?;
            if password.is_empty() || password != confirmation {
                return Err(CliError::Usage(
                    "passwords are empty or do not match".into(),
                ));
            }
            AuthClient::from_relay(relay, token_path)?
                .register(&username, &email, &password)
                .await?;
            write_success(output, json, "registered")?;
        }
        AuthCommand::Login { username } => {
            let relay = configured_relay(&config)?;
            let username = prompt_value(username.as_deref(), "Username", input, output)?;
            let password = rpassword::prompt_password("Password: ")?;
            if password.is_empty() {
                return Err(CliError::Usage("password must not be empty".into()));
            }
            AuthClient::from_relay(relay, token_path)?
                .login(&username, &password)
                .await?;
            write_success(output, json, "logged_in")?;
        }
        AuthCommand::Logout { local } => {
            if pairing_path.exists() {
                remove_pairing(&pairing_path)?;
                remove_token(&token_path)?;
            } else if *local {
                remove_token(&token_path)?;
            } else {
                let relay = configured_relay(&config)?;
                AuthClient::from_relay(relay, token_path)?.logout().await?;
            }
            write_success(output, json, "logged_out")?;
        }
    }
    Ok(())
}

fn execute_key(
    command: &KeyCommand,
    input: &mut dyn Read,
    output: &mut dyn Write,
    json: bool,
) -> Result<(), CliError> {
    let config = Config::load(None)?;
    let path = config
        .security
        .sync_key_path
        .clone()
        .map(Ok)
        .unwrap_or_else(default_sync_key_path)?;
    match command {
        KeyCommand::Generate { force } => {
            if path.exists() && !force {
                return Err(CliError::Usage(
                    "a synchronization key already exists; use --force only when intentionally starting a new account key"
                        .into(),
                ));
            }
            generate_sync_key(&path).map_err(SyncError::from)?;
            write_success(output, json, "key_generated")?;
        }
        KeyCommand::Import { file } => {
            if let Some(source) = file {
                import_legacy_key(source, &path).map_err(SyncError::from)?;
            } else {
                writeln!(
                    output,
                    "Enter the existing 24-word recovery mnemonic (input is hidden):"
                )?;
                let words = rpassword::read_password()?;
                let key = key_from_mnemonic(words.trim()).map_err(SyncError::from)?;
                write_sync_key(&path, &key).map_err(SyncError::from)?;
            }
            write_success(output, json, "key_imported")?;
        }
        KeyCommand::Export { show } => {
            if !show {
                return Err(CliError::Usage(
                    "refusing to print recovery material without --show".into(),
                ));
            }
            let key = read_sync_key(&path).map_err(SyncError::from)?;
            let mnemonic = mnemonic_for_key(&key).map_err(SyncError::from)?;
            if json {
                write_json(output, &serde_json::json!({ "mnemonic": mnemonic }))?;
            } else {
                writeln!(
                    output,
                    "WARNING: anyone with these words can decrypt synchronized clipboard history."
                )?;
                writeln!(output, "{mnemonic}")?;
            }
        }
    }
    let _ = input;
    Ok(())
}

fn migrate_legacy(
    token_source: Option<&Path>,
    key_source: Option<&Path>,
    output: &mut dyn Write,
    json: bool,
) -> Result<(), CliError> {
    let config = Config::load(None)?;
    let home = std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or(ConfigError::MissingHomeDirectory)?;
    let token_source = token_source
        .map(Path::to_path_buf)
        .unwrap_or_else(|| home.join(".config/clipboard_app/token.json"));
    let key_source = key_source
        .map(Path::to_path_buf)
        .unwrap_or_else(|| home.join(".config/clipboard_app/key"));
    let token_destination = config
        .sync
        .token_path
        .clone()
        .map(Ok)
        .unwrap_or_else(default_token_path)?;
    let key_destination = config
        .security
        .sync_key_path
        .clone()
        .map(Ok)
        .unwrap_or_else(default_sync_key_path)?;

    // The legacy Python client commonly created 0644 files. Validate ownership
    // and file type, then copy into private kclip-owned destinations.
    let token: TokenFile = serde_json::from_slice(&read_owned_legacy_file(&token_source)?)?;
    if token.access_token.trim().is_empty() {
        return Err(CliError::Usage("legacy access token is empty".into()));
    }
    let key: [u8; 32] = read_owned_legacy_file(&key_source)?
        .try_into()
        .map_err(|_| CliError::Usage("legacy synchronization key is not 32 bytes".into()))?;
    // Validate both sources before mutating either destination.
    let token_backup = backup_existing_secret(&token_destination)?;
    let _key_backup = backup_existing_secret(&key_destination)?;
    write_token(&token_destination, &token.access_token)?;
    if let Err(error) = atomic_write_secret(&key_destination, &key) {
        restore_secret(&token_destination, token_backup.as_deref())?;
        return Err(SyncError::from(error).into());
    }
    write_success(output, json, "legacy_credentials_imported")
}

fn read_owned_legacy_file(path: &Path) -> Result<Vec<u8>, CliError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.len() > 64 * 1024
    {
        return Err(CliError::Usage(
            "legacy secret must be a regular non-symbolic-link file owned by this user".into(),
        ));
    }
    Ok(fs::read(path)?)
}

fn backup_existing_secret(path: &Path) -> Result<Option<PathBuf>, CliError> {
    if !path.exists() {
        return Ok(None);
    }
    kclip_crypto::validate_secret_file(path).map_err(SyncError::from)?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let file_name = path
        .file_name()
        .ok_or_else(|| CliError::Usage("secret path has no file name".into()))?;
    let backup = path.with_file_name(format!("{}.bak.{timestamp}", file_name.to_string_lossy()));
    if backup.exists() {
        return Err(CliError::Usage(format!(
            "refusing to replace existing migration backup {}",
            backup.display()
        )));
    }
    let bytes = fs::read(path)?;
    atomic_write_secret(&backup, &bytes).map_err(SyncError::from)?;
    Ok(Some(backup))
}

fn restore_secret(path: &Path, backup: Option<&Path>) -> Result<(), CliError> {
    match backup {
        Some(backup) => {
            let bytes = fs::read(backup)?;
            atomic_write_secret(path, &bytes).map_err(SyncError::from)?;
        }
        None => match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        },
    }
    Ok(())
}

fn configured_relay(config: &Config) -> Result<&str, CliError> {
    config
        .sync
        .relay_url
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| CliError::Usage("sync.relay_url must be configured first".into()))
}

fn prompt_value(
    configured: Option<&str>,
    label: &str,
    input: &mut dyn Read,
    output: &mut dyn Write,
) -> Result<String, CliError> {
    if let Some(value) = configured.filter(|value| !value.trim().is_empty()) {
        return Ok(value.to_owned());
    }
    write!(output, "{label}: ")?;
    output.flush()?;
    let mut bytes = Vec::new();
    let mut byte = [0_u8; 1];
    while input.read(&mut byte)? == 1 && byte[0] != b'\n' {
        bytes.push(byte[0]);
    }
    let value = String::from_utf8(bytes)
        .map_err(|_| CliError::Usage(format!("{label} must be valid UTF-8")))?;
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Err(CliError::Usage(format!("{label} must not be empty")));
    }
    Ok(value)
}

fn write_success(output: &mut dyn Write, json: bool, action: &str) -> Result<(), CliError> {
    if json {
        write_json(
            output,
            &serde_json::json!({ "success": true, "action": action }),
        )
    } else {
        writeln!(output, "{action}").map_err(CliError::Io)
    }
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
    #[error("synchronization failed: {0}")]
    Sync(#[from] SyncError),
    #[error("invalid command usage: {0}")]
    Usage(String),
}

impl CliError {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::DaemonUnavailable(_) => 3,
            Self::Remote(error) => error.code.exit_code(),
            Self::Config(_) => 2,
            Self::Usage(_) => 2,
            Self::Sync(SyncError::Authentication | SyncError::Credentials(_)) => 9,
            Self::Sync(_) => 8,
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
