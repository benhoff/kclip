use clap::{Parser, Subcommand};
use kclip_config::{
    Config, ConfigError, PreparedSyncConfig, SyncResolution, default_config_path,
    default_pairing_path, default_sync_key_path, prepare_sync_disconnect, prepare_sync_setup,
};
use kclip_crypto::{key_from_mnemonic, mnemonic_for_key, read_sync_key, write_sync_key};
use kclip_protocol::{
    DEFAULT_SLOT, DaemonStatus, ErrorCode, FrameError, MAX_FRAME_SIZE, Operation, PROTOCOL_VERSION,
    ProtocolError, Request, Response, ResponsePayload, ResponseResult, RevisionMetadata,
    read_frame, write_frame,
};
use kclip_sync::{
    DeviceSetupCodeV1, PairingCredential, SyncError, read_pairing, remove_pairing, write_pairing,
};
use std::{
    fs::{self, File, OpenOptions},
    future::Future,
    io::{self, IsTerminal, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    pin::Pin,
    process::Command as ProcessCommand,
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

    /// Configure and inspect encrypted PyPasteServer synchronization.
    Sync {
        #[command(subcommand)]
        command: SyncCommand,
    },
}

#[derive(Debug, Clone, Subcommand)]
pub enum SyncCommand {
    /// Configure this device from one hidden server-generated setup code.
    Setup,
    /// Show an actionable local and live synchronization checklist.
    Status,
    /// Print the account recovery words after an interactive warning.
    RecoveryCode,
    /// Disable synchronization and remove only this device's local credential.
    Disconnect,
}

pub trait SecretInput {
    fn is_interactive(&self) -> bool;
    fn read_hidden(&mut self, prompt: &str) -> io::Result<String>;
}

struct TerminalSecretInput;

impl SecretInput for TerminalSecretInput {
    fn is_interactive(&self) -> bool {
        io::stdin().is_terminal() && io::stdout().is_terminal()
    }

    fn read_hidden(&mut self, prompt: &str) -> io::Result<String> {
        rpassword::prompt_password(prompt)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartOutcome {
    Restarted,
    ManualRestartRequired,
}

pub trait SetupRuntime {
    fn restart_daemon(&mut self) -> Result<RestartOutcome, CliError>;

    fn daemon_status<'a>(
        &'a mut self,
        socket: &'a Path,
    ) -> Pin<Box<dyn Future<Output = Option<DaemonStatus>> + 'a>>;

    fn delay<'a>(
        &'a mut self,
        duration: std::time::Duration,
    ) -> Pin<Box<dyn Future<Output = ()> + 'a>>;

    fn verification_attempts(&self) -> usize {
        80
    }
}

struct SystemSetupRuntime;

impl SetupRuntime for SystemSetupRuntime {
    fn restart_daemon(&mut self) -> Result<RestartOutcome, CliError> {
        restart_installed_daemon()
    }

    fn daemon_status<'a>(
        &'a mut self,
        socket: &'a Path,
    ) -> Pin<Box<dyn Future<Output = Option<DaemonStatus>> + 'a>> {
        Box::pin(async move {
            match send_request(socket, Operation::Status).await {
                Ok(ResponsePayload::Status(status)) => Some(status),
                Ok(_) | Err(_) => None,
            }
        })
    }

    fn delay<'a>(
        &'a mut self,
        duration: std::time::Duration,
    ) -> Pin<Box<dyn Future<Output = ()> + 'a>> {
        Box::pin(tokio::time::sleep(duration))
    }
}

pub async fn execute(
    cli: &Cli,
    input: &mut dyn Read,
    output: &mut dyn Write,
) -> Result<(), CliError> {
    execute_with_runtime(
        cli,
        input,
        output,
        &mut TerminalSecretInput,
        &mut SystemSetupRuntime,
    )
    .await
}

pub async fn execute_with_secret_input(
    cli: &Cli,
    input: &mut dyn Read,
    output: &mut dyn Write,
    secrets: &mut dyn SecretInput,
) -> Result<(), CliError> {
    execute_with_runtime(cli, input, output, secrets, &mut SystemSetupRuntime).await
}

pub async fn execute_with_runtime(
    cli: &Cli,
    input: &mut dyn Read,
    output: &mut dyn Write,
    secrets: &mut dyn SecretInput,
    runtime: &mut dyn SetupRuntime,
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
                writeln!(output, "plasma: {}", status.plasma_state)?;
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
                if let Some(category) = status.last_plasma_error_category {
                    writeln!(output, "last plasma error: {category}")?;
                }
            }
        }
        Command::Sync { command } => match command {
            SyncCommand::Setup => execute_sync_setup(cli, input, output, secrets, runtime).await?,
            SyncCommand::Status => execute_sync_status(cli, output).await?,
            SyncCommand::RecoveryCode => execute_recovery_code(cli, input, output, secrets)?,
            SyncCommand::Disconnect => execute_sync_disconnect(cli, output, runtime).await?,
        },
    }
    Ok(())
}

fn local_socket(cli: &Cli) -> Result<PathBuf, CliError> {
    match &cli.socket {
        Some(path) => Ok(path.clone()),
        None => Ok(Config::load(None)?.resolve_socket(None)?),
    }
}

async fn execute_sync_setup(
    cli: &Cli,
    input: &mut dyn Read,
    output: &mut dyn Write,
    secrets: &mut dyn SecretInput,
    runtime: &mut dyn SetupRuntime,
) -> Result<(), CliError> {
    if cli.json {
        return Err(CliError::Usage(
            "sync setup does not support --json because it is interactive".into(),
        ));
    }
    if !secrets.is_interactive() {
        return Err(CliError::Usage(
            "sync setup requires an interactive terminal".into(),
        ));
    }

    let config_path = default_config_path()?;
    let config = load_optional_config(&config_path)?;
    let raw_code = secrets.read_hidden("Client setup code: ")?;
    let setup = DeviceSetupCodeV1::parse(&raw_code)?;
    drop(raw_code);

    let configured_account = config
        .sync
        .account_name
        .as_deref()
        .filter(|value| !value.is_empty());
    let configured_relay = config
        .sync
        .relay_url
        .as_deref()
        .filter(|value| !value.is_empty());

    let pairing_path = config
        .sync
        .pairing_path
        .clone()
        .map(Ok)
        .unwrap_or_else(default_pairing_path)?;
    let key_path = config
        .security
        .sync_key_path
        .clone()
        .map(Ok)
        .unwrap_or_else(default_sync_key_path)?;
    let existing_pairing = read_optional_pairing(&pairing_path)?;
    let existing_key = read_optional_sync_key(&key_path)?;
    let relay_conflict = configured_relay.is_some_and(|value| value != setup.relay_url)
        && (config.sync.enabled || configured_account.is_some() || existing_key.is_some());
    let account_conflict = configured_account.is_some_and(|value| value != setup.username);
    if relay_conflict || account_conflict {
        write_setup_conflict(
            output,
            configured_relay,
            configured_account,
            &setup.relay_url,
            &setup.username,
        )?;
        return Err(CliError::Reported(2));
    }

    let unlabeled_existing_key = existing_key.is_some()
        && configured_account.is_none()
        && (configured_relay.is_none() || configured_relay == Some(setup.relay_url.as_str()));
    if existing_key.is_some()
        && !unlabeled_existing_key
        && (configured_relay != Some(setup.relay_url.as_str())
            || configured_account != Some(setup.username.as_str()))
    {
        writeln!(
            output,
            "Setup cannot safely match the existing account encryption key to this account."
        )?;
        writeln!(
            output,
            "Next: run `kclip sync recovery-code` to preserve the existing key before changing accounts."
        )?;
        return Err(CliError::Reported(2));
    }

    let prepared_config = prepare_sync_setup(
        &config_path,
        &setup.relay_url,
        &setup.username,
        &setup.device_name,
    )?;

    writeln!(output)?;
    writeln!(output, "Server:  {}", setup.relay_url)?;
    writeln!(output, "Account: {}", setup.username)?;
    writeln!(output, "Device:  {}", setup.device_name)?;
    writeln!(output)?;

    if unlabeled_existing_key {
        writeln!(
            output,
            "An existing account encryption key was found, but it predates account labels."
        )?;
        writeln!(
            output,
            "Reusing it avoids changing access to existing synchronized history."
        )?;
        let confirmation = read_line_prompt(
            input,
            output,
            &format!(
                "Confirm this key belongs to account {}? [y/N] ",
                setup.username
            ),
            16,
        )?;
        if !matches!(confirmation.to_ascii_lowercase().as_str(), "y" | "yes") {
            writeln!(output, "Setup cancelled; no files were changed.")?;
            writeln!(
                output,
                "Next: run `kclip sync recovery-code` if you need to preserve this unlabelled key."
            )?;
            return Err(CliError::Reported(2));
        }
        writeln!(output)?;
    }

    let mut new_key = None;
    if existing_key.is_none() {
        writeln!(
            output,
            "The setup code authenticates this device. Recovery words provide the shared encryption key used by every device."
        )?;
        writeln!(output)?;
        writeln!(
            output,
            "How should this device get the shared encryption key?"
        )?;
        writeln!(output, "  1) This is the first device for this account")?;
        writeln!(output, "  2) Join devices that are already synchronized")?;
        let choice = read_line_prompt(input, output, "Choice [1-2]: ", 16)?;
        match choice.as_str() {
            "1" => {
                let mut key = [0_u8; 32];
                getrandom::fill(&mut key)
                    .map_err(|_| CliError::Usage("secure randomness is unavailable".into()))?;
                let mnemonic = mnemonic_for_key(&key).map_err(SyncError::from)?;
                writeln!(output)?;
                writeln!(
                    output,
                    "Recovery words protect access to synchronized clipboard history. Every additional device needs them, and losing every copy loses access to that history."
                )?;
                writeln!(
                    output,
                    "Store them somewhere private. They will be shown once during setup."
                )?;
                writeln!(output)?;
                writeln!(output, "{mnemonic}")?;
                writeln!(output)?;
                let saved = read_line_prompt(
                    input,
                    output,
                    "Have you saved the recovery words? [y/N] ",
                    16,
                )?;
                if !matches!(saved.to_ascii_lowercase().as_str(), "y" | "yes") {
                    return Err(CliError::Usage(
                        "setup cancelled before recovery words were confirmed; no files were changed"
                            .into(),
                    ));
                }
                new_key = Some(key);
            }
            "2" => loop {
                let words = secrets.read_hidden("Existing 24-word recovery mnemonic: ")?;
                if words.trim().is_empty() {
                    return Err(CliError::Usage(
                        "setup cancelled; no files were changed".into(),
                    ));
                }
                match key_from_mnemonic(words.trim()) {
                    Ok(key) => {
                        new_key = Some(key);
                        break;
                    }
                    Err(_) => {
                        writeln!(
                            output,
                            "The recovery words are invalid. Try again, or submit an empty value to cancel."
                        )?;
                    }
                }
            },
            _ => {
                return Err(CliError::Usage(
                    "setup cancelled: choose 1 or 2; no files were changed".into(),
                ));
            }
        }
    }

    let new_pairing = setup.pairing_credential();
    commit_setup_files(
        &key_path,
        new_key.as_ref(),
        &pairing_path,
        &new_pairing,
        existing_pairing.as_ref(),
        prepared_config,
    )?;

    writeln!(output)?;
    if unlabeled_existing_key {
        writeln!(
            output,
            "✓ Existing account encryption key associated with {}",
            setup.username
        )?;
    }
    writeln!(output, "✓ Device credential stored")?;
    writeln!(output, "✓ Synchronization configuration updated")?;

    if runtime.restart_daemon()? == RestartOutcome::ManualRestartRequired {
        writeln!(
            output,
            "✗ kclipd was not restarted because the user systemd service is unavailable"
        )?;
        writeln!(output, "Restart it manually with: kclipd")?;
        writeln!(
            output,
            "Setup is configured but not connected. Next: run `kclip sync status` after restarting kclipd."
        )?;
        show_replaced_pairing_notice(output, existing_pairing.as_ref(), &new_pairing)?;
        return Err(CliError::Reported(8));
    }
    writeln!(output, "✓ kclipd restarted")?;

    let socket = match &cli.socket {
        Some(path) => path.clone(),
        None => config.resolve_socket(None)?,
    };
    let mut last_status = None;
    for _ in 0..runtime.verification_attempts() {
        match runtime.daemon_status(&socket).await {
            Some(status) if daemon_sync_ready(&status) => {
                writeln!(output, "✓ Authenticated with PyPasteServer")?;
                writeln!(output)?;
                writeln!(output, "Synchronization is ready.")?;
                show_replaced_pairing_notice(output, existing_pairing.as_ref(), &new_pairing)?;
                return Ok(());
            }
            Some(status) => last_status = Some(status),
            None => {}
        }
        runtime.delay(std::time::Duration::from_millis(250)).await;
    }

    writeln!(
        output,
        "✗ PyPasteServer authentication was not verified within 20 seconds"
    )?;
    writeln!(
        output,
        "{}",
        setup_timeout_action(last_status.as_ref(), &setup.relay_url)
    )?;
    writeln!(
        output,
        "Setup is configured but not connected. Next: run `kclip sync status`."
    )?;
    show_replaced_pairing_notice(output, existing_pairing.as_ref(), &new_pairing)?;
    Err(CliError::Reported(8))
}

#[derive(serde::Serialize)]
struct SyncStatusReport {
    healthy: bool,
    state: String,
    configuration: String,
    enabled: bool,
    relay_url: Option<String>,
    account_name: Option<String>,
    device_name: Option<String>,
    device_credential: String,
    account_encryption_key: String,
    daemon: String,
    server_connection: String,
    authenticated: bool,
    last_successful_connection: Option<i64>,
    pending_outbox_count: u64,
    processed_server_cursor: u64,
    quarantined_event_count: u64,
    last_error_category: Option<String>,
    next_action: Option<String>,
}

async fn execute_sync_status(cli: &Cli, output: &mut dyn Write) -> Result<(), CliError> {
    let config_path = default_config_path()?;
    let config = match load_optional_config(&config_path) {
        Ok(config) => config,
        Err(error) => {
            write_invalid_sync_status(output, cli.json, &config_path, &error.to_string())?;
            return Err(CliError::Reported(2));
        }
    };
    let invalid_configuration = config
        .validate_phase_one()
        .err()
        .map(|error| error.to_string())
        .or_else(|| match config.sync_resolution() {
            SyncResolution::Invalid(message) => Some(message),
            SyncResolution::Disabled | SyncResolution::Ready(_) => None,
        });
    if let Some(message) = invalid_configuration {
        write_invalid_sync_status(output, cli.json, &config_path, &message)?;
        return Err(CliError::Reported(2));
    }
    let pairing_path = config
        .sync
        .pairing_path
        .clone()
        .map(Ok)
        .unwrap_or_else(default_pairing_path)?;
    let key_path = config
        .security
        .sync_key_path
        .clone()
        .map(Ok)
        .unwrap_or_else(default_sync_key_path)?;
    let credential_state = local_pairing_state(&pairing_path);
    let key_state = local_key_state(&key_path);

    let daemon_status = match &cli.socket {
        Some(socket) => send_request(socket, Operation::Status).await.ok(),
        None => match config.resolve_socket(None) {
            Ok(socket) => send_request(&socket, Operation::Status).await.ok(),
            Err(_) => None,
        },
    };
    let daemon = daemon_status.and_then(|payload| match payload {
        ResponsePayload::Status(status) => Some(status),
        _ => None,
    });
    let healthy = config.sync.enabled
        && credential_state == "present"
        && key_state == "present"
        && daemon.as_ref().is_some_and(daemon_sync_ready);
    let next_action = sync_next_action(&config, credential_state, key_state, daemon.as_ref());
    let report = SyncStatusReport {
        healthy,
        state: if healthy {
            "ready".into()
        } else if !config.sync.enabled || credential_state != "present" || key_state != "present" {
            "setup_incomplete".into()
        } else {
            "unhealthy".into()
        },
        configuration: if config.sync.enabled {
            "enabled".into()
        } else {
            "disabled".into()
        },
        enabled: config.sync.enabled,
        relay_url: config.sync.relay_url.clone(),
        account_name: config.sync.account_name.clone(),
        device_name: config.sync.device_name.clone(),
        device_credential: credential_state.into(),
        account_encryption_key: key_state.into(),
        daemon: if daemon.is_some() {
            "running".into()
        } else {
            "unavailable".into()
        },
        server_connection: daemon
            .as_ref()
            .map(|status| status.synchronization_state.clone())
            .unwrap_or_else(|| "not checked".into()),
        authenticated: daemon.as_ref().is_some_and(|status| status.authenticated),
        last_successful_connection: daemon
            .as_ref()
            .and_then(|status| status.last_successful_connection),
        pending_outbox_count: daemon
            .as_ref()
            .map_or(0, |status| status.pending_outbox_count),
        processed_server_cursor: daemon
            .as_ref()
            .map_or(0, |status| status.processed_server_cursor),
        quarantined_event_count: daemon
            .as_ref()
            .map_or(0, |status| status.quarantined_event_count),
        last_error_category: daemon
            .as_ref()
            .and_then(|status| status.last_sync_error_category.clone()),
        next_action,
    };
    write_sync_status(output, cli.json, &report)?;
    if healthy {
        Ok(())
    } else {
        Err(CliError::Reported(8))
    }
}

fn execute_recovery_code(
    cli: &Cli,
    input: &mut dyn Read,
    output: &mut dyn Write,
    secrets: &mut dyn SecretInput,
) -> Result<(), CliError> {
    if cli.json {
        return Err(CliError::Usage(
            "sync recovery-code never supports --json".into(),
        ));
    }
    if !secrets.is_interactive() {
        return Err(CliError::Usage(
            "sync recovery-code requires an interactive terminal".into(),
        ));
    }
    let config_path = default_config_path()?;
    let config = load_optional_config(&config_path)?;
    let key_path = config
        .security
        .sync_key_path
        .clone()
        .map(Ok)
        .unwrap_or_else(default_sync_key_path)?;
    let key = read_sync_key(&key_path).map_err(SyncError::from)?;
    writeln!(
        output,
        "WARNING: anyone with these recovery words can decrypt synchronized clipboard history."
    )?;
    let confirmed = read_line_prompt(input, output, "Show the recovery words? [y/N] ", 16)?;
    if !matches!(confirmed.to_ascii_lowercase().as_str(), "y" | "yes") {
        return Err(CliError::Usage("recovery-code cancelled".into()));
    }
    let mnemonic = mnemonic_for_key(&key).map_err(SyncError::from)?;
    writeln!(output, "{mnemonic}")?;
    Ok(())
}

async fn execute_sync_disconnect(
    cli: &Cli,
    output: &mut dyn Write,
    runtime: &mut dyn SetupRuntime,
) -> Result<(), CliError> {
    if cli.json {
        return Err(CliError::Usage(
            "sync disconnect does not support --json".into(),
        ));
    }
    let config_path = default_config_path()?;
    let config = load_optional_config(&config_path)?;
    let pairing_path = config
        .sync
        .pairing_path
        .clone()
        .map(Ok)
        .unwrap_or_else(default_pairing_path)?;
    let pairing = read_optional_pairing(&pairing_path)?;
    let prepared = prepare_sync_disconnect(&config_path)?;

    writeln!(
        output,
        "This disables synchronization locally; it does not revoke the server credential."
    )?;
    if let Some(pairing) = &pairing {
        writeln!(output, "Pairing ID: {}", pairing.pairing_id)?;
        writeln!(
            output,
            "On the PyPasteServer host, run: ./admin.sh device revoke {}",
            pairing.pairing_id
        )?;
    }
    prepared.commit()?;
    remove_pairing(&pairing_path)?;
    writeln!(output, "✓ Synchronization disabled")?;
    writeln!(output, "✓ Local device credential removed")?;
    writeln!(output, "✓ Account encryption key retained")?;
    if runtime.restart_daemon()? == RestartOutcome::Restarted {
        writeln!(output, "✓ kclipd restarted")?;
        Ok(())
    } else {
        writeln!(output, "Restart the manually managed daemon with: kclipd")?;
        Err(CliError::Reported(8))
    }
}

fn load_optional_config(path: &Path) -> Result<Config, CliError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            Ok(Config::load(Some(path))?)
        }
        Ok(_) => Err(ConfigError::UnsafeFile(path.to_path_buf()).into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Config::default()),
        Err(error) => Err(ConfigError::Read {
            path: path.to_path_buf(),
            source: error,
        }
        .into()),
    }
}

fn read_optional_pairing(path: &Path) -> Result<Option<PairingCredential>, CliError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(Some(read_pairing(path)?)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn read_optional_sync_key(path: &Path) -> Result<Option<[u8; 32]>, CliError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(Some(read_sync_key(path).map_err(SyncError::from)?)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn write_setup_conflict(
    output: &mut dyn Write,
    current_relay: Option<&str>,
    current_account: Option<&str>,
    requested_relay: &str,
    requested_account: &str,
) -> Result<(), CliError> {
    writeln!(
        output,
        "Setup cannot replace a different synchronization account in this local profile."
    )?;
    writeln!(output)?;
    writeln!(
        output,
        "Current relay:   {}",
        current_relay.unwrap_or("not recorded")
    )?;
    writeln!(
        output,
        "Current account: {}",
        current_account.unwrap_or("not recorded")
    )?;
    writeln!(output, "Requested relay:   {requested_relay}")?;
    writeln!(output, "Requested account: {requested_account}")?;
    writeln!(output)?;
    writeln!(
        output,
        "Next: use a setup code for the current relay/account. Replacing accounts requires a separate data-reconciliation workflow."
    )?;
    Ok(())
}

fn restore_pairing(path: &Path, previous: Option<&PairingCredential>) -> Result<(), CliError> {
    match previous {
        Some(credential) => write_pairing(path, credential)?,
        None => {
            remove_pairing(path)?;
        }
    }
    Ok(())
}

fn commit_setup_files(
    key_path: &Path,
    new_key: Option<&[u8; 32]>,
    pairing_path: &Path,
    new_pairing: &PairingCredential,
    previous_pairing: Option<&PairingCredential>,
    prepared_config: PreparedSyncConfig,
) -> Result<(), CliError> {
    if let Some(key) = new_key {
        write_sync_key(key_path, key).map_err(SyncError::from)?;
    }
    if let Err(error) = write_pairing(pairing_path, new_pairing) {
        if new_key.is_some() {
            fs::remove_file(key_path)?;
        }
        return Err(error.into());
    }
    if let Err(error) = prepared_config.commit() {
        let pairing_rollback = restore_pairing(pairing_path, previous_pairing);
        let key_rollback = if new_key.is_some() {
            fs::remove_file(key_path).map_err(CliError::from)
        } else {
            Ok(())
        };
        if pairing_rollback.is_err() || key_rollback.is_err() {
            return Err(CliError::Usage(
                "the configuration update failed and local credential rollback was incomplete; synchronization was not enabled"
                    .into(),
            ));
        }
        return Err(error.into());
    }
    Ok(())
}

fn read_line_prompt(
    input: &mut dyn Read,
    output: &mut dyn Write,
    prompt: &str,
    maximum: usize,
) -> Result<String, CliError> {
    write!(output, "{prompt}")?;
    output.flush()?;
    let mut bytes = Vec::new();
    let mut byte = [0_u8; 1];
    while input.read(&mut byte)? == 1 && byte[0] != b'\n' {
        if bytes.len() == maximum {
            return Err(CliError::Usage("interactive response is too long".into()));
        }
        if byte[0] != b'\r' {
            bytes.push(byte[0]);
        }
    }
    String::from_utf8(bytes)
        .map(|value| value.trim().to_owned())
        .map_err(|_| CliError::Usage("interactive response must be valid UTF-8".into()))
}

fn restart_installed_daemon() -> Result<RestartOutcome, CliError> {
    let show = match ProcessCommand::new("systemctl")
        .args([
            "--user",
            "show",
            "kclipd.service",
            "--property=LoadState",
            "--value",
        ])
        .output()
    {
        Ok(output) => output,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(RestartOutcome::ManualRestartRequired);
        }
        Err(error) => return Err(error.into()),
    };
    if !show.status.success() || String::from_utf8_lossy(&show.stdout).trim() != "loaded" {
        return Ok(RestartOutcome::ManualRestartRequired);
    }
    let restart = ProcessCommand::new("systemctl")
        .args(["--user", "restart", "kclipd.service"])
        .status()?;
    if !restart.success() {
        return Err(CliError::Usage(
            "local synchronization changes were saved, but `systemctl --user restart kclipd.service` failed; inspect `journalctl --user -u kclipd.service`"
                .into(),
        ));
    }
    Ok(RestartOutcome::Restarted)
}

fn daemon_sync_ready(status: &DaemonStatus) -> bool {
    status.synchronization_enabled
        && status.synchronization_configured
        && status.synchronization_state == "connected"
        && status.authenticated
        && !status.credential_error
}

fn setup_timeout_action(status: Option<&DaemonStatus>, relay_url: &str) -> String {
    match status {
        None => "The daemon socket is unavailable. Inspect `systemctl --user status kclipd.service`.".into(),
        Some(status) if status.credential_error || status.last_sync_error_category.as_deref() == Some("authentication") => {
            "The device credential was rejected. Ask the server operator to add this device again.".into()
        }
        Some(status) if status.last_sync_error_category.as_deref() == Some("cryptography") => {
            "The account key cannot decrypt synchronized data. Run setup with the correct existing recovery words; do not generate a new key.".into()
        }
        Some(status) if status.last_sync_error_category.as_deref() == Some("connectivity") => {
            format!("The relay could not be reached at {relay_url}. Check reachability and TLS configuration.")
        }
        Some(_) => "The daemon is still connecting. Inspect `kclip sync status` for the latest cause.".into(),
    }
}

fn local_pairing_state(path: &Path) -> &'static str {
    match fs::symlink_metadata(path) {
        Ok(_) if read_pairing(path).is_ok() => "present",
        Ok(_) => "invalid_or_unsafe",
        Err(error) if error.kind() == io::ErrorKind::NotFound => "missing",
        Err(_) => "invalid_or_unsafe",
    }
}

fn local_key_state(path: &Path) -> &'static str {
    match fs::symlink_metadata(path) {
        Ok(_) if read_sync_key(path).is_ok() => "present",
        Ok(_) => "invalid_or_unsafe",
        Err(error) if error.kind() == io::ErrorKind::NotFound => "missing",
        Err(_) => "invalid_or_unsafe",
    }
}

fn sync_next_action(
    config: &Config,
    credential_state: &str,
    key_state: &str,
    daemon: Option<&DaemonStatus>,
) -> Option<String> {
    if !config.sync.enabled {
        return Some("Run `kclip sync setup`.".into());
    }
    if credential_state != "present" {
        return Some("Run `kclip sync setup` again; bearer authentication is not used.".into());
    }
    if key_state != "present" {
        return Some(
            "Run `kclip sync setup` and choose the correct first/additional-device option.".into(),
        );
    }
    let Some(status) = daemon else {
        return Some("Start or inspect `kclipd.service`.".into());
    };
    if status.quarantined_event_count > 0
        || status.last_sync_error_category.as_deref() == Some("cryptography")
    {
        return Some(
            "Import the correct account recovery words; do not generate a new key.".into(),
        );
    }
    if status.credential_error
        || status.last_sync_error_category.as_deref() == Some("authentication")
    {
        return Some("Ask the server operator to add this device again, then rerun setup.".into());
    }
    if status.last_sync_error_category.as_deref() == Some("connectivity") {
        return Some("Check relay reachability and TLS configuration.".into());
    }
    if !daemon_sync_ready(status) {
        return Some(
            "Inspect `systemctl --user status kclipd.service` and retry `kclip sync status`."
                .into(),
        );
    }
    None
}

fn write_sync_status(
    output: &mut dyn Write,
    json: bool,
    report: &SyncStatusReport,
) -> Result<(), CliError> {
    if json {
        return write_json(output, report);
    }
    writeln!(
        output,
        "Synchronization: {}",
        report.state.replace('_', " ")
    )?;
    writeln!(output)?;
    checklist(
        output,
        report.enabled,
        "configuration",
        &report.configuration,
    )?;
    checklist(
        output,
        report.relay_url.is_some(),
        "relay",
        report.relay_url.as_deref().unwrap_or("missing"),
    )?;
    checklist(
        output,
        report.account_name.is_some(),
        "account",
        report.account_name.as_deref().unwrap_or("missing"),
    )?;
    checklist(
        output,
        report.device_credential == "present",
        "device credential",
        &report.device_credential,
    )?;
    checklist(
        output,
        report.account_encryption_key == "present",
        "account encryption key",
        &report.account_encryption_key,
    )?;
    checklist(output, report.daemon == "running", "daemon", &report.daemon)?;
    checklist(
        output,
        report.healthy,
        "server connection",
        &report.server_connection,
    )?;
    if let Some(device) = &report.device_name {
        writeln!(output, "  device: {device}")?;
    }
    if report.daemon == "running" {
        writeln!(
            output,
            "  last successful connection: {}",
            report
                .last_successful_connection
                .map_or_else(|| "never".into(), |value| value.to_string())
        )?;
        writeln!(output, "  pending outbox: {}", report.pending_outbox_count)?;
        writeln!(
            output,
            "  server cursor: {}",
            report.processed_server_cursor
        )?;
        writeln!(
            output,
            "  quarantined events: {}",
            report.quarantined_event_count
        )?;
    }
    if let Some(action) = &report.next_action {
        writeln!(output)?;
        writeln!(output, "Next: {action}")?;
    }
    Ok(())
}

fn write_invalid_sync_status(
    output: &mut dyn Write,
    json: bool,
    config_path: &Path,
    message: &str,
) -> Result<(), CliError> {
    let report = SyncStatusReport {
        healthy: false,
        state: "setup_incomplete".into(),
        configuration: format!("invalid: {message}"),
        enabled: false,
        relay_url: None,
        account_name: None,
        device_name: None,
        device_credential: "unknown".into(),
        account_encryption_key: "unknown".into(),
        daemon: "unknown".into(),
        server_connection: "not checked".into(),
        authenticated: false,
        last_successful_connection: None,
        pending_outbox_count: 0,
        processed_server_cursor: 0,
        quarantined_event_count: 0,
        last_error_category: Some("invalid_configuration".into()),
        next_action: Some(format!(
            "Fix the invalid configuration at {} and run `kclip sync setup`.",
            config_path.display()
        )),
    };
    write_sync_status(output, json, &report)
}

fn checklist(
    output: &mut dyn Write,
    success: bool,
    label: &str,
    value: &str,
) -> Result<(), CliError> {
    writeln!(
        output,
        "{} {label}: {value}",
        if success { "✓" } else { "✗" }
    )?;
    Ok(())
}

fn show_replaced_pairing_notice(
    output: &mut dyn Write,
    previous: Option<&PairingCredential>,
    current: &PairingCredential,
) -> Result<(), CliError> {
    if let Some(previous) = previous.filter(|value| value.pairing_id != current.pairing_id) {
        writeln!(output)?;
        writeln!(
            output,
            "Previous pairing ID: {}. Revoke that old device entry on the PyPasteServer host.",
            previous.pairing_id
        )?;
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
    #[error("command completed with an unhealthy result")]
    Reported(u8),
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
            Self::Reported(code) => *code,
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

    pub fn already_reported(&self) -> bool {
        matches!(self, Self::Reported(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io::Cursor;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;
    use tokio::sync::Mutex;

    static ENVIRONMENT: Mutex<()> = Mutex::const_new(());

    struct MockSecrets {
        values: VecDeque<String>,
    }

    struct MockRuntime {
        restart: RestartOutcome,
        statuses: VecDeque<Option<DaemonStatus>>,
        delays: usize,
    }

    impl SecretInput for MockSecrets {
        fn is_interactive(&self) -> bool {
            true
        }

        fn read_hidden(&mut self, _prompt: &str) -> io::Result<String> {
            self.values
                .pop_front()
                .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))
        }
    }

    impl SetupRuntime for MockRuntime {
        fn restart_daemon(&mut self) -> Result<RestartOutcome, CliError> {
            Ok(self.restart)
        }

        fn daemon_status<'a>(
            &'a mut self,
            _socket: &'a Path,
        ) -> Pin<Box<dyn Future<Output = Option<DaemonStatus>> + 'a>> {
            let status = self.statuses.pop_front().flatten();
            Box::pin(async move { status })
        }

        fn delay<'a>(
            &'a mut self,
            _duration: std::time::Duration,
        ) -> Pin<Box<dyn Future<Output = ()> + 'a>> {
            self.delays += 1;
            Box::pin(async {})
        }

        fn verification_attempts(&self) -> usize {
            self.statuses.len().max(1)
        }
    }

    fn daemon_status(category: Option<&str>) -> DaemonStatus {
        DaemonStatus {
            daemon_available: true,
            daemon_version: "test".into(),
            schema_version: 1,
            device_id: "device".into(),
            synchronization_enabled: true,
            synchronization_configured: true,
            synchronization_state: "disconnected".into(),
            authenticated: false,
            credential_error: false,
            pending_outbox_count: 0,
            oldest_pending_age_millis: None,
            last_successful_connection: None,
            last_acknowledgement: None,
            processed_server_cursor: 0,
            last_sync_error_category: category.map(str::to_owned),
            quarantined_event_count: 0,
            plasma_enabled: false,
            plasma_state: "disabled".into(),
            last_plasma_error_category: None,
        }
    }

    fn credential(id: &str, byte: u8) -> PairingCredential {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        PairingCredential {
            version: 1,
            pairing_id: id.into(),
            pairing_secret: URL_SAFE_NO_PAD.encode([byte; 32]),
        }
    }

    #[test]
    fn guided_commit_writes_all_prerequisites_before_enabling_sync() {
        let temp = TempDir::new().unwrap();
        let config_path = temp.path().join("config/kclip/config.toml");
        let key_path = temp.path().join("data/kclip/sync.key");
        let pairing_path = temp.path().join("config/kclip/pairing.json");
        let pairing = credential("eb6b89c3-6a6f-45fa-8da7-b74ea00bbfd5", 7);
        let prepared = prepare_sync_setup(
            &config_path,
            "wss://clipboard.example.test/sync/v1",
            "alice",
            "office-laptop",
        )
        .unwrap();

        commit_setup_files(
            &key_path,
            Some(&[11_u8; 32]),
            &pairing_path,
            &pairing,
            None,
            prepared,
        )
        .unwrap();

        assert_eq!(read_sync_key(&key_path).unwrap(), [11_u8; 32]);
        assert_eq!(
            read_pairing(&pairing_path).unwrap().pairing_id,
            pairing.pairing_id
        );
        let config = Config::load(Some(&config_path)).unwrap();
        assert!(config.sync.enabled);
        assert_eq!(config.sync.account_name.as_deref(), Some("alice"));
        assert_eq!(
            fs::metadata(&key_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&pairing_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn failed_config_commit_rolls_back_new_secrets_and_previous_pairing() {
        let temp = TempDir::new().unwrap();
        let blocked_parent = temp.path().join("blocked");
        let config_path = blocked_parent.join("config.toml");
        let key_path = temp.path().join("secrets/sync.key");
        let pairing_path = temp.path().join("secrets/pairing.json");
        let old = credential("eb6b89c3-6a6f-45fa-8da7-b74ea00bbfd5", 1);
        let new = credential("8d5f7f7c-cbc5-4e05-ab9f-ecf002cbd42c", 2);
        write_pairing(&pairing_path, &old).unwrap();
        let prepared = prepare_sync_setup(
            &config_path,
            "wss://clipboard.example.test/sync/v1",
            "alice",
            "office-laptop",
        )
        .unwrap();
        fs::write(&blocked_parent, b"not a directory").unwrap();

        assert!(
            commit_setup_files(
                &key_path,
                Some(&[9_u8; 32]),
                &pairing_path,
                &new,
                Some(&old),
                prepared,
            )
            .is_err()
        );
        assert!(!key_path.exists());
        assert_eq!(
            read_pairing(&pairing_path).unwrap().pairing_id,
            old.pairing_id
        );
        assert!(!config_path.exists());
    }

    #[test]
    fn obsolete_auth_key_and_migration_commands_are_absent() {
        for command in ["auth", "key", "migrate-legacy"] {
            assert!(Cli::try_parse_from(["kclip", command]).is_err());
        }
        assert!(Cli::try_parse_from(["kclip", "sync", "setup"]).is_ok());
        assert!(Cli::try_parse_from(["kclip", "sync", "status"]).is_ok());
    }

    #[tokio::test]
    async fn declining_recovery_confirmation_changes_no_files() {
        let _environment = ENVIRONMENT.lock().await;
        let temp = TempDir::new().unwrap();
        let config_home = temp.path().join("config-home");
        let data_home = temp.path().join("data-home");
        let old_config = std::env::var_os("XDG_CONFIG_HOME");
        let old_data = std::env::var_os("XDG_DATA_HOME");
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &config_home);
            std::env::set_var("XDG_DATA_HOME", &data_home);
        }
        let cli = Cli {
            socket: Some(temp.path().join("unused.sock")),
            json: false,
            command: Command::Sync {
                command: SyncCommand::Setup,
            },
        };
        let fixture = include_str!("../../../fixtures/kclip-setup-v1.txt")
            .trim()
            .to_owned();
        let mut secrets = MockSecrets {
            values: VecDeque::from([fixture.clone()]),
        };
        let mut input = Cursor::new(b"1\nn\n".to_vec());
        let mut output = Vec::new();
        let error = execute_with_secret_input(&cli, &mut input, &mut output, &mut secrets)
            .await
            .unwrap_err();

        assert!(matches!(error, CliError::Usage(_)));
        assert!(!config_home.exists());
        assert!(!data_home.exists());
        let rendered = String::from_utf8(output).unwrap();
        assert!(!rendered.contains(&fixture));
        assert!(!rendered.contains("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"));

        unsafe {
            match old_config {
                Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
            match old_data {
                Some(value) => std::env::set_var("XDG_DATA_HOME", value),
                None => std::env::remove_var("XDG_DATA_HOME"),
            }
        }
    }

    #[tokio::test]
    async fn unlabeled_existing_key_can_be_explicitly_confirmed_without_migration_steps() {
        let _environment = ENVIRONMENT.lock().await;
        let temp = TempDir::new().unwrap();
        let config_home = temp.path().join("config-home");
        let data_home = temp.path().join("data-home");
        let old_config = std::env::var_os("XDG_CONFIG_HOME");
        let old_data = std::env::var_os("XDG_DATA_HOME");
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &config_home);
            std::env::set_var("XDG_DATA_HOME", &data_home);
        }
        let config_path = config_home.join("kclip/config.toml");
        let pairing_path = config_home.join("kclip/pairing.json");
        let key_path = data_home.join("kclip/sync.key");
        fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        fs::write(
            &config_path,
            "[sync]\nenabled = true\nrelay_url = \"wss://clipboard.example.test/sync/v1\"\ndevice_name = \"legacy-device\"\n",
        )
        .unwrap();
        let old_pairing = credential("8d5f7f7c-cbc5-4e05-ab9f-ecf002cbd42c", 9);
        write_pairing(&pairing_path, &old_pairing).unwrap();
        write_sync_key(&key_path, &[6_u8; 32]).unwrap();
        let original_config = fs::read(&config_path).unwrap();
        let original_pairing = fs::read(&pairing_path).unwrap();
        let cli = Cli {
            socket: Some(temp.path().join("mock.sock")),
            json: false,
            command: Command::Sync {
                command: SyncCommand::Setup,
            },
        };
        let fixture = include_str!("../../../fixtures/kclip-setup-v1.txt")
            .trim()
            .to_owned();

        let mut decline_secrets = MockSecrets {
            values: VecDeque::from([fixture.clone()]),
        };
        let mut decline_runtime = MockRuntime {
            restart: RestartOutcome::Restarted,
            statuses: VecDeque::new(),
            delays: 0,
        };
        let mut decline_input = Cursor::new(b"n\n".to_vec());
        let mut decline_output = Vec::new();
        let declined = execute_with_runtime(
            &cli,
            &mut decline_input,
            &mut decline_output,
            &mut decline_secrets,
            &mut decline_runtime,
        )
        .await;
        assert!(matches!(declined, Err(CliError::Reported(2))));
        assert_eq!(fs::read(&config_path).unwrap(), original_config);
        assert_eq!(fs::read(&pairing_path).unwrap(), original_pairing);
        assert_eq!(read_sync_key(&key_path).unwrap(), [6_u8; 32]);

        fs::write(
            &config_path,
            "[sync]\nenabled = true\nrelay_url = \"wss://clipboard.example.test/sync/v1\"\naccount_name = \"bob\"\ndevice_name = \"other-account\"\n",
        )
        .unwrap();
        let conflicting_config = fs::read(&config_path).unwrap();
        let mut conflict_secrets = MockSecrets {
            values: VecDeque::from([fixture.clone()]),
        };
        let mut conflict_runtime = MockRuntime {
            restart: RestartOutcome::Restarted,
            statuses: VecDeque::new(),
            delays: 0,
        };
        let mut conflict_input = Cursor::new(Vec::new());
        let mut conflict_output = Vec::new();
        let conflict = execute_with_runtime(
            &cli,
            &mut conflict_input,
            &mut conflict_output,
            &mut conflict_secrets,
            &mut conflict_runtime,
        )
        .await;
        assert!(matches!(conflict, Err(CliError::Reported(2))));
        assert_eq!(fs::read(&config_path).unwrap(), conflicting_config);
        let conflict_output = String::from_utf8(conflict_output).unwrap();
        assert!(conflict_output.contains("Current account: bob"));
        assert!(conflict_output.contains("Requested account: alice"));
        fs::write(&config_path, &original_config).unwrap();

        let mut ready = daemon_status(None);
        ready.synchronization_state = "connected".into();
        ready.authenticated = true;
        let mut confirm_secrets = MockSecrets {
            values: VecDeque::from([fixture]),
        };
        let mut confirm_runtime = MockRuntime {
            restart: RestartOutcome::Restarted,
            statuses: VecDeque::from([Some(ready)]),
            delays: 0,
        };
        let mut confirm_input = Cursor::new(b"y\n".to_vec());
        let mut confirm_output = Vec::new();
        execute_with_runtime(
            &cli,
            &mut confirm_input,
            &mut confirm_output,
            &mut confirm_secrets,
            &mut confirm_runtime,
        )
        .await
        .unwrap();
        let configured = Config::load(Some(&config_path)).unwrap();
        assert_eq!(configured.sync.account_name.as_deref(), Some("alice"));
        assert_eq!(read_sync_key(&key_path).unwrap(), [6_u8; 32]);
        let output = String::from_utf8(confirm_output).unwrap();
        assert!(output.contains("predates account labels"));
        assert!(output.contains("Existing account encryption key associated with alice"));
        assert!(output.contains("Synchronization is ready."));

        unsafe {
            match old_config {
                Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
            match old_data {
                Some(value) => std::env::set_var("XDG_DATA_HOME", value),
                None => std::env::remove_var("XDG_DATA_HOME"),
            }
        }
    }

    #[tokio::test]
    async fn additional_device_setup_uses_hidden_mnemonic_and_live_ready_status() {
        let _environment = ENVIRONMENT.lock().await;
        let temp = TempDir::new().unwrap();
        let config_home = temp.path().join("config-home");
        let data_home = temp.path().join("data-home");
        let old_config = std::env::var_os("XDG_CONFIG_HOME");
        let old_data = std::env::var_os("XDG_DATA_HOME");
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &config_home);
            std::env::set_var("XDG_DATA_HOME", &data_home);
        }
        let config_path = config_home.join("kclip/config.toml");
        fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        fs::write(&config_path, "[slots.private]\nsync = false\n").unwrap();
        let cli = Cli {
            socket: Some(temp.path().join("mock.sock")),
            json: false,
            command: Command::Sync {
                command: SyncCommand::Setup,
            },
        };
        let fixture = include_str!("../../../fixtures/kclip-setup-v1.txt")
            .trim()
            .to_owned();
        let mnemonic = mnemonic_for_key(&[5_u8; 32]).unwrap();
        let mut secrets = MockSecrets {
            values: VecDeque::from([fixture.clone(), mnemonic.clone()]),
        };
        let mut ready = daemon_status(None);
        ready.synchronization_state = "connected".into();
        ready.authenticated = true;
        let mut runtime = MockRuntime {
            restart: RestartOutcome::Restarted,
            statuses: VecDeque::from([Some(ready)]),
            delays: 0,
        };
        let mut input = Cursor::new(b"2\n".to_vec());
        let mut output = Vec::new();
        execute_with_runtime(&cli, &mut input, &mut output, &mut secrets, &mut runtime)
            .await
            .unwrap();

        let config = Config::load(Some(&config_path)).unwrap();
        assert!(config.sync.enabled);
        assert_eq!(config.sync.account_name.as_deref(), Some("alice"));
        assert_eq!(config.slots["private"].sync, Some(false));
        assert_eq!(
            read_sync_key(&data_home.join("kclip/sync.key")).unwrap(),
            [5_u8; 32]
        );
        assert_eq!(
            read_pairing(&config_home.join("kclip/pairing.json"))
                .unwrap()
                .pairing_id,
            "eb6b89c3-6a6f-45fa-8da7-b74ea00bbfd5"
        );
        let rendered = String::from_utf8(output).unwrap();
        assert!(rendered.contains("Synchronization is ready."));
        assert!(!rendered.contains(&fixture));
        assert!(!rendered.contains(&mnemonic));
        assert_eq!(runtime.delays, 0);

        let mut retry_secrets = MockSecrets {
            values: VecDeque::from([fixture]),
        };
        let mut retry_runtime = MockRuntime {
            restart: RestartOutcome::Restarted,
            statuses: VecDeque::from([Some(daemon_status(Some("connectivity")))]),
            delays: 0,
        };
        let mut retry_input = Cursor::new(Vec::new());
        let mut retry_output = Vec::new();
        let retry = execute_with_runtime(
            &cli,
            &mut retry_input,
            &mut retry_output,
            &mut retry_secrets,
            &mut retry_runtime,
        )
        .await;
        assert!(matches!(retry, Err(CliError::Reported(8))));
        assert!(Config::load(Some(&config_path)).unwrap().sync.enabled);
        assert_eq!(
            read_sync_key(&data_home.join("kclip/sync.key")).unwrap(),
            [5_u8; 32]
        );
        assert!(
            String::from_utf8(retry_output)
                .unwrap()
                .contains("configured but not connected")
        );

        unsafe {
            match old_config {
                Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
            match old_data {
                Some(value) => std::env::set_var("XDG_DATA_HOME", value),
                None => std::env::remove_var("XDG_DATA_HOME"),
            }
        }
    }

    #[tokio::test]
    async fn sync_status_reports_invalid_enabled_configuration_with_an_action() {
        let _environment = ENVIRONMENT.lock().await;
        let temp = TempDir::new().unwrap();
        let config_home = temp.path().join("config-home");
        let old_config = std::env::var_os("XDG_CONFIG_HOME");
        fs::create_dir_all(config_home.join("kclip")).unwrap();
        fs::write(
            config_home.join("kclip/config.toml"),
            "[sync]\nenabled = true\nrelay_url = \"wss://example.test/sync/v1\"\n",
        )
        .unwrap();
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &config_home);
        }
        let cli = Cli {
            socket: Some(temp.path().join("unused.sock")),
            json: true,
            command: Command::Sync {
                command: SyncCommand::Status,
            },
        };
        let mut secrets = MockSecrets {
            values: VecDeque::new(),
        };
        let mut runtime = MockRuntime {
            restart: RestartOutcome::Restarted,
            statuses: VecDeque::new(),
            delays: 0,
        };
        let mut input = Cursor::new(Vec::new());
        let mut output = Vec::new();
        let result =
            execute_with_runtime(&cli, &mut input, &mut output, &mut secrets, &mut runtime).await;
        assert!(matches!(result, Err(CliError::Reported(2))));
        let report: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(report["last_error_category"], "invalid_configuration");
        assert!(
            report["configuration"]
                .as_str()
                .unwrap()
                .contains("sync.account_name is required")
        );
        assert!(report["next_action"].as_str().unwrap().contains("Fix"));

        unsafe {
            match old_config {
                Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
        }
    }

    #[test]
    fn unhealthy_runtime_categories_always_produce_specific_actions() {
        let mut config = Config::default();
        config.sync.enabled = true;
        let mut status = daemon_status(Some("connectivity"));
        assert!(
            sync_next_action(&config, "present", "present", Some(&status))
                .unwrap()
                .contains("reachability")
        );
        status.credential_error = true;
        status.last_sync_error_category = Some("authentication".into());
        assert!(
            sync_next_action(&config, "present", "present", Some(&status))
                .unwrap()
                .contains("server operator")
        );
        status.credential_error = false;
        status.quarantined_event_count = 1;
        status.last_sync_error_category = Some("cryptography".into());
        assert!(
            sync_next_action(&config, "present", "present", Some(&status))
                .unwrap()
                .contains("correct account recovery words")
        );
        assert!(
            sync_next_action(&config, "present", "present", None)
                .unwrap()
                .contains("kclipd.service")
        );
    }
}
