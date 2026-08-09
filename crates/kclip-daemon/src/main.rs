use clap::Parser;
use kclip_config::{Config, ConfigUpdate, default_config_path, update_config_file};
use kclip_daemon::{ServerConfig, run_until};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "kclipd", version, about = "Local kclip clipboard daemon")]
struct Arguments {
    /// Override the Unix socket path.
    #[arg(long)]
    socket: Option<PathBuf>,

    /// Override the root data directory (primarily useful for testing).
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Read configuration from this path.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Override the maximum content size in bytes.
    #[arg(long)]
    max_content_size: Option<u64>,

    /// Create or merge the configuration, then exit without starting the daemon.
    #[arg(
        long,
        conflicts_with_all = ["socket", "data_dir", "max_content_size"]
    )]
    update_config: bool,
}

#[tokio::main]
async fn main() {
    unsafe {
        libc::umask(0o077);
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let arguments = Arguments::parse();
    let result = async {
        if arguments.update_config {
            let path = match arguments.config.clone() {
                Some(path) => path,
                None => default_config_path()?,
            };
            match update_config_file(&path, include_str!("../../../config/kclip.toml.example"))? {
                ConfigUpdate::Created => {
                    println!("Created configuration: {}", path.display());
                }
                ConfigUpdate::Updated { backup_path } => {
                    println!("Updated configuration: {}", path.display());
                    println!("Previous configuration: {}", backup_path.display());
                }
                ConfigUpdate::Unchanged => {
                    println!("Configuration is current: {}", path.display());
                }
            }
            return Ok::<(), Box<dyn std::error::Error>>(());
        }

        let config = Config::load(arguments.config.as_deref())?;
        let resolved = config.resolve(
            arguments.socket,
            arguments.data_dir,
            arguments.max_content_size,
        )?;
        let server = ServerConfig {
            socket_path: resolved.socket_path,
            database_path: resolved.database_path,
            blob_directory: resolved.blob_directory,
            max_content_size: resolved.max_content_size,
            plasma: resolved.plasma,
            sync: resolved.sync,
            slots: resolved.slots,
        };
        run_until(server, async {
            if let Err(error) = tokio::signal::ctrl_c().await {
                tracing::error!(error = %error, "could not install shutdown handler");
            }
        })
        .await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    }
    .await;

    if let Err(error) = result {
        tracing::error!(error = %error, "kclipd failed");
        std::process::exit(1);
    }
}
