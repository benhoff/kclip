use clap::Parser;
use kclip_config::{Config, ConfigUpdate, default_config_path, update_config_file};
use kclip_daemon::{ServerConfig, run_until};
use kclip_storage::{
    SCHEMA_VERSION, SchemaCompatibility, inspect_schema_version, migrate_database_schema,
    schema_compatibility,
};
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

    /// Print machine-readable storage compatibility details for install.sh.
    #[arg(
        long,
        hide = true,
        conflicts_with_all = ["socket", "data_dir", "max_content_size", "update_config"]
    )]
    installer_storage_info: bool,

    /// Migrate storage for install.sh without starting the daemon.
    #[arg(
        long,
        hide = true,
        conflicts_with_all = [
            "socket",
            "data_dir",
            "max_content_size",
            "update_config",
            "installer_storage_info"
        ]
    )]
    installer_migrate_storage: bool,
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
        if arguments.installer_storage_info {
            let config = Config::load(arguments.config.as_deref())?;
            let resolved =
                config.resolve(Some(PathBuf::from("/run/kclip-installer.sock")), None, None)?;
            let existing = inspect_schema_version(&resolved.database_path)?;
            match existing {
                None => println!("absent - {SCHEMA_VERSION}"),
                Some(version) => {
                    let state = match schema_compatibility(version) {
                        SchemaCompatibility::Current => "current",
                        SchemaCompatibility::Migratable => "migratable",
                        SchemaCompatibility::Unsupported => "unsupported",
                    };
                    println!("{state} {version} {SCHEMA_VERSION}");
                }
            }
            println!("{}", resolved.database_path.display());
            return Ok::<(), Box<dyn std::error::Error>>(());
        }

        if arguments.installer_migrate_storage {
            let config = Config::load(arguments.config.as_deref())?;
            let resolved =
                config.resolve(Some(PathBuf::from("/run/kclip-installer.sock")), None, None)?;
            let version = migrate_database_schema(&resolved.database_path)?;
            println!(
                "Migrated database to schema {version}: {}",
                resolved.database_path.display()
            );
            return Ok::<(), Box<dyn std::error::Error>>(());
        }

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
