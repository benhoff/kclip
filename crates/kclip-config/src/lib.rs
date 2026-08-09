use kclip_protocol::{DEFAULT_MAX_CONTENT_SIZE, MAX_FRAME_SIZE, validate_slot_name};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    env, fs,
    fs::{File, OpenOptions},
    io,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub daemon: DaemonConfig,
    pub storage: StorageConfig,
    pub plasma: PlasmaConfig,
    pub sync: SyncConfig,
    pub security: SecurityConfig,
    pub slots: BTreeMap<String, SlotConfig>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DaemonConfig {
    pub socket_path: Option<PathBuf>,
    pub max_content_size: Option<u64>,
    pub history_limit: Option<u32>,
    pub history_max_age: Option<String>,
    pub tombstone_retention: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    pub database_path: Option<PathBuf>,
    pub blob_directory: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PlasmaConfig {
    pub enabled: bool,
    pub mirror_slot: Option<String>,
    pub desktop_to_slot: bool,
    pub slot_to_desktop: bool,
    pub text_only: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SyncConfig {
    pub enabled: bool,
    pub relay_url: Option<String>,
    pub account_name: Option<String>,
    pub reconnect_min_delay: Option<String>,
    pub reconnect_max_delay: Option<String>,
    pub device_name: Option<String>,
    pub pairing_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecurityConfig {
    pub identity_path: Option<PathBuf>,
    pub require_encrypted_sync: Option<bool>,
    pub sync_key_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SlotConfig {
    pub sync: Option<bool>,
    pub history_limit: Option<u32>,
    pub history_max_age: Option<String>,
    pub plasma_mirror: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub socket_path: PathBuf,
    pub database_path: PathBuf,
    pub blob_directory: PathBuf,
    pub max_content_size: u64,
    pub plasma: Option<ResolvedPlasmaConfig>,
    pub sync: SyncResolution,
    pub slots: BTreeMap<String, SlotConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPlasmaConfig {
    pub mirror_slot: String,
    pub desktop_to_slot: bool,
    pub slot_to_desktop: bool,
}

#[derive(Debug, Clone)]
pub enum SyncResolution {
    Disabled,
    Ready(ResolvedSyncConfig),
    Invalid(String),
}

#[derive(Debug, Clone)]
pub struct ResolvedSyncConfig {
    pub relay_url: String,
    pub account_name: String,
    pub reconnect_min_delay: Duration,
    pub reconnect_max_delay: Duration,
    pub device_name: String,
    pub pairing_path: PathBuf,
    pub sync_key_path: PathBuf,
}

impl Config {
    pub fn load(path_override: Option<&Path>) -> Result<Self, ConfigError> {
        let path = match path_override {
            Some(path) => path.to_path_buf(),
            None => default_config_path()?,
        };

        match fs::read_to_string(&path) {
            Ok(contents) => {
                toml::from_str(&contents).map_err(|source| ConfigError::Parse { path, source })
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound && path_override.is_none() => {
                Ok(Self::default())
            }
            Err(source) => Err(ConfigError::Read { path, source }),
        }
    }

    pub fn resolve(
        &self,
        socket_override: Option<PathBuf>,
        data_override: Option<PathBuf>,
        max_size_override: Option<u64>,
    ) -> Result<ResolvedConfig, ConfigError> {
        self.validate_phase_one()?;
        let data_root = match data_override {
            Some(path) => path,
            None => default_data_dir()?,
        };

        let socket_path = match socket_override.or_else(|| self.daemon.socket_path.clone()) {
            Some(path) => path,
            None => default_socket_path()?,
        };
        let database_path = self
            .storage
            .database_path
            .clone()
            .unwrap_or_else(|| data_root.join("kclip.db"));
        let blob_directory = self
            .storage
            .blob_directory
            .clone()
            .unwrap_or_else(|| data_root.join("blobs"));
        let max_content_size = max_size_override
            .or(self.daemon.max_content_size)
            .unwrap_or(DEFAULT_MAX_CONTENT_SIZE);

        if max_content_size == 0 {
            return Err(ConfigError::Invalid(
                "daemon.max_content_size must be greater than zero".into(),
            ));
        }
        if max_content_size as usize > MAX_FRAME_SIZE.saturating_sub(1024 * 1024) {
            return Err(ConfigError::Invalid(format!(
                "daemon.max_content_size must be at most {} bytes",
                MAX_FRAME_SIZE - 1024 * 1024
            )));
        }

        Ok(ResolvedConfig {
            socket_path,
            database_path,
            blob_directory,
            max_content_size,
            plasma: self.resolve_plasma()?,
            sync: self.resolve_sync(),
            slots: self.slots.clone(),
        })
    }

    pub fn resolve_socket(&self, socket_override: Option<PathBuf>) -> Result<PathBuf, ConfigError> {
        match socket_override.or_else(|| self.daemon.socket_path.clone()) {
            Some(path) => Ok(path),
            None => default_socket_path(),
        }
    }

    pub fn validate_phase_one(&self) -> Result<(), ConfigError> {
        if let Some(slot) = &self.plasma.mirror_slot {
            validate_slot_name(slot).map_err(|error| {
                ConfigError::Invalid(format!("invalid plasma mirror slot: {}", error.message))
            })?;
        }
        for (name, slot) in &self.slots {
            validate_slot_name(name).map_err(|error| {
                ConfigError::Invalid(format!("invalid configured slot: {}", error.message))
            })?;
            if slot.history_limit == Some(0) {
                return Err(ConfigError::Invalid(format!(
                    "slots.{name}.history_limit must be greater than zero"
                )));
            }
        }
        if self.daemon.history_limit == Some(0) {
            return Err(ConfigError::Invalid(
                "daemon.history_limit must be greater than zero".into(),
            ));
        }
        Ok(())
    }

    fn resolve_plasma(&self) -> Result<Option<ResolvedPlasmaConfig>, ConfigError> {
        if !self.plasma.enabled {
            return Ok(None);
        }
        if !self.plasma.text_only {
            return Err(ConfigError::Invalid(
                "plasma.text_only must be true; Klipper D-Bus integration supports text only"
                    .into(),
            ));
        }
        if !self.plasma.desktop_to_slot && !self.plasma.slot_to_desktop {
            return Err(ConfigError::Invalid(
                "at least one of plasma.desktop_to_slot or plasma.slot_to_desktop must be true"
                    .into(),
            ));
        }

        let marked_slots: Vec<&str> = self
            .slots
            .iter()
            .filter_map(|(name, configuration)| {
                (configuration.plasma_mirror == Some(true)).then_some(name.as_str())
            })
            .collect();
        if marked_slots.len() > 1 {
            return Err(ConfigError::Invalid(
                "only one slot can set plasma_mirror = true".into(),
            ));
        }
        let mirror_slot = match (&self.plasma.mirror_slot, marked_slots.first()) {
            (Some(configured), Some(marked)) if configured != marked => {
                return Err(ConfigError::Invalid(format!(
                    "plasma.mirror_slot ({configured}) conflicts with slots.{marked}.plasma_mirror"
                )));
            }
            (Some(configured), _) => configured.clone(),
            (None, Some(marked)) => (*marked).to_owned(),
            (None, None) => {
                return Err(ConfigError::Invalid(
                    "plasma.mirror_slot is required when Plasma integration is enabled".into(),
                ));
            }
        };

        Ok(Some(ResolvedPlasmaConfig {
            mirror_slot,
            desktop_to_slot: self.plasma.desktop_to_slot,
            slot_to_desktop: self.plasma.slot_to_desktop,
        }))
    }

    pub fn slot_sync_enabled(&self, slot: &str) -> bool {
        self.sync.enabled
            && self
                .slots
                .get(slot)
                .and_then(|configuration| configuration.sync)
                .unwrap_or(true)
    }

    pub fn sync_resolution(&self) -> SyncResolution {
        self.resolve_sync()
    }

    fn resolve_sync(&self) -> SyncResolution {
        if !self.sync.enabled {
            return SyncResolution::Disabled;
        }

        let resolve = || -> Result<ResolvedSyncConfig, ConfigError> {
            let relay_url = self
                .sync
                .relay_url
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| ConfigError::Invalid("sync.relay_url is required".into()))?;
            let parsed_relay = url::Url::parse(relay_url)
                .map_err(|_| ConfigError::Invalid("sync.relay_url is invalid".into()))?;
            if !matches!(parsed_relay.scheme(), "ws" | "wss")
                || parsed_relay.host_str().is_none()
                || !parsed_relay.username().is_empty()
                || parsed_relay.password().is_some()
                || parsed_relay.path() != "/sync/v1"
                || parsed_relay.query().is_some()
                || parsed_relay.fragment().is_some()
            {
                return Err(ConfigError::Invalid(
                    "sync.relay_url must be ws:// or wss:// with the exact path /sync/v1 and no credentials, query, or fragment".into(),
                ));
            }
            let account_name = self
                .sync
                .account_name
                .clone()
                .filter(|value| !value.is_empty())
                .ok_or_else(|| ConfigError::Invalid("sync.account_name is required".into()))?;

            let reconnect_min_delay = parse_duration(
                self.sync.reconnect_min_delay.as_deref().unwrap_or("1s"),
                "sync.reconnect_min_delay",
            )?;
            let reconnect_max_delay = parse_duration(
                self.sync.reconnect_max_delay.as_deref().unwrap_or("5m"),
                "sync.reconnect_max_delay",
            )?;
            if reconnect_min_delay.is_zero() || reconnect_max_delay < reconnect_min_delay {
                return Err(ConfigError::Invalid(
                    "sync reconnect delays must be nonzero and max must be at least min".into(),
                ));
            }

            Ok(ResolvedSyncConfig {
                relay_url: relay_url.to_owned(),
                account_name,
                reconnect_min_delay,
                reconnect_max_delay,
                device_name: self
                    .sync
                    .device_name
                    .clone()
                    .filter(|name| !name.trim().is_empty())
                    .unwrap_or_else(|| "kclip-device".into()),
                pairing_path: self
                    .sync
                    .pairing_path
                    .clone()
                    .map(Ok)
                    .unwrap_or_else(default_pairing_path)?,
                sync_key_path: self
                    .security
                    .sync_key_path
                    .clone()
                    .map(Ok)
                    .unwrap_or_else(default_sync_key_path)?,
            })
        };

        match resolve() {
            Ok(settings) => SyncResolution::Ready(settings),
            Err(error) => SyncResolution::Invalid(error.to_string()),
        }
    }
}

fn parse_duration(value: &str, field: &str) -> Result<Duration, ConfigError> {
    let (number, multiplier) = if let Some(number) = value.strip_suffix("ms") {
        (number, 1_u64)
    } else if let Some(number) = value.strip_suffix('s') {
        (number, 1_000)
    } else if let Some(number) = value.strip_suffix('m') {
        (number, 60_000)
    } else if let Some(number) = value.strip_suffix('h') {
        (number, 3_600_000)
    } else {
        return Err(ConfigError::Invalid(format!(
            "{field} must use ms, s, m, or h"
        )));
    };
    let amount = number
        .parse::<u64>()
        .map_err(|_| ConfigError::Invalid(format!("{field} contains an invalid duration")))?;
    let milliseconds = amount
        .checked_mul(multiplier)
        .ok_or_else(|| ConfigError::Invalid(format!("{field} duration is too large")))?;
    Ok(Duration::from_millis(milliseconds))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigUpdate {
    Created,
    Updated { backup_path: PathBuf },
    Unchanged,
}

/// A fully rendered and validated synchronization configuration change.
/// Preparing is read-only; `commit` performs the private backup and atomic
/// replacement after callers have staged any credential files.
pub struct PreparedSyncConfig {
    path: PathBuf,
    contents: Vec<u8>,
    previous: Option<Vec<u8>>,
    changed: bool,
}

impl PreparedSyncConfig {
    pub fn commit(self) -> Result<ConfigUpdate, ConfigError> {
        let parent = self.path.parent().ok_or_else(|| {
            ConfigError::Invalid("configuration path has no parent directory".into())
        })?;
        fs::create_dir_all(parent).map_err(|source| ConfigError::Write {
            path: parent.to_path_buf(),
            source,
        })?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|source| {
            ConfigError::Write {
                path: parent.to_path_buf(),
                source,
            }
        })?;

        if !self.changed {
            fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600)).map_err(
                |source| ConfigError::Write {
                    path: self.path.clone(),
                    source,
                },
            )?;
            return Ok(ConfigUpdate::Unchanged);
        }

        let update = if let Some(previous) = self.previous {
            let backup_path = backup_path(&self.path)?;
            atomic_write_private(&backup_path, &previous)?;
            ConfigUpdate::Updated { backup_path }
        } else {
            ConfigUpdate::Created
        };
        atomic_write_private(&self.path, &self.contents)?;
        Ok(update)
    }
}

/// Render the setup-owned `[sync]` fields while preserving every unrelated
/// table and custom slot. No filesystem mutation occurs until `commit`.
pub fn prepare_sync_setup(
    path: &Path,
    relay_url: &str,
    account_name: &str,
    device_name: &str,
) -> Result<PreparedSyncConfig, ConfigError> {
    prepare_sync_change(path, |sync| {
        sync.insert("enabled".into(), toml::Value::Boolean(true));
        sync.insert("relay_url".into(), toml::Value::String(relay_url.into()));
        sync.insert(
            "account_name".into(),
            toml::Value::String(account_name.into()),
        );
        sync.insert(
            "device_name".into(),
            toml::Value::String(device_name.into()),
        );
    })
}

pub fn prepare_sync_disconnect(path: &Path) -> Result<PreparedSyncConfig, ConfigError> {
    prepare_sync_change(path, |sync| {
        sync.insert("enabled".into(), toml::Value::Boolean(false));
    })
}

fn prepare_sync_change(
    path: &Path,
    change: impl FnOnce(&mut toml::map::Map<String, toml::Value>),
) -> Result<PreparedSyncConfig, ConfigError> {
    let previous = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(ConfigError::UnsafeFile(path.to_path_buf()));
            }
            Some(fs::read(path).map_err(|source| ConfigError::Read {
                path: path.to_path_buf(),
                source,
            })?)
        }
        Err(source) if source.kind() == io::ErrorKind::NotFound => None,
        Err(source) => {
            return Err(ConfigError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let mut document = match previous.as_deref() {
        Some(contents) => {
            toml::from_slice::<toml::Value>(contents).map_err(|source| ConfigError::Parse {
                path: path.to_path_buf(),
                source,
            })?
        }
        None => toml::Value::Table(toml::map::Map::new()),
    };
    let original_document = document.clone();
    let root = document.as_table_mut().ok_or_else(|| {
        ConfigError::Invalid("configuration document must be a TOML table".into())
    })?;
    let sync = root
        .entry("sync")
        .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
        .as_table_mut()
        .ok_or_else(|| ConfigError::Invalid("sync must be a TOML table".into()))?;
    change(sync);
    let rendered = toml::to_string_pretty(&document).map_err(|source| ConfigError::Serialize {
        path: path.to_path_buf(),
        source,
    })?;
    let parsed: Config = toml::from_str(&rendered).map_err(|source| ConfigError::Parse {
        path: path.to_path_buf(),
        source,
    })?;
    parsed.validate_phase_one()?;
    if parsed.sync.enabled && !matches!(parsed.resolve_sync(), SyncResolution::Ready(_)) {
        let SyncResolution::Invalid(message) = parsed.resolve_sync() else {
            unreachable!()
        };
        return Err(ConfigError::Invalid(message));
    }
    let changed = previous.is_none() || document != original_document;
    Ok(PreparedSyncConfig {
        path: path.to_path_buf(),
        contents: rendered.into_bytes(),
        previous,
        changed,
    })
}

pub fn update_config_file(
    path: &Path,
    default_contents: &str,
) -> Result<ConfigUpdate, ConfigError> {
    let parent = path
        .parent()
        .ok_or_else(|| ConfigError::Invalid("configuration path has no parent directory".into()))?;
    fs::create_dir_all(parent).map_err(|source| ConfigError::Write {
        path: parent.to_path_buf(),
        source,
    })?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(|source| {
        ConfigError::Write {
            path: parent.to_path_buf(),
            source,
        }
    })?;

    let defaults: toml::Value =
        toml::from_str(default_contents).map_err(|source| ConfigError::Parse {
            path: PathBuf::from("embedded default configuration"),
            source,
        })?;

    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            let parsed: Config =
                toml::from_str(default_contents).map_err(|source| ConfigError::Parse {
                    path: path.to_path_buf(),
                    source,
                })?;
            parsed.validate_phase_one()?;
            atomic_write_private(path, default_contents.as_bytes())?;
            return Ok(ConfigUpdate::Created);
        }
        Err(source) => {
            return Err(ConfigError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(ConfigError::UnsafeFile(path.to_path_buf()));
    }

    let existing_contents = fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let mut existing: toml::Value =
        toml::from_str(&existing_contents).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
    let changed = merge_missing(&mut existing, &defaults);
    let merged = toml::to_string_pretty(&existing).map_err(|source| ConfigError::Serialize {
        path: path.to_path_buf(),
        source,
    })?;
    let parsed: Config = toml::from_str(&merged).map_err(|source| ConfigError::Parse {
        path: path.to_path_buf(),
        source,
    })?;
    parsed.validate_phase_one()?;

    if !changed {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| {
            ConfigError::Write {
                path: path.to_path_buf(),
                source,
            }
        })?;
        return Ok(ConfigUpdate::Unchanged);
    }

    let backup_path = backup_path(path)?;
    fs::copy(path, &backup_path).map_err(|source| ConfigError::Write {
        path: backup_path.clone(),
        source,
    })?;
    fs::set_permissions(&backup_path, fs::Permissions::from_mode(0o600)).map_err(|source| {
        ConfigError::Write {
            path: backup_path.clone(),
            source,
        }
    })?;
    File::open(&backup_path)
        .and_then(|file| file.sync_all())
        .map_err(|source| ConfigError::Write {
            path: backup_path.clone(),
            source,
        })?;
    atomic_write_private(path, merged.as_bytes())?;
    Ok(ConfigUpdate::Updated { backup_path })
}

fn merge_missing(existing: &mut toml::Value, defaults: &toml::Value) -> bool {
    let (toml::Value::Table(existing), toml::Value::Table(defaults)) = (existing, defaults) else {
        return false;
    };
    let mut changed = false;
    for (key, default_value) in defaults {
        if let Some(existing_value) = existing.get_mut(key) {
            changed |= merge_missing(existing_value, default_value);
        } else {
            existing.insert(key.clone(), default_value.clone());
            changed = true;
        }
    }
    changed
}

fn atomic_write_private(path: &Path, contents: &[u8]) -> Result<(), ConfigError> {
    let parent = path
        .parent()
        .ok_or_else(|| ConfigError::Invalid("configuration path has no parent directory".into()))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| ConfigError::Invalid("configuration path has no file name".into()))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let temporary = parent.join(format!(
        ".{}.kclip-{}-{nonce}.tmp",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    let write_result = (|| -> io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result.map_err(|source| ConfigError::Write {
        path: path.to_path_buf(),
        source,
    })
}

fn backup_path(path: &Path) -> Result<PathBuf, ConfigError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ConfigError::Invalid("system clock is before the Unix epoch".into()))?
        .as_secs();
    let file_name = path
        .file_name()
        .ok_or_else(|| ConfigError::Invalid("configuration path has no file name".into()))?;
    let stem = format!("{}.bak.{timestamp}", file_name.to_string_lossy());
    for suffix in 0_u32.. {
        let name = if suffix == 0 {
            stem.clone()
        } else {
            format!("{stem}.{suffix}")
        };
        let candidate = path.with_file_name(name);
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    unreachable!("u32 backup suffixes were exhausted")
}

pub fn default_socket_path() -> Result<PathBuf, ConfigError> {
    let runtime = env::var_os("XDG_RUNTIME_DIR").ok_or(ConfigError::MissingRuntimeDirectory)?;
    if runtime.is_empty() {
        return Err(ConfigError::MissingRuntimeDirectory);
    }
    Ok(PathBuf::from(runtime).join("kclip/kclipd.sock"))
}

pub fn default_data_dir() -> Result<PathBuf, ConfigError> {
    if let Some(path) = env::var_os("XDG_DATA_HOME").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(path).join("kclip"));
    }
    Ok(home_dir()?.join(".local/share/kclip"))
}

pub fn default_config_path() -> Result<PathBuf, ConfigError> {
    if let Some(path) = env::var_os("XDG_CONFIG_HOME").filter(|value| !value.is_empty()) {
        return Ok(PathBuf::from(path).join("kclip/config.toml"));
    }
    Ok(home_dir()?.join(".config/kclip/config.toml"))
}

pub fn default_pairing_path() -> Result<PathBuf, ConfigError> {
    Ok(default_config_path()?
        .parent()
        .expect("default configuration path has a parent")
        .join("pairing.json"))
}

pub fn default_sync_key_path() -> Result<PathBuf, ConfigError> {
    Ok(default_data_dir()?.join("sync.key"))
}

fn home_dir() -> Result<PathBuf, ConfigError> {
    env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or(ConfigError::MissingHomeDirectory)
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("XDG_RUNTIME_DIR is unavailable; set it or pass an explicit socket path")]
    MissingRuntimeDirectory,
    #[error("HOME is unavailable and no XDG directory override was provided")]
    MissingHomeDirectory,
    #[error("could not read configuration at {path}: {source}")]
    Read { path: PathBuf, source: io::Error },
    #[error("invalid configuration at {path}: {source}")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("could not serialize updated configuration at {path}: {source}")]
    Serialize {
        path: PathBuf,
        source: toml::ser::Error,
    },
    #[error("could not write configuration at {path}: {source}")]
    Write { path: PathBuf, source: io::Error },
    #[error("refusing to update non-regular or symbolic-link configuration at {0}")]
    UnsafeFile(PathBuf),
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const DEFAULTS: &str = r#"
[daemon]
max_content_size = 10485760
history_limit = 10

[storage]

[plasma]
enabled = false

[sync]
enabled = false

[security]
require_encrypted_sync = true

[slots.default]
sync = true
history_limit = 10
"#;

    #[test]
    fn rejects_unknown_configuration_fields() {
        let error = toml::from_str::<Config>("[daemon]\nunknown = true\n").unwrap_err();
        assert!(error.to_string().contains("unknown"));
    }

    #[test]
    fn validates_content_limit() {
        let config: Config = toml::from_str("[daemon]\nmax_content_size = 0\n").unwrap();
        assert!(
            config
                .resolve(
                    Some("/tmp/kclip.sock".into()),
                    Some("/tmp/data".into()),
                    None
                )
                .is_err()
        );
    }

    #[test]
    fn resolves_text_only_plasma_mirroring() {
        let config: Config = toml::from_str(
            r#"
[plasma]
enabled = true
mirror_slot = "default"
desktop_to_slot = true
slot_to_desktop = true
text_only = true

[slots.default]
plasma_mirror = true
"#,
        )
        .unwrap();
        let resolved = config
            .resolve(
                Some("/tmp/kclip.sock".into()),
                Some("/tmp/data".into()),
                None,
            )
            .unwrap();
        assert_eq!(
            resolved.plasma,
            Some(ResolvedPlasmaConfig {
                mirror_slot: "default".into(),
                desktop_to_slot: true,
                slot_to_desktop: true,
            })
        );
    }

    #[test]
    fn rejects_ambiguous_or_non_text_plasma_configuration() {
        for source in [
            r#"
[plasma]
enabled = true
mirror_slot = "default"
slot_to_desktop = true
text_only = false
"#,
            r#"
[plasma]
enabled = true
mirror_slot = "default"
slot_to_desktop = true
text_only = true
[slots.other]
plasma_mirror = true
"#,
            r#"
[plasma]
enabled = true
mirror_slot = "default"
text_only = true
"#,
        ] {
            let config: Config = toml::from_str(source).unwrap();
            assert!(
                config
                    .resolve(
                        Some("/tmp/kclip.sock".into()),
                        Some("/tmp/data".into()),
                        None,
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn update_creates_a_private_configuration() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("config/kclip/config.toml");
        assert_eq!(
            update_config_file(&path, DEFAULTS).unwrap(),
            ConfigUpdate::Created
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        Config::load(Some(&path))
            .unwrap()
            .validate_phase_one()
            .unwrap();
    }

    #[test]
    fn update_preserves_values_and_custom_slots_while_adding_defaults() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("config.toml");
        fs::write(
            &path,
            "[daemon]\nmax_content_size = 42\n\n[slots.custom]\nsync = false\n",
        )
        .unwrap();

        let ConfigUpdate::Updated { backup_path } = update_config_file(&path, DEFAULTS).unwrap()
        else {
            panic!("expected the configuration to be updated")
        };
        let value: toml::Value = toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(value["daemon"]["max_content_size"].as_integer(), Some(42));
        assert_eq!(value["daemon"]["history_limit"].as_integer(), Some(10));
        assert_eq!(value["slots"]["custom"]["sync"].as_bool(), Some(false));
        assert!(backup_path.is_file());
        assert!(
            fs::read_to_string(backup_path)
                .unwrap()
                .contains("max_content_size = 42")
        );
    }

    #[test]
    fn second_update_is_idempotent() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("config.toml");
        update_config_file(&path, DEFAULTS).unwrap();
        assert_eq!(
            update_config_file(&path, DEFAULTS).unwrap(),
            ConfigUpdate::Unchanged
        );
    }

    #[test]
    fn invalid_existing_configuration_is_never_replaced() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("config.toml");
        let original = b"[daemon]\nunknown_field = true\n";
        fs::write(&path, original).unwrap();

        assert!(update_config_file(&path, DEFAULTS).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    #[test]
    fn enabled_sync_accepts_noise_ws_and_rejects_non_websocket_urls() {
        let paired_lan: Config = toml::from_str(
            r#"
[sync]
enabled = true
relay_url = "ws://clipboard.example/sync/v1"
account_name = "alice"
[security]
sync_key_path = "/tmp/key"
"#,
        )
        .unwrap();
        let resolved = paired_lan
            .resolve(
                Some("/tmp/kclip.sock".into()),
                Some("/tmp/kclip-data".into()),
                None,
            )
            .unwrap();
        assert!(matches!(resolved.sync, SyncResolution::Ready(_)));

        let invalid: Config = toml::from_str(
            "[sync]\nenabled = true\nrelay_url = \"http://clipboard.example/sync/v1\"\n",
        )
        .unwrap();
        let resolved = invalid
            .resolve(
                Some("/tmp/kclip.sock".into()),
                Some("/tmp/kclip-data".into()),
                None,
            )
            .unwrap();
        assert!(matches!(resolved.sync, SyncResolution::Invalid(_)));

        let secure: Config = toml::from_str(
            r#"
[sync]
enabled = true
relay_url = "wss://clipboard.example/sync/v1"
account_name = "alice"
reconnect_min_delay = "500ms"
reconnect_max_delay = "2m"
[security]
sync_key_path = "/tmp/key"
"#,
        )
        .unwrap();
        let resolved = secure
            .resolve(
                Some("/tmp/kclip.sock".into()),
                Some("/tmp/kclip-data".into()),
                None,
            )
            .unwrap();
        assert!(matches!(resolved.sync, SyncResolution::Ready(_)));
    }

    #[test]
    fn guided_setup_preserves_custom_values_and_creates_private_backup() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("kclip/config.toml");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            "[daemon]\nmax_content_size = 42\n\n[slots.private]\nsync = false\n",
        )
        .unwrap();

        let prepared = prepare_sync_setup(
            &path,
            "wss://clipboard.example.test/sync/v1",
            "alice",
            "office-laptop",
        )
        .unwrap();
        let ConfigUpdate::Updated { backup_path } = prepared.commit().unwrap() else {
            panic!("expected an update")
        };
        let configured = Config::load(Some(&path)).unwrap();
        assert!(configured.sync.enabled);
        assert_eq!(configured.sync.account_name.as_deref(), Some("alice"));
        assert_eq!(
            configured.sync.device_name.as_deref(),
            Some("office-laptop")
        );
        assert_eq!(configured.daemon.max_content_size, Some(42));
        assert_eq!(configured.slots["private"].sync, Some(false));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&backup_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            prepare_sync_setup(
                &path,
                "wss://clipboard.example.test/sync/v1",
                "alice",
                "office-laptop",
            )
            .unwrap()
            .commit()
            .unwrap(),
            ConfigUpdate::Unchanged
        );
    }
}
