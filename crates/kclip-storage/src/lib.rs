use kclip_protocol::{RevisionMetadata, validate_slot_name};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fmt::Write as _,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use uuid::Uuid;

pub const SCHEMA_VERSION: u32 = 1;

pub struct Storage {
    connection: Mutex<Connection>,
    blobs: BlobStore,
    max_content_size: u64,
}

impl Storage {
    pub fn open(
        database_path: impl AsRef<Path>,
        blob_directory: impl AsRef<Path>,
        max_content_size: u64,
    ) -> Result<Self, StorageError> {
        let database_path = database_path.as_ref();
        let database_parent = database_path.parent().ok_or_else(|| {
            StorageError::InvalidPath("database path has no parent directory".into())
        })?;
        create_private_directory(database_parent)?;

        let mut connection = Connection::open(database_path)?;
        fs::set_permissions(database_path, fs::Permissions::from_mode(0o600))?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             PRAGMA synchronous = FULL;",
        )?;
        apply_migrations(&mut connection)?;
        initialize_metadata(&mut connection)?;

        let blobs = BlobStore::open(blob_directory)?;
        blobs.recover_temporary_files()?;

        let storage = Self {
            connection: Mutex::new(connection),
            blobs,
            max_content_size,
        };
        storage.garbage_collect_unreferenced_blobs()?;
        Ok(storage)
    }

    pub fn copy(
        &self,
        slot: &str,
        content: &[u8],
        content_type: Option<&str>,
    ) -> Result<RevisionMetadata, StorageError> {
        validate_slot(slot)?;
        if content.len() as u64 > self.max_content_size {
            return Err(StorageError::ContentTooLarge {
                actual: content.len() as u64,
                maximum: self.max_content_size,
            });
        }

        let blob = self.blobs.put(content)?;
        let detected_content_type = content_type
            .map(str::to_owned)
            .unwrap_or_else(|| detect_content_type(content).to_owned());

        let mut connection = self.lock_connection()?;
        let transaction = connection.transaction()?;
        let metadata = create_revision(
            &transaction,
            slot,
            Some(&blob.hash),
            content.len() as u64,
            Some(&detected_content_type),
            false,
        )?;
        transaction.commit()?;
        Ok(metadata)
    }

    pub fn paste(&self, slot: &str) -> Result<(RevisionMetadata, Vec<u8>), StorageError> {
        validate_slot(slot)?;
        let metadata = {
            let connection = self.lock_connection()?;
            connection
                .query_row(
                    "SELECT r.revision_id, r.slot_name, r.origin_device_id,
                            r.origin_sequence, r.hlc_physical, r.hlc_logical,
                            r.content_hash, r.content_size, r.content_type,
                            r.created_at, r.expires_at, r.is_deleted,
                            r.is_local_only, r.source_adapter
                     FROM slots s
                     JOIN revisions r ON r.revision_id = s.current_revision_id
                     WHERE s.slot_name = ?1 AND r.is_deleted = 0",
                    [slot],
                    revision_from_row,
                )
                .optional()?
                .ok_or_else(|| StorageError::SlotNotFound(slot.to_owned()))?
        };

        let hash = metadata
            .content_hash
            .as_deref()
            .ok_or_else(|| StorageError::Corrupt("live revision has no content hash".into()))?;
        let content = self.blobs.read(hash)?;
        if content.len() as u64 != metadata.content_size {
            return Err(StorageError::Corrupt(
                "blob size does not match revision metadata".into(),
            ));
        }
        Ok((metadata, content))
    }

    pub fn list(&self) -> Result<Vec<RevisionMetadata>, StorageError> {
        let connection = self.lock_connection()?;
        let mut statement = connection.prepare(
            "SELECT r.revision_id, r.slot_name, r.origin_device_id,
                    r.origin_sequence, r.hlc_physical, r.hlc_logical,
                    r.content_hash, r.content_size, r.content_type,
                    r.created_at, r.expires_at, r.is_deleted,
                    r.is_local_only, r.source_adapter
             FROM slots s
             JOIN revisions r ON r.revision_id = s.current_revision_id
             WHERE r.is_deleted = 0
             ORDER BY s.slot_name COLLATE BINARY",
        )?;
        let rows = statement.query_map([], revision_from_row)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    }

    pub fn clear(&self, slot: &str) -> Result<RevisionMetadata, StorageError> {
        validate_slot(slot)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection.transaction()?;
        let metadata = create_revision(&transaction, slot, None, 0, None, true)?;
        transaction.commit()?;
        Ok(metadata)
    }

    pub fn device_id(&self) -> Result<String, StorageError> {
        let connection = self.lock_connection()?;
        metadata_value(&connection, "device_id")
    }

    pub fn schema_version(&self) -> u32 {
        SCHEMA_VERSION
    }

    pub fn blob_directory(&self) -> &Path {
        self.blobs.directory()
    }

    pub fn garbage_collect_unreferenced_blobs(&self) -> Result<usize, StorageError> {
        let referenced = {
            let connection = self.lock_connection()?;
            let mut statement = connection.prepare(
                "SELECT DISTINCT content_hash FROM revisions WHERE content_hash IS NOT NULL",
            )?;
            let values = statement.query_map([], |row| row.get::<_, String>(0))?;
            values.collect::<Result<HashSet<_>, _>>()?
        };
        self.blobs.remove_unreferenced(&referenced)
    }

    fn lock_connection(&self) -> Result<MutexGuard<'_, Connection>, StorageError> {
        self.connection
            .lock()
            .map_err(|_| StorageError::LockPoisoned)
    }
}

#[derive(Debug, Clone)]
pub struct BlobStore {
    directory: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredBlob {
    pub hash: String,
    pub path: PathBuf,
    pub size: u64,
}

impl BlobStore {
    pub fn open(directory: impl AsRef<Path>) -> Result<Self, StorageError> {
        create_private_directory(directory.as_ref())?;
        Ok(Self {
            directory: directory.as_ref().to_path_buf(),
        })
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn put(&self, content: &[u8]) -> Result<StoredBlob, StorageError> {
        let hash = sha256_hex(content);
        let final_path = self.directory.join(&hash);
        if final_path.is_file() {
            return Ok(StoredBlob {
                hash,
                path: final_path,
                size: content.len() as u64,
            });
        }

        let temporary_path = self
            .directory
            .join(format!(".tmp-{}", Uuid::new_v4().simple()));
        let write_result = (|| -> Result<(), StorageError> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary_path)?;
            file.write_all(content)?;
            file.sync_all()?;
            fs::rename(&temporary_path, &final_path)?;
            File::open(&self.directory)?.sync_all()?;
            Ok(())
        })();

        if write_result.is_err() {
            let _ = fs::remove_file(&temporary_path);
        }
        write_result?;

        Ok(StoredBlob {
            hash,
            path: final_path,
            size: content.len() as u64,
        })
    }

    pub fn read(&self, hash: &str) -> Result<Vec<u8>, StorageError> {
        if !is_valid_hash(hash) {
            return Err(StorageError::Corrupt(
                "invalid blob hash in database".into(),
            ));
        }
        let mut content = Vec::new();
        File::open(self.directory.join(hash))?.read_to_end(&mut content)?;
        Ok(content)
    }

    fn recover_temporary_files(&self) -> Result<usize, StorageError> {
        let mut removed = 0;
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            if entry.file_type()?.is_file()
                && entry.file_name().to_string_lossy().starts_with(".tmp-")
            {
                fs::remove_file(entry.path())?;
                removed += 1;
            }
        }
        Ok(removed)
    }

    fn remove_unreferenced(&self, referenced: &HashSet<String>) -> Result<usize, StorageError> {
        let mut removed = 0;
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if is_valid_hash(&name) && !referenced.contains(&name) {
                fs::remove_file(entry.path())?;
                removed += 1;
            }
        }
        if removed > 0 {
            File::open(&self.directory)?.sync_all()?;
        }
        Ok(removed)
    }
}

fn create_revision(
    transaction: &Transaction<'_>,
    slot: &str,
    content_hash: Option<&str>,
    content_size: u64,
    content_type: Option<&str>,
    is_deleted: bool,
) -> Result<RevisionMetadata, StorageError> {
    let now = unix_millis()?;
    transaction.execute(
        "INSERT INTO slots (
             slot_name, current_revision_id, sync_policy, history_limit,
             history_max_age_seconds, created_at, updated_at
         ) VALUES (?1, NULL, 'sync', 10, 86400, ?2, ?2)
         ON CONFLICT(slot_name) DO NOTHING",
        params![slot, now],
    )?;

    let device_id = transaction.query_row(
        "SELECT value FROM metadata WHERE key = 'device_id'",
        [],
        |row| row.get::<_, String>(0),
    )?;
    let sequence = parse_metadata_u64(transaction, "next_origin_sequence")?;
    let last_physical = parse_metadata_i64(transaction, "last_hlc_physical")?;
    let last_logical = parse_metadata_u64(transaction, "last_hlc_logical")?;
    let (hlc_physical, hlc_logical) = if now > last_physical {
        (now, 0_u32)
    } else {
        let next = last_logical
            .checked_add(1)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| StorageError::Corrupt("logical clock overflow".into()))?;
        (last_physical, next)
    };
    let revision_id = format!("{device_id}:{sequence}");

    transaction.execute(
        "INSERT INTO revisions (
             revision_id, slot_name, origin_device_id, origin_sequence,
             hlc_physical, hlc_logical, content_hash, content_size,
             content_type, blob_path, created_at, received_at, expires_at,
             is_deleted, is_local_only, no_history, source_adapter,
             parent_revision_id
         ) VALUES (
             ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?7, ?10, ?10, NULL,
             ?11, 0, 0, 'cli',
             (SELECT current_revision_id FROM slots WHERE slot_name = ?2)
         )",
        params![
            revision_id,
            slot,
            device_id,
            i64::try_from(sequence)
                .map_err(|_| StorageError::Corrupt("sequence overflow".into()))?,
            hlc_physical,
            hlc_logical,
            content_hash,
            i64::try_from(content_size)
                .map_err(|_| StorageError::Corrupt("content size overflow".into()))?,
            content_type,
            now,
            is_deleted,
        ],
    )?;
    transaction.execute(
        "UPDATE slots SET current_revision_id = ?1, updated_at = ?2 WHERE slot_name = ?3",
        params![revision_id, now, slot],
    )?;
    let next_sequence = sequence
        .checked_add(1)
        .ok_or_else(|| StorageError::Corrupt("origin sequence overflow".into()))?;
    set_metadata(
        transaction,
        "next_origin_sequence",
        &next_sequence.to_string(),
    )?;
    set_metadata(transaction, "last_hlc_physical", &hlc_physical.to_string())?;
    set_metadata(transaction, "last_hlc_logical", &hlc_logical.to_string())?;

    Ok(RevisionMetadata {
        revision_id,
        slot: slot.to_owned(),
        origin_device_id: device_id,
        origin_sequence: sequence,
        hlc_physical,
        hlc_logical,
        content_hash: content_hash.map(str::to_owned),
        content_size,
        content_type: content_type.map(str::to_owned),
        created_at: now,
        expires_at: None,
        is_deleted,
        is_local_only: false,
        source_adapter: "cli".into(),
        synchronization_state: "local".into(),
    })
}

fn revision_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RevisionMetadata> {
    Ok(RevisionMetadata {
        revision_id: row.get(0)?,
        slot: row.get(1)?,
        origin_device_id: row.get(2)?,
        origin_sequence: row.get::<_, i64>(3)? as u64,
        hlc_physical: row.get(4)?,
        hlc_logical: row.get::<_, i64>(5)? as u32,
        content_hash: row.get(6)?,
        content_size: row.get::<_, i64>(7)? as u64,
        content_type: row.get(8)?,
        created_at: row.get(9)?,
        expires_at: row.get(10)?,
        is_deleted: row.get(11)?,
        is_local_only: row.get(12)?,
        source_adapter: row.get(13)?,
        synchronization_state: "local".into(),
    })
}

fn apply_migrations(connection: &mut Connection) -> Result<(), StorageError> {
    let current: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if current > SCHEMA_VERSION {
        return Err(StorageError::UnsupportedSchema(current));
    }
    if current == 0 {
        let transaction = connection.transaction()?;
        transaction.execute_batch(
            "CREATE TABLE metadata (
                 key TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );

             CREATE TABLE slots (
                 slot_name TEXT PRIMARY KEY,
                 current_revision_id TEXT,
                 sync_policy TEXT NOT NULL,
                 history_limit INTEGER NOT NULL,
                 history_max_age_seconds INTEGER NOT NULL,
                 created_at INTEGER NOT NULL,
                 updated_at INTEGER NOT NULL
             );

             CREATE TABLE revisions (
                 revision_id TEXT PRIMARY KEY,
                 slot_name TEXT NOT NULL REFERENCES slots(slot_name),
                 origin_device_id TEXT NOT NULL,
                 origin_sequence INTEGER NOT NULL,
                 hlc_physical INTEGER NOT NULL,
                 hlc_logical INTEGER NOT NULL,
                 content_hash TEXT,
                 content_size INTEGER NOT NULL,
                 content_type TEXT,
                 blob_path TEXT,
                 created_at INTEGER NOT NULL,
                 received_at INTEGER NOT NULL,
                 expires_at INTEGER,
                 is_deleted INTEGER NOT NULL CHECK(is_deleted IN (0, 1)),
                 is_local_only INTEGER NOT NULL CHECK(is_local_only IN (0, 1)),
                 no_history INTEGER NOT NULL CHECK(no_history IN (0, 1)),
                 source_adapter TEXT NOT NULL,
                 parent_revision_id TEXT REFERENCES revisions(revision_id),
                 UNIQUE(origin_device_id, origin_sequence)
             );

             CREATE INDEX revisions_slot_created
                 ON revisions(slot_name, created_at DESC);
             CREATE INDEX revisions_content_hash
                 ON revisions(content_hash) WHERE content_hash IS NOT NULL;

             CREATE TABLE devices (
                 device_id TEXT PRIMARY KEY,
                 display_name TEXT NOT NULL,
                 public_identity_key BLOB,
                 trust_state TEXT NOT NULL,
                 paired_at INTEGER,
                 revoked_at INTEGER,
                 last_seen_at INTEGER,
                 last_acknowledged_revision TEXT
             );

             CREATE TABLE outbox (
                 outbox_id INTEGER PRIMARY KEY,
                 revision_id TEXT NOT NULL REFERENCES revisions(revision_id),
                 destination_device_id TEXT,
                 envelope_path_or_blob TEXT,
                 created_at INTEGER NOT NULL,
                 next_attempt_at INTEGER,
                 attempt_count INTEGER NOT NULL DEFAULT 0,
                 last_error TEXT,
                 acknowledged_at INTEGER
             );

             CREATE TABLE inbox (
                 message_id TEXT PRIMARY KEY,
                 source_device_id TEXT NOT NULL,
                 received_at INTEGER NOT NULL,
                 processed_at INTEGER,
                 processing_error TEXT
             );

             CREATE TABLE acknowledgements (
                 device_id TEXT NOT NULL,
                 revision_id TEXT NOT NULL,
                 acknowledged_at INTEGER NOT NULL,
                 PRIMARY KEY(device_id, revision_id)
             );

             CREATE TABLE audit_events (
                 event_id INTEGER PRIMARY KEY,
                 event_type TEXT NOT NULL,
                 device_id TEXT,
                 revision_id TEXT,
                 created_at INTEGER NOT NULL,
                 details_json TEXT
             );",
        )?;
        transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        transaction.execute(
            "INSERT INTO metadata(key, value) VALUES ('schema_version', ?1)",
            [SCHEMA_VERSION.to_string()],
        )?;
        transaction.commit()?;
    }
    Ok(())
}

fn initialize_metadata(connection: &mut Connection) -> Result<(), StorageError> {
    let transaction = connection.transaction()?;
    transaction.execute(
        "INSERT OR IGNORE INTO metadata(key, value) VALUES ('device_id', ?1)",
        [format!("device-{}", Uuid::new_v4().simple())],
    )?;
    transaction.execute(
        "INSERT OR IGNORE INTO metadata(key, value) VALUES ('next_origin_sequence', '1')",
        [],
    )?;
    transaction.execute(
        "INSERT OR IGNORE INTO metadata(key, value) VALUES ('last_hlc_physical', '0')",
        [],
    )?;
    transaction.execute(
        "INSERT OR IGNORE INTO metadata(key, value) VALUES ('last_hlc_logical', '0')",
        [],
    )?;
    transaction.commit()?;
    Ok(())
}

fn metadata_value(connection: &Connection, key: &str) -> Result<String, StorageError> {
    connection
        .query_row("SELECT value FROM metadata WHERE key = ?1", [key], |row| {
            row.get(0)
        })
        .map_err(StorageError::from)
}

fn parse_metadata_u64(transaction: &Transaction<'_>, key: &str) -> Result<u64, StorageError> {
    transaction
        .query_row("SELECT value FROM metadata WHERE key = ?1", [key], |row| {
            row.get::<_, String>(0)
        })?
        .parse()
        .map_err(|_| StorageError::Corrupt(format!("invalid metadata value for {key}")))
}

fn parse_metadata_i64(transaction: &Transaction<'_>, key: &str) -> Result<i64, StorageError> {
    transaction
        .query_row("SELECT value FROM metadata WHERE key = ?1", [key], |row| {
            row.get::<_, String>(0)
        })?
        .parse()
        .map_err(|_| StorageError::Corrupt(format!("invalid metadata value for {key}")))
}

fn set_metadata(transaction: &Transaction<'_>, key: &str, value: &str) -> Result<(), StorageError> {
    transaction.execute(
        "UPDATE metadata SET value = ?1 WHERE key = ?2",
        params![value, key],
    )?;
    Ok(())
}

fn validate_slot(slot: &str) -> Result<(), StorageError> {
    validate_slot_name(slot).map_err(|error| StorageError::InvalidSlot(error.message))
}

fn detect_content_type(content: &[u8]) -> &'static str {
    if std::str::from_utf8(content).is_ok() {
        "text/plain; charset=utf-8"
    } else {
        "application/octet-stream"
    }
}

fn sha256_hex(content: &[u8]) -> String {
    let digest = Sha256::digest(content);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn is_valid_hash(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn unix_millis() -> Result<i64, StorageError> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StorageError::ClockBeforeEpoch)?;
    i64::try_from(duration.as_millis()).map_err(|_| StorageError::ClockOverflow)
}

fn create_private_directory(path: &Path) -> Result<(), StorageError> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("slot not found: {0}")]
    SlotNotFound(String),
    #[error("invalid slot name: {0}")]
    InvalidSlot(String),
    #[error("content size {actual} exceeds configured maximum {maximum}")]
    ContentTooLarge { actual: u64, maximum: u64 },
    #[error("storage database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("storage I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid storage path: {0}")]
    InvalidPath(String),
    #[error("database schema version {0} is newer than this daemon supports")]
    UnsupportedSchema(u32),
    #[error("storage metadata is inconsistent: {0}")]
    Corrupt(String),
    #[error("storage lock was poisoned")]
    LockPoisoned,
    #[error("system clock is before the Unix epoch")]
    ClockBeforeEpoch,
    #[error("system clock value is too large")]
    ClockOverflow,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn storage(temp: &TempDir) -> Storage {
        Storage::open(
            temp.path().join("kclip.db"),
            temp.path().join("blobs"),
            1024,
        )
        .unwrap()
    }

    #[test]
    fn schema_is_created_automatically() {
        let temp = TempDir::new().unwrap();
        let storage = storage(&temp);
        let connection = storage.lock_connection().unwrap();
        let version: u32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let table_count: u32 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='revisions'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(table_count, 1);
    }

    #[test]
    fn blob_writes_are_atomic_and_identical_content_is_deduplicated() {
        let temp = TempDir::new().unwrap();
        let storage = storage(&temp);
        let first = storage.copy("first", b"same bytes", None).unwrap();
        let second = storage.copy("second", b"same bytes", None).unwrap();
        assert_eq!(first.content_hash, second.content_hash);

        let entries: Vec<_> = fs::read_dir(storage.blob_directory()).unwrap().collect();
        assert_eq!(entries.len(), 1);
        let entry = entries[0].as_ref().unwrap();
        assert!(!entry.file_name().to_string_lossy().starts_with(".tmp-"));
        assert_eq!(fs::read(entry.path()).unwrap(), b"same bytes");
    }

    #[test]
    fn sequence_and_content_survive_reopen() {
        let temp = TempDir::new().unwrap();
        let first_id = {
            let storage = storage(&temp);
            storage
                .copy("default", b"persistent", None)
                .unwrap()
                .revision_id
        };
        let storage = storage(&temp);
        assert_eq!(storage.paste("default").unwrap().1, b"persistent");
        let second_id = storage.copy("default", b"new", None).unwrap().revision_id;
        assert_ne!(first_id, second_id);
    }

    #[test]
    fn clear_hides_only_the_selected_slot() {
        let temp = TempDir::new().unwrap();
        let storage = storage(&temp);
        storage.copy("one", b"1", None).unwrap();
        storage.copy("two", b"2", None).unwrap();
        storage.clear("one").unwrap();
        assert!(matches!(
            storage.paste("one"),
            Err(StorageError::SlotNotFound(_))
        ));
        assert_eq!(storage.paste("two").unwrap().1, b"2");
    }

    #[test]
    fn oversized_content_is_rejected_without_a_revision() {
        let temp = TempDir::new().unwrap();
        let storage = storage(&temp);
        assert!(matches!(
            storage.copy("default", &[0; 1025], None),
            Err(StorageError::ContentTooLarge { .. })
        ));
        assert!(storage.list().unwrap().is_empty());
    }
}
