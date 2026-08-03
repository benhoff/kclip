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

pub const SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationOptions {
    pub source_adapter: String,
    pub local_only: bool,
    pub enqueue_sync: bool,
}

impl Default for MutationOptions {
    fn default() -> Self {
        Self {
            source_adapter: "cli".into(),
            local_only: false,
            enqueue_sync: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRevision {
    pub metadata: RevisionMetadata,
    pub parent_revision_id: Option<String>,
    pub content: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboxItem {
    pub outbox_id: i64,
    pub message_id: String,
    pub revision: StoredRevision,
    pub encrypted_envelope: Option<String>,
    pub attempt_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboxEvent {
    pub message_id: String,
    pub server_sequence: u64,
    pub source_device_id: String,
    pub algorithm: String,
    pub nonce: String,
    pub ciphertext: String,
    pub tag: String,
    pub accepted_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncStorageStatus {
    pub pending_outbox_count: u64,
    pub oldest_pending_age_millis: Option<u64>,
    pub server_cursor: u64,
    pub quarantined_events: u64,
    pub last_acknowledged_at: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteApplyOutcome {
    AppliedWinner,
    AppliedHistory,
    Duplicate,
}

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
        self.copy_with_options(slot, content, content_type, MutationOptions::default())
    }

    pub fn copy_with_options(
        &self,
        slot: &str,
        content: &[u8],
        content_type: Option<&str>,
        options: MutationOptions,
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
            &options,
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
        self.clear_with_options(slot, MutationOptions::default())
    }

    pub fn clear_with_options(
        &self,
        slot: &str,
        options: MutationOptions,
    ) -> Result<RevisionMetadata, StorageError> {
        validate_slot(slot)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection.transaction()?;
        let metadata = create_revision(&transaction, slot, None, 0, None, true, &options)?;
        transaction.commit()?;
        Ok(metadata)
    }

    pub fn pending_outbox(&self, limit: usize) -> Result<Vec<OutboxItem>, StorageError> {
        let now = unix_millis()?;
        let rows = {
            let connection = self.lock_connection()?;
            let mut statement = connection.prepare(
                "SELECT o.outbox_id, o.message_id, o.envelope_path_or_blob,
                        o.attempt_count, r.revision_id, r.slot_name,
                        r.origin_device_id, r.origin_sequence, r.hlc_physical,
                        r.hlc_logical, r.content_hash, r.content_size,
                        r.content_type, r.created_at, r.expires_at, r.is_deleted,
                        r.is_local_only, r.source_adapter, r.parent_revision_id
                 FROM outbox o
                 JOIN revisions r ON r.revision_id = o.revision_id
                 WHERE o.acknowledged_at IS NULL
                   AND (o.next_attempt_at IS NULL OR o.next_attempt_at <= ?1)
                 ORDER BY r.origin_sequence, o.outbox_id
                 LIMIT ?2",
            )?;
            let mapped = statement.query_map(
                params![now, i64::try_from(limit).unwrap_or(i64::MAX)],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, i64>(3)? as u32,
                        revision_from_row_offset(row, 4)?,
                        row.get::<_, Option<String>>(18)?,
                    ))
                },
            )?;
            mapped.collect::<Result<Vec<_>, _>>()?
        };
        rows.into_iter()
            .map(
                |(outbox_id, message_id, encrypted_envelope, attempt_count, metadata, parent)| {
                    let content = match metadata.content_hash.as_deref() {
                        Some(hash) => Some(self.blobs.read(hash)?),
                        None => None,
                    };
                    Ok(OutboxItem {
                        outbox_id,
                        message_id,
                        revision: StoredRevision {
                            metadata,
                            parent_revision_id: parent,
                            content,
                        },
                        encrypted_envelope,
                        attempt_count,
                    })
                },
            )
            .collect()
    }

    pub fn store_outbox_envelope(
        &self,
        outbox_id: i64,
        envelope: &str,
    ) -> Result<(), StorageError> {
        let connection = self.lock_connection()?;
        connection.execute(
            "UPDATE outbox SET envelope_path_or_blob = COALESCE(envelope_path_or_blob, ?1)
             WHERE outbox_id = ?2 AND acknowledged_at IS NULL",
            params![envelope, outbox_id],
        )?;
        Ok(())
    }

    pub fn acknowledge_outbox(
        &self,
        message_id: &str,
        server_sequence: u64,
    ) -> Result<(), StorageError> {
        let now = unix_millis()?;
        let connection = self.lock_connection()?;
        let updated = connection.execute(
            "UPDATE outbox SET acknowledged_at = ?1, server_sequence = ?2,
                 last_error = NULL WHERE message_id = ?3",
            params![
                now,
                i64_from_u64(server_sequence, "server sequence")?,
                message_id
            ],
        )?;
        if updated != 1 {
            return Err(StorageError::Corrupt(
                "acknowledgement references an unknown outbox message".into(),
            ));
        }
        Ok(())
    }

    pub fn fail_outbox(
        &self,
        message_id: &str,
        safe_error: &str,
        retry_at: i64,
    ) -> Result<(), StorageError> {
        let connection = self.lock_connection()?;
        connection.execute(
            "UPDATE outbox SET attempt_count = attempt_count + 1,
                 last_error = ?1, next_attempt_at = ?2
             WHERE message_id = ?3 AND acknowledged_at IS NULL",
            params![safe_error, retry_at, message_id],
        )?;
        Ok(())
    }

    pub fn record_inbox(&self, event: &InboxEvent) -> Result<bool, StorageError> {
        let connection = self.lock_connection()?;
        let inserted = connection.execute(
            "INSERT INTO inbox (
                 message_id, source_device_id, received_at, processed_at,
                 processing_error, server_sequence, algorithm, nonce,
                 ciphertext, tag, accepted_at, error_category, quarantined
             ) VALUES (?1, ?2, ?3, NULL, NULL, ?4, ?5, ?6, ?7, ?8, ?9, NULL, 0)
             ON CONFLICT(message_id) DO NOTHING",
            params![
                event.message_id,
                event.source_device_id,
                unix_millis()?,
                i64_from_u64(event.server_sequence, "server sequence")?,
                event.algorithm,
                event.nonce,
                event.ciphertext,
                event.tag,
                event.accepted_at,
            ],
        )?;
        if inserted == 0 {
            let matches: bool = connection.query_row(
                "SELECT server_sequence = ?1 AND source_device_id = ?2
                 AND algorithm = ?3 AND nonce = ?4 AND ciphertext = ?5 AND tag = ?6
                 AND accepted_at = ?7 FROM inbox WHERE message_id = ?8",
                params![
                    i64_from_u64(event.server_sequence, "server sequence")?,
                    event.source_device_id,
                    event.algorithm,
                    event.nonce,
                    event.ciphertext,
                    event.tag,
                    event.accepted_at,
                    event.message_id,
                ],
                |row| row.get(0),
            )?;
            if !matches {
                return Err(StorageError::IdentityConflict(event.message_id.clone()));
            }
        }
        Ok(inserted != 0)
    }

    pub fn pending_inbox(&self) -> Result<Vec<InboxEvent>, StorageError> {
        let connection = self.lock_connection()?;
        let mut statement = connection.prepare(
            "SELECT message_id, server_sequence, source_device_id, algorithm,
                    nonce, ciphertext, tag, accepted_at
             FROM inbox WHERE processed_at IS NULL ORDER BY server_sequence",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(InboxEvent {
                message_id: row.get(0)?,
                server_sequence: row.get::<_, i64>(1)? as u64,
                source_device_id: row.get(2)?,
                algorithm: row.get(3)?,
                nonce: row.get(4)?,
                ciphertext: row.get(5)?,
                tag: row.get(6)?,
                accepted_at: row.get(7)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(StorageError::from)
    }

    pub fn quarantine_inbox(&self, message_id: &str, category: &str) -> Result<u64, StorageError> {
        let now = unix_millis()?;
        let mut connection = self.lock_connection()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            "UPDATE inbox SET processed_at = ?1, processing_error = ?2,
                 error_category = ?2, quarantined = 1 WHERE message_id = ?3",
            params![now, category, message_id],
        )?;
        let cursor = advance_cursor(&transaction)?;
        transaction.commit()?;
        Ok(cursor)
    }

    pub fn apply_remote_revision(
        &self,
        message_id: &str,
        mut metadata: RevisionMetadata,
        parent_revision_id: Option<&str>,
        content: Option<&[u8]>,
    ) -> Result<(RemoteApplyOutcome, u64), StorageError> {
        validate_slot(&metadata.slot)?;
        validate_remote_revision(&metadata, content, self.max_content_size)?;
        let blob = match content {
            Some(content) => Some(self.blobs.put(content)?),
            None => None,
        };
        metadata.is_local_only = false;
        metadata.synchronization_state = "received".into();

        let mut connection = self.lock_connection()?;
        let transaction = connection.transaction()?;
        let inbox_pending: bool = transaction
            .query_row(
                "SELECT processed_at IS NULL FROM inbox WHERE message_id = ?1",
                [message_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or_else(|| {
                StorageError::Corrupt("remote revision has no durable inbox row".into())
            })?;
        if !inbox_pending {
            let cursor = parse_metadata_u64(&transaction, "sync_server_cursor")?;
            return Ok((RemoteApplyOutcome::Duplicate, cursor));
        }

        transaction.execute(
            "INSERT INTO slots (
                 slot_name, current_revision_id, sync_policy, history_limit,
                 history_max_age_seconds, created_at, updated_at
             ) VALUES (?1, NULL, 'sync', 10, 86400, ?2, ?2)
             ON CONFLICT(slot_name) DO NOTHING",
            params![metadata.slot, metadata.created_at],
        )?;

        let existing = transaction
            .query_row(
                "SELECT r.revision_id, r.slot_name, r.origin_device_id,
                        r.origin_sequence, r.hlc_physical, r.hlc_logical,
                        r.content_hash, r.content_size, r.content_type,
                        r.created_at, r.expires_at, r.is_deleted,
                        r.is_local_only, r.source_adapter, r.parent_revision_id
                 FROM revisions r
                 WHERE r.revision_id = ?1 OR
                       (r.origin_device_id = ?2 AND r.origin_sequence = ?3)",
                params![
                    metadata.revision_id,
                    metadata.origin_device_id,
                    i64_from_u64(metadata.origin_sequence, "origin sequence")?,
                ],
                |row| Ok((revision_from_row(row)?, row.get::<_, Option<String>>(14)?)),
            )
            .optional()?;

        let duplicate = if let Some((existing, existing_parent)) = existing {
            if !same_immutable_revision(
                &existing,
                existing_parent.as_deref(),
                &metadata,
                parent_revision_id,
            ) {
                return Err(StorageError::IdentityConflict(metadata.revision_id.clone()));
            }
            true
        } else {
            transaction.execute(
                "INSERT INTO revisions (
                     revision_id, slot_name, origin_device_id, origin_sequence,
                     hlc_physical, hlc_logical, content_hash, content_size,
                     content_type, blob_path, created_at, received_at, expires_at,
                     is_deleted, is_local_only, no_history, source_adapter,
                     parent_revision_id
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?7, ?10, ?11,
                           ?12, ?13, 0, 0, ?14, ?15)",
                params![
                    metadata.revision_id,
                    metadata.slot,
                    metadata.origin_device_id,
                    i64_from_u64(metadata.origin_sequence, "origin sequence")?,
                    metadata.hlc_physical,
                    metadata.hlc_logical,
                    metadata.content_hash,
                    i64_from_u64(metadata.content_size, "content size")?,
                    metadata.content_type,
                    metadata.created_at,
                    unix_millis()?,
                    metadata.expires_at,
                    metadata.is_deleted,
                    metadata.source_adapter,
                    parent_revision_id,
                ],
            )?;
            false
        };

        let current = current_head(&transaction, &metadata.slot)?;
        let wins = current
            .as_ref()
            .is_none_or(|head| revision_order_key(&metadata) > revision_order_key(head));
        if wins {
            transaction.execute(
                "UPDATE slots SET current_revision_id = ?1, updated_at = ?2 WHERE slot_name = ?3",
                params![metadata.revision_id, unix_millis()?, metadata.slot],
            )?;
        }
        advance_hlc_for_receive(&transaction, metadata.hlc_physical, metadata.hlc_logical)?;
        transaction.execute(
            "UPDATE inbox SET processed_at = ?1, processing_error = NULL,
                 error_category = NULL WHERE message_id = ?2",
            params![unix_millis()?, message_id],
        )?;
        let cursor = advance_cursor(&transaction)?;
        transaction.commit()?;

        // A failed transaction can leave a newly written blob unreferenced; startup GC
        // handles it. Never remove it here because another revision may already share it.
        drop(blob);
        let outcome = if duplicate {
            RemoteApplyOutcome::Duplicate
        } else if wins {
            RemoteApplyOutcome::AppliedWinner
        } else {
            RemoteApplyOutcome::AppliedHistory
        };
        Ok((outcome, cursor))
    }

    pub fn sync_status(&self) -> Result<SyncStorageStatus, StorageError> {
        let now = unix_millis()?;
        let connection = self.lock_connection()?;
        let (pending_outbox_count, oldest): (i64, Option<i64>) = connection.query_row(
            "SELECT COUNT(*), MIN(created_at) FROM outbox WHERE acknowledged_at IS NULL",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let quarantined_events: i64 = connection.query_row(
            "SELECT COUNT(*) FROM inbox WHERE quarantined = 1",
            [],
            |row| row.get(0),
        )?;
        let last_acknowledged_at =
            connection.query_row("SELECT MAX(acknowledged_at) FROM outbox", [], |row| {
                row.get(0)
            })?;
        Ok(SyncStorageStatus {
            pending_outbox_count: pending_outbox_count as u64,
            oldest_pending_age_millis: oldest.map(|created| now.saturating_sub(created) as u64),
            server_cursor: metadata_value(&connection, "sync_server_cursor")?
                .parse()
                .map_err(|_| StorageError::Corrupt("invalid sync server cursor".into()))?,
            quarantined_events: quarantined_events as u64,
            last_acknowledged_at,
        })
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
    options: &MutationOptions,
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
             ?11, ?12, 0, ?13,
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
            options.local_only,
            options.source_adapter,
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

    if options.enqueue_sync && !options.local_only {
        transaction.execute(
            "INSERT INTO outbox (
                 revision_id, message_id, created_at, next_attempt_at,
                 attempt_count
             ) VALUES (?1, ?2, ?3, NULL, 0)",
            params![revision_id, Uuid::new_v4().to_string(), now],
        )?;
    }

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
        is_local_only: options.local_only,
        source_adapter: options.source_adapter.clone(),
        synchronization_state: if options.enqueue_sync && !options.local_only {
            "pending".into()
        } else {
            "local".into()
        },
    })
}

fn revision_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RevisionMetadata> {
    revision_from_row_offset(row, 0)
}

fn revision_from_row_offset(
    row: &rusqlite::Row<'_>,
    offset: usize,
) -> rusqlite::Result<RevisionMetadata> {
    Ok(RevisionMetadata {
        revision_id: row.get(offset)?,
        slot: row.get(offset + 1)?,
        origin_device_id: row.get(offset + 2)?,
        origin_sequence: row.get::<_, i64>(offset + 3)? as u64,
        hlc_physical: row.get(offset + 4)?,
        hlc_logical: row.get::<_, i64>(offset + 5)? as u32,
        content_hash: row.get(offset + 6)?,
        content_size: row.get::<_, i64>(offset + 7)? as u64,
        content_type: row.get(offset + 8)?,
        created_at: row.get(offset + 9)?,
        expires_at: row.get(offset + 10)?,
        is_deleted: row.get(offset + 11)?,
        is_local_only: row.get(offset + 12)?,
        source_adapter: row.get(offset + 13)?,
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
                 message_id TEXT NOT NULL UNIQUE,
                 destination_device_id TEXT,
                 envelope_path_or_blob TEXT,
                 created_at INTEGER NOT NULL,
                 next_attempt_at INTEGER,
                 attempt_count INTEGER NOT NULL DEFAULT 0,
                 last_error TEXT,
                 server_sequence INTEGER,
                 acknowledged_at INTEGER
             );

             CREATE TABLE inbox (
                 message_id TEXT PRIMARY KEY,
                 source_device_id TEXT NOT NULL,
                 received_at INTEGER NOT NULL,
                 processed_at INTEGER,
                 processing_error TEXT,
                 server_sequence INTEGER NOT NULL UNIQUE,
                 algorithm TEXT NOT NULL,
                 nonce TEXT NOT NULL,
                 ciphertext TEXT NOT NULL,
                 tag TEXT NOT NULL,
                 accepted_at INTEGER NOT NULL,
                 error_category TEXT,
                 quarantined INTEGER NOT NULL DEFAULT 0 CHECK(quarantined IN (0, 1))
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
    if current == 1 {
        let transaction = connection.transaction()?;
        transaction.execute_batch(
            "ALTER TABLE outbox ADD COLUMN message_id TEXT;
             ALTER TABLE outbox ADD COLUMN server_sequence INTEGER;
             UPDATE outbox SET message_id = lower(hex(randomblob(16)))
                 WHERE message_id IS NULL;
             CREATE UNIQUE INDEX outbox_message_id ON outbox(message_id);

             ALTER TABLE inbox ADD COLUMN server_sequence INTEGER;
             ALTER TABLE inbox ADD COLUMN algorithm TEXT;
             ALTER TABLE inbox ADD COLUMN nonce TEXT;
             ALTER TABLE inbox ADD COLUMN ciphertext TEXT;
             ALTER TABLE inbox ADD COLUMN tag TEXT;
             ALTER TABLE inbox ADD COLUMN accepted_at INTEGER;
             ALTER TABLE inbox ADD COLUMN error_category TEXT;
             ALTER TABLE inbox ADD COLUMN quarantined INTEGER NOT NULL DEFAULT 0;
             CREATE UNIQUE INDEX inbox_server_sequence ON inbox(server_sequence)
                 WHERE server_sequence IS NOT NULL;",
        )?;
        transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        transaction.execute(
            "UPDATE metadata SET value = ?1 WHERE key = 'schema_version'",
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
    transaction.execute(
        "INSERT OR IGNORE INTO metadata(key, value) VALUES ('sync_server_cursor', '0')",
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

fn current_head(
    transaction: &Transaction<'_>,
    slot: &str,
) -> Result<Option<RevisionMetadata>, StorageError> {
    transaction
        .query_row(
            "SELECT r.revision_id, r.slot_name, r.origin_device_id,
                    r.origin_sequence, r.hlc_physical, r.hlc_logical,
                    r.content_hash, r.content_size, r.content_type,
                    r.created_at, r.expires_at, r.is_deleted,
                    r.is_local_only, r.source_adapter
             FROM slots s JOIN revisions r ON r.revision_id = s.current_revision_id
             WHERE s.slot_name = ?1",
            [slot],
            revision_from_row,
        )
        .optional()
        .map_err(StorageError::from)
}

fn revision_order_key(metadata: &RevisionMetadata) -> (i64, u32, &str, u64, &str) {
    (
        metadata.hlc_physical,
        metadata.hlc_logical,
        metadata.origin_device_id.as_str(),
        metadata.origin_sequence,
        metadata.revision_id.as_str(),
    )
}

fn same_immutable_revision(
    existing: &RevisionMetadata,
    existing_parent: Option<&str>,
    incoming: &RevisionMetadata,
    incoming_parent: Option<&str>,
) -> bool {
    existing.revision_id == incoming.revision_id
        && !existing.is_local_only
        && existing.slot == incoming.slot
        && existing.origin_device_id == incoming.origin_device_id
        && existing.origin_sequence == incoming.origin_sequence
        && existing.hlc_physical == incoming.hlc_physical
        && existing.hlc_logical == incoming.hlc_logical
        && existing.content_hash == incoming.content_hash
        && existing.content_size == incoming.content_size
        && existing.content_type == incoming.content_type
        && existing.created_at == incoming.created_at
        && existing.expires_at == incoming.expires_at
        && existing.is_deleted == incoming.is_deleted
        && existing.source_adapter == incoming.source_adapter
        && existing_parent == incoming_parent
}

fn validate_remote_revision(
    metadata: &RevisionMetadata,
    content: Option<&[u8]>,
    maximum: u64,
) -> Result<(), StorageError> {
    if metadata.revision_id != format!("{}:{}", metadata.origin_device_id, metadata.origin_sequence)
    {
        return Err(StorageError::Corrupt(
            "invalid remote revision identity".into(),
        ));
    }
    if metadata.content_size > maximum {
        return Err(StorageError::ContentTooLarge {
            actual: metadata.content_size,
            maximum,
        });
    }
    if metadata.is_deleted {
        if content.is_some() || metadata.content_hash.is_some() || metadata.content_size != 0 {
            return Err(StorageError::Corrupt("invalid remote tombstone".into()));
        }
    } else {
        let content =
            content.ok_or_else(|| StorageError::Corrupt("remote content missing".into()))?;
        let hash = metadata
            .content_hash
            .as_deref()
            .ok_or_else(|| StorageError::Corrupt("remote content hash missing".into()))?;
        if content.len() as u64 != metadata.content_size || sha256_hex(content) != hash {
            return Err(StorageError::Corrupt(
                "remote content verification failed".into(),
            ));
        }
    }
    Ok(())
}

fn advance_hlc_for_receive(
    transaction: &Transaction<'_>,
    remote_physical: i64,
    remote_logical: u32,
) -> Result<(), StorageError> {
    let now = unix_millis()?;
    let local_physical = parse_metadata_i64(transaction, "last_hlc_physical")?;
    let local_logical = u32::try_from(parse_metadata_u64(transaction, "last_hlc_logical")?)
        .map_err(|_| StorageError::Corrupt("logical clock overflow".into()))?;
    let physical = now.max(local_physical).max(remote_physical);
    let logical = if physical == local_physical && physical == remote_physical {
        local_logical.max(remote_logical).checked_add(1)
    } else if physical == local_physical {
        local_logical.checked_add(1)
    } else if physical == remote_physical {
        remote_logical.checked_add(1)
    } else {
        Some(0)
    }
    .ok_or_else(|| StorageError::Corrupt("logical clock overflow".into()))?;
    set_metadata(transaction, "last_hlc_physical", &physical.to_string())?;
    set_metadata(transaction, "last_hlc_logical", &logical.to_string())
}

fn advance_cursor(transaction: &Transaction<'_>) -> Result<u64, StorageError> {
    let mut cursor = parse_metadata_u64(transaction, "sync_server_cursor")?;
    loop {
        let next = cursor
            .checked_add(1)
            .ok_or_else(|| StorageError::Corrupt("server cursor overflow".into()))?;
        let processed = transaction
            .query_row(
                "SELECT processed_at IS NOT NULL FROM inbox WHERE server_sequence = ?1",
                [i64_from_u64(next, "server sequence")?],
                |row| row.get::<_, bool>(0),
            )
            .optional()?
            .unwrap_or(false);
        if !processed {
            break;
        }
        cursor = next;
    }
    set_metadata(transaction, "sync_server_cursor", &cursor.to_string())?;
    Ok(cursor)
}

fn i64_from_u64(value: u64, field: &str) -> Result<i64, StorageError> {
    i64::try_from(value).map_err(|_| StorageError::Corrupt(format!("{field} overflow")))
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

pub fn unix_millis() -> Result<i64, StorageError> {
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
    #[error("conflicting immutable data for revision or message identity: {0}")]
    IdentityConflict(String),
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
    fn version_one_database_is_migrated_without_replacement() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("legacy.db");
        let mut connection = Connection::open(path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                 INSERT INTO metadata VALUES ('schema_version', '1');
                 CREATE TABLE outbox (
                     outbox_id INTEGER PRIMARY KEY, revision_id TEXT NOT NULL,
                     destination_device_id TEXT, envelope_path_or_blob TEXT,
                     created_at INTEGER NOT NULL, next_attempt_at INTEGER,
                     attempt_count INTEGER NOT NULL DEFAULT 0, last_error TEXT,
                     acknowledged_at INTEGER
                 );
                 CREATE TABLE inbox (
                     message_id TEXT PRIMARY KEY, source_device_id TEXT NOT NULL,
                     received_at INTEGER NOT NULL, processed_at INTEGER,
                     processing_error TEXT
                 );
                 PRAGMA user_version = 1;",
            )
            .unwrap();
        apply_migrations(&mut connection).unwrap();
        let version: u32 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let outbox_columns: Vec<String> = connection
            .prepare("PRAGMA table_info(outbox)")
            .unwrap()
            .query_map([], |row| row.get(1))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(outbox_columns.contains(&"message_id".into()));
        assert!(outbox_columns.contains(&"server_sequence".into()));
        let inbox_columns: Vec<String> = connection
            .prepare("PRAGMA table_info(inbox)")
            .unwrap()
            .query_map([], |row| row.get(1))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert!(inbox_columns.contains(&"ciphertext".into()));
        assert!(inbox_columns.contains(&"quarantined".into()));
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

    #[test]
    fn revision_and_outbox_are_atomic_and_message_id_survives_restart() {
        let temp = TempDir::new().unwrap();
        let message_id = {
            let storage = storage(&temp);
            let revision = storage
                .copy_with_options(
                    "default",
                    b"queued",
                    None,
                    MutationOptions {
                        source_adapter: "cli".into(),
                        local_only: false,
                        enqueue_sync: true,
                    },
                )
                .unwrap();
            let pending = storage.pending_outbox(10).unwrap();
            assert_eq!(pending.len(), 1);
            assert_eq!(
                pending[0].revision.metadata.revision_id,
                revision.revision_id
            );
            pending[0].message_id.clone()
        };
        let storage = storage(&temp);
        assert_eq!(
            storage.pending_outbox(10).unwrap()[0].message_id,
            message_id
        );
        storage
            .copy_with_options(
                "private",
                b"never upload",
                None,
                MutationOptions {
                    source_adapter: "cli".into(),
                    local_only: true,
                    enqueue_sync: true,
                },
            )
            .unwrap();
        assert_eq!(storage.pending_outbox(10).unwrap().len(), 1);
    }

    fn remote_metadata(
        device: &str,
        sequence: u64,
        physical: i64,
        content: &[u8],
    ) -> RevisionMetadata {
        RevisionMetadata {
            revision_id: format!("{device}:{sequence}"),
            slot: "default".into(),
            origin_device_id: device.into(),
            origin_sequence: sequence,
            hlc_physical: physical,
            hlc_logical: 0,
            content_hash: Some(sha256_hex(content)),
            content_size: content.len() as u64,
            content_type: Some("application/octet-stream".into()),
            created_at: physical,
            expires_at: None,
            is_deleted: false,
            is_local_only: false,
            source_adapter: "cli".into(),
            synchronization_state: "received".into(),
        }
    }

    fn inbox(message: &str, sequence: u64, source: &str) -> InboxEvent {
        InboxEvent {
            message_id: message.into(),
            server_sequence: sequence,
            source_device_id: source.into(),
            algorithm: "xchacha20-poly1305".into(),
            nonce: "nonce".into(),
            ciphertext: "ciphertext".into(),
            tag: "tag".into(),
            accepted_at: 1,
        }
    }

    #[test]
    fn remote_conflicts_are_deterministic_and_advance_the_local_clock() {
        let temp = TempDir::new().unwrap();
        let storage = storage(&temp);
        let future = unix_millis().unwrap() + 10_000;
        storage.record_inbox(&inbox("m1", 1, "remote-z")).unwrap();
        let remote = remote_metadata("remote-z", 9, future, b"winner");
        assert_eq!(
            storage
                .apply_remote_revision("m1", remote.clone(), None, Some(b"winner"))
                .unwrap(),
            (RemoteApplyOutcome::AppliedWinner, 1)
        );
        assert_eq!(storage.paste("default").unwrap().1, b"winner");

        let local = storage.copy("other", b"after", None).unwrap();
        assert!(
            (local.hlc_physical, local.hlc_logical) > (remote.hlc_physical, remote.hlc_logical)
        );

        storage.record_inbox(&inbox("m2", 2, "remote-z")).unwrap();
        let mut conflicting = remote;
        conflicting.content_hash = Some(sha256_hex(b"changed"));
        conflicting.content_size = 7;
        assert!(matches!(
            storage.apply_remote_revision("m2", conflicting, None, Some(b"changed")),
            Err(StorageError::IdentityConflict(_))
        ));
    }

    #[test]
    fn cursor_moves_only_across_a_contiguous_processed_prefix() {
        let temp = TempDir::new().unwrap();
        let storage = storage(&temp);
        storage.record_inbox(&inbox("second", 2, "remote")).unwrap();
        storage
            .apply_remote_revision(
                "second",
                remote_metadata("remote", 2, 2, b"two"),
                None,
                Some(b"two"),
            )
            .unwrap();
        assert_eq!(storage.sync_status().unwrap().server_cursor, 0);
        storage.record_inbox(&inbox("first", 1, "remote")).unwrap();
        assert_eq!(
            storage.quarantine_inbox("first", "cryptography").unwrap(),
            2
        );
        let status = storage.sync_status().unwrap();
        assert_eq!(status.server_cursor, 2);
        assert_eq!(status.quarantined_events, 1);
    }
}
