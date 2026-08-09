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
use tokio::sync::broadcast;
use uuid::Uuid;

pub const SCHEMA_VERSION: u32 = 4;

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
    pub message_id: String,
    pub revision: StoredRevision,
    pub encrypted_envelope: Option<String>,
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
    pub last_retention_floor: Option<u64>,
    pub last_retention_at: Option<i64>,
    pub retention_truncation_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionFloorOutcome {
    Advanced(u64),
    Unchanged(u64),
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
    revision_events: broadcast::Sender<RevisionMetadata>,
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

        let blobs = BlobStore::open(blob_directory)?;
        blobs.recover_temporary_files()?;

        let (revision_events, _) = broadcast::channel(128);
        let storage = Self {
            connection: Mutex::new(connection),
            blobs,
            max_content_size,
            revision_events,
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
        self.notify_revision(&metadata);
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

    /// Returns the current slot head, including tombstones, and its content
    /// when the head is live.
    pub fn slot_head(
        &self,
        slot: &str,
    ) -> Result<(RevisionMetadata, Option<Vec<u8>>), StorageError> {
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
                     WHERE s.slot_name = ?1",
                    [slot],
                    revision_from_row,
                )
                .optional()?
                .ok_or_else(|| StorageError::SlotNotFound(slot.to_owned()))?
        };
        if metadata.is_deleted {
            return Ok((metadata, None));
        }
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
        Ok((metadata, Some(content)))
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
        self.notify_revision(&metadata);
        Ok(metadata)
    }

    pub fn pending_outbox(&self, limit: usize) -> Result<Vec<OutboxItem>, StorageError> {
        let now = unix_millis()?;
        let rows = {
            let connection = self.lock_connection()?;
            let mut statement = connection.prepare(
                "SELECT o.message_id, o.encrypted_envelope,
                        r.revision_id, r.slot_name,
                        r.origin_device_id, r.origin_sequence, r.hlc_physical,
                        r.hlc_logical, r.content_hash, r.content_size,
                        r.content_type, r.created_at, r.expires_at, r.is_deleted,
                        r.is_local_only, r.source_adapter, r.parent_revision_id
                 FROM outbox o
                 JOIN revisions r ON r.revision_id = o.revision_id
                 WHERE o.next_attempt_at IS NULL OR o.next_attempt_at <= ?1
                 ORDER BY r.origin_sequence, o.message_id
                 LIMIT ?2",
            )?;
            let mapped = statement.query_map(
                params![now, i64::try_from(limit).unwrap_or(i64::MAX)],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        revision_from_row_offset(row, 2)?,
                        row.get::<_, Option<String>>(16)?,
                    ))
                },
            )?;
            mapped.collect::<Result<Vec<_>, _>>()?
        };
        rows.into_iter()
            .map(|(message_id, encrypted_envelope, metadata, parent)| {
                let content = match metadata.content_hash.as_deref() {
                    Some(hash) => Some(self.blobs.read(hash)?),
                    None => None,
                };
                Ok(OutboxItem {
                    message_id,
                    revision: StoredRevision {
                        metadata,
                        parent_revision_id: parent,
                        content,
                    },
                    encrypted_envelope,
                })
            })
            .collect()
    }

    pub fn store_outbox_envelope(
        &self,
        message_id: &str,
        envelope: &str,
    ) -> Result<(), StorageError> {
        let connection = self.lock_connection()?;
        let updated = connection.execute(
            "UPDATE outbox SET encrypted_envelope = COALESCE(encrypted_envelope, ?1)
             WHERE message_id = ?2",
            params![envelope, message_id],
        )?;
        if updated != 1 {
            return Err(StorageError::Corrupt(
                "encrypted envelope references an unknown outbox message".into(),
            ));
        }
        Ok(())
    }

    pub fn acknowledge_outbox(&self, message_id: &str) -> Result<(), StorageError> {
        let now = unix_millis()?;
        let mut connection = self.lock_connection()?;
        let transaction = connection.transaction()?;
        let deleted =
            transaction.execute("DELETE FROM outbox WHERE message_id = ?1", [message_id])?;
        if deleted != 1 {
            return Err(StorageError::Corrupt(
                "acknowledgement references an unknown outbox message".into(),
            ));
        }
        transaction.execute(
            "UPDATE local_state SET last_acknowledged_at = ?1 WHERE singleton = 1",
            [now],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn fail_outbox(&self, message_id: &str, retry_at: i64) -> Result<(), StorageError> {
        let connection = self.lock_connection()?;
        connection.execute(
            "UPDATE outbox SET next_attempt_at = ?1 WHERE message_id = ?2",
            params![retry_at, message_id],
        )?;
        Ok(())
    }

    pub fn record_inbox(&self, event: &InboxEvent) -> Result<bool, StorageError> {
        let connection = self.lock_connection()?;
        let inserted = connection.execute(
            "INSERT INTO inbox (
                 message_id, source_device_id, server_sequence, algorithm,
                 nonce, ciphertext, tag, accepted_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(message_id) DO NOTHING",
            params![
                event.message_id,
                event.source_device_id,
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
             FROM inbox ORDER BY server_sequence",
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
        let server_sequence = pending_inbox_sequence(&transaction, message_id)?;
        require_next_sequence(&transaction, server_sequence)?;
        transaction.execute(
            "INSERT INTO quarantined_events (
                 server_sequence, message_id, error_category, quarantined_at
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                i64_from_u64(server_sequence, "server sequence")?,
                message_id,
                category,
                now,
            ],
        )?;
        complete_inbox(&transaction, message_id, server_sequence)?;
        transaction.commit()?;
        Ok(server_sequence)
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
        let server_sequence = pending_inbox_sequence(&transaction, message_id)?;
        require_next_sequence(&transaction, server_sequence)?;

        transaction.execute(
            "INSERT INTO slots (slot_name, current_revision_id) VALUES (?1, NULL)
             ON CONFLICT(slot_name) DO NOTHING",
            [metadata.slot.as_str()],
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
                     content_type, created_at, expires_at, is_deleted,
                     is_local_only, source_adapter, parent_revision_id
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                           ?12, 0, ?13, ?14)",
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
                "UPDATE slots SET current_revision_id = ?1 WHERE slot_name = ?2",
                params![metadata.revision_id, metadata.slot],
            )?;
        }
        advance_hlc_for_receive(&transaction, metadata.hlc_physical, metadata.hlc_logical)?;
        complete_inbox(&transaction, message_id, server_sequence)?;
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
        if outcome == RemoteApplyOutcome::AppliedWinner {
            self.notify_revision(&metadata);
        }
        Ok((outcome, server_sequence))
    }

    pub fn sync_status(&self) -> Result<SyncStorageStatus, StorageError> {
        let now = unix_millis()?;
        let connection = self.lock_connection()?;
        let (pending_outbox_count, oldest): (i64, Option<i64>) =
            connection.query_row("SELECT COUNT(*), MIN(created_at) FROM outbox", [], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?;
        let quarantined_events: i64 =
            connection.query_row("SELECT COUNT(*) FROM quarantined_events", [], |row| {
                row.get(0)
            })?;
        let (
            server_cursor,
            last_acknowledged_at,
            last_retention_floor,
            last_retention_at,
            retention_truncation_count,
        ): (i64, Option<i64>, Option<i64>, Option<i64>, i64) = connection.query_row(
            "SELECT sync_server_cursor, last_acknowledged_at,
                        last_retention_floor, last_retention_at,
                        retention_truncation_count
                 FROM local_state WHERE singleton = 1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?;
        Ok(SyncStorageStatus {
            pending_outbox_count: pending_outbox_count as u64,
            oldest_pending_age_millis: oldest.map(|created| now.saturating_sub(created) as u64),
            server_cursor: server_cursor as u64,
            quarantined_events: quarantined_events as u64,
            last_acknowledged_at,
            last_retention_floor: last_retention_floor.map(|value| value as u64),
            last_retention_at,
            retention_truncation_count: retention_truncation_count as u64,
        })
    }

    /// Atomically accepts a server retention floor without synthesizing inbox data.
    pub fn accept_retention_floor(
        &self,
        earliest_sequence: u64,
        latest_sequence: u64,
    ) -> Result<RetentionFloorOutcome, StorageError> {
        let upper = latest_sequence.checked_add(1).ok_or_else(|| {
            StorageError::InvalidRetentionFloor("latest sequence overflow".into())
        })?;
        if earliest_sequence == 0 || earliest_sequence > upper {
            return Err(StorageError::InvalidRetentionFloor(
                "earliest sequence is outside the advertised range".into(),
            ));
        }
        let target = earliest_sequence - 1;
        let now = unix_millis()?;
        let mut connection = self.lock_connection()?;
        let transaction = connection.transaction()?;
        let (cursor, count): (i64, i64) = transaction.query_row(
            "SELECT sync_server_cursor, retention_truncation_count
             FROM local_state WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let cursor = cursor as u64;
        if target <= cursor {
            transaction.commit()?;
            return Ok(RetentionFloorOutcome::Unchanged(cursor));
        }
        let pending: bool = transaction.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM inbox
                 WHERE server_sequence <= ?1
             )",
            [i64_from_u64(target, "retention target")?],
            |row| row.get(0),
        )?;
        if pending {
            return Err(StorageError::PendingInboxBelowRetentionFloor(target));
        }
        let count = (count as u64)
            .checked_add(1)
            .ok_or_else(|| StorageError::Corrupt("retention truncation count overflow".into()))?;
        transaction.execute(
            "UPDATE local_state
             SET sync_server_cursor = ?1, last_retention_floor = ?2,
                 last_retention_at = ?3, retention_truncation_count = ?4
             WHERE singleton = 1",
            params![
                i64_from_u64(target, "retention target")?,
                i64_from_u64(earliest_sequence, "earliest sequence")?,
                now,
                i64_from_u64(count, "retention truncation count")?,
            ],
        )?;
        transaction.commit()?;
        Ok(RetentionFloorOutcome::Advanced(target))
    }

    pub fn device_id(&self) -> Result<String, StorageError> {
        let connection = self.lock_connection()?;
        connection
            .query_row(
                "SELECT device_id FROM local_state WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(StorageError::from)
    }

    pub fn schema_version(&self) -> u32 {
        SCHEMA_VERSION
    }

    pub fn blob_directory(&self) -> &Path {
        self.blobs.directory()
    }

    pub fn subscribe_revisions(&self) -> broadcast::Receiver<RevisionMetadata> {
        self.revision_events.subscribe()
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

    fn notify_revision(&self, metadata: &RevisionMetadata) {
        let _ = self.revision_events.send(metadata.clone());
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
        "INSERT INTO slots (slot_name, current_revision_id) VALUES (?1, NULL)
         ON CONFLICT(slot_name) DO NOTHING",
        [slot],
    )?;

    let (device_id, sequence, last_physical, last_logical): (String, i64, i64, i64) = transaction
        .query_row(
        "SELECT device_id, next_origin_sequence, last_hlc_physical,
                last_hlc_logical
         FROM local_state WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    let sequence = sequence as u64;
    let last_logical = last_logical as u64;
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
             content_type, created_at, expires_at, is_deleted, is_local_only,
             source_adapter, parent_revision_id
         ) VALUES (
             ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, NULL, ?11, ?12, ?13,
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
        "UPDATE slots SET current_revision_id = ?1 WHERE slot_name = ?2",
        params![revision_id, slot],
    )?;
    let next_sequence = sequence
        .checked_add(1)
        .ok_or_else(|| StorageError::Corrupt("origin sequence overflow".into()))?;
    transaction.execute(
        "UPDATE local_state
         SET next_origin_sequence = ?1, last_hlc_physical = ?2,
             last_hlc_logical = ?3
         WHERE singleton = 1",
        params![
            i64_from_u64(next_sequence, "origin sequence")?,
            hlc_physical,
            hlc_logical,
        ],
    )?;

    if options.enqueue_sync && !options.local_only {
        transaction.execute(
            "INSERT INTO outbox (
                 message_id, revision_id, encrypted_envelope, created_at,
                 next_attempt_at
             ) VALUES (?1, ?2, NULL, ?3, NULL)",
            params![Uuid::new_v4().to_string(), revision_id, now],
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
    if current != 0 && current != SCHEMA_VERSION {
        return Err(StorageError::UnsupportedSchema(current));
    }
    if current == 0 {
        let transaction = connection.transaction()?;
        transaction.execute_batch(
            "CREATE TABLE local_state (
                 singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                 device_id TEXT NOT NULL,
                 next_origin_sequence INTEGER NOT NULL CHECK(next_origin_sequence >= 1),
                 last_hlc_physical INTEGER NOT NULL,
                 last_hlc_logical INTEGER NOT NULL CHECK(last_hlc_logical >= 0),
                 sync_server_cursor INTEGER NOT NULL CHECK(sync_server_cursor >= 0),
                 last_retention_floor INTEGER CHECK(last_retention_floor >= 1),
                 last_retention_at INTEGER,
                 retention_truncation_count INTEGER NOT NULL
                     CHECK(retention_truncation_count >= 0),
                 last_acknowledged_at INTEGER
             );

             CREATE TABLE slots (
                 slot_name TEXT PRIMARY KEY,
                 current_revision_id TEXT
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
                 created_at INTEGER NOT NULL,
                 expires_at INTEGER,
                 is_deleted INTEGER NOT NULL CHECK(is_deleted IN (0, 1)),
                 is_local_only INTEGER NOT NULL CHECK(is_local_only IN (0, 1)),
                 source_adapter TEXT NOT NULL,
                 parent_revision_id TEXT REFERENCES revisions(revision_id),
                 UNIQUE(origin_device_id, origin_sequence)
             );

             CREATE INDEX revisions_content_hash
                 ON revisions(content_hash) WHERE content_hash IS NOT NULL;

             CREATE TABLE outbox (
                 message_id TEXT PRIMARY KEY,
                 revision_id TEXT NOT NULL UNIQUE REFERENCES revisions(revision_id),
                 encrypted_envelope TEXT,
                 created_at INTEGER NOT NULL,
                 next_attempt_at INTEGER
             );

             CREATE TABLE inbox (
                 message_id TEXT PRIMARY KEY,
                 source_device_id TEXT NOT NULL,
                 server_sequence INTEGER NOT NULL UNIQUE,
                 algorithm TEXT NOT NULL,
                 nonce TEXT NOT NULL,
                 ciphertext TEXT NOT NULL,
                 tag TEXT NOT NULL,
                 accepted_at INTEGER NOT NULL
             );

             CREATE TABLE quarantined_events (
                 server_sequence INTEGER PRIMARY KEY,
                 message_id TEXT NOT NULL,
                 error_category TEXT NOT NULL,
                 quarantined_at INTEGER NOT NULL
             );",
        )?;
        transaction.execute(
            "INSERT INTO local_state (
                 singleton, device_id, next_origin_sequence, last_hlc_physical,
                 last_hlc_logical, sync_server_cursor, last_retention_floor,
                 last_retention_at, retention_truncation_count,
                 last_acknowledged_at
             ) VALUES (1, ?1, 1, 0, 0, 0, NULL, NULL, 0, NULL)",
            [format!("device-{}", Uuid::new_v4().simple())],
        )?;
        transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        transaction.commit()?;
    }
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
    let (local_physical, local_logical): (i64, i64) = transaction.query_row(
        "SELECT last_hlc_physical, last_hlc_logical
         FROM local_state WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let local_logical = u32::try_from(local_logical)
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
    transaction.execute(
        "UPDATE local_state SET last_hlc_physical = ?1, last_hlc_logical = ?2
         WHERE singleton = 1",
        params![physical, logical],
    )?;
    Ok(())
}

fn pending_inbox_sequence(
    transaction: &Transaction<'_>,
    message_id: &str,
) -> Result<u64, StorageError> {
    transaction
        .query_row(
            "SELECT server_sequence FROM inbox WHERE message_id = ?1",
            [message_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .map(|value| value as u64)
        .ok_or_else(|| StorageError::Corrupt("remote event has no durable inbox row".into()))
}

fn require_next_sequence(
    transaction: &Transaction<'_>,
    server_sequence: u64,
) -> Result<(), StorageError> {
    let cursor: i64 = transaction.query_row(
        "SELECT sync_server_cursor FROM local_state WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    let expected = (cursor as u64)
        .checked_add(1)
        .ok_or_else(|| StorageError::Corrupt("server cursor overflow".into()))?;
    if server_sequence != expected {
        return Err(StorageError::Corrupt(
            "pending inbox event is not contiguous with the server cursor".into(),
        ));
    }
    Ok(())
}

fn complete_inbox(
    transaction: &Transaction<'_>,
    message_id: &str,
    server_sequence: u64,
) -> Result<(), StorageError> {
    let deleted = transaction.execute("DELETE FROM inbox WHERE message_id = ?1", [message_id])?;
    if deleted != 1 {
        return Err(StorageError::Corrupt(
            "completed event disappeared from the inbox".into(),
        ));
    }
    transaction.execute(
        "UPDATE local_state SET sync_server_cursor = ?1 WHERE singleton = 1",
        [i64_from_u64(server_sequence, "server sequence")?],
    )?;
    Ok(())
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
    #[error("database schema version {0} is not supported by this clean-break release")]
    UnsupportedSchema(u32),
    #[error("storage metadata is inconsistent: {0}")]
    Corrupt(String),
    #[error("conflicting immutable data for revision or message identity: {0}")]
    IdentityConflict(String),
    #[error("invalid retention floor: {0}")]
    InvalidRetentionFloor(String),
    #[error("pending inbox data exists at or below retention target {0}")]
    PendingInboxBelowRetentionFloor(u64),
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
        let tables: HashSet<String> = connection
            .prepare(
                "SELECT name FROM sqlite_master
                 WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            )
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            tables,
            HashSet::from([
                "local_state".into(),
                "slots".into(),
                "revisions".into(),
                "outbox".into(),
                "inbox".into(),
                "quarantined_events".into(),
            ])
        );
    }

    #[test]
    fn pre_clean_break_databases_are_rejected() {
        for version in [1_u32, 2, 3] {
            let mut connection = Connection::open_in_memory().unwrap();
            connection
                .pragma_update(None, "user_version", version)
                .unwrap();
            assert!(matches!(
                apply_migrations(&mut connection),
                Err(StorageError::UnsupportedSchema(found)) if found == version
            ));
            let unchanged: u32 = connection
                .pragma_query_value(None, "user_version", |row| row.get(0))
                .unwrap();
            assert_eq!(unchanged, version);
        }
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
        let (head, content) = storage.slot_head("one").unwrap();
        assert!(head.is_deleted);
        assert!(content.is_none());
    }

    #[test]
    fn revision_notifications_are_post_commit_and_only_include_winning_heads() {
        let temp = TempDir::new().unwrap();
        let storage = storage(&temp);
        let mut revisions = storage.subscribe_revisions();

        let local = storage.copy("default", b"local", None).unwrap();
        assert_eq!(revisions.try_recv().unwrap().revision_id, local.revision_id);

        storage.record_inbox(&inbox("loser", 1, "remote")).unwrap();
        let loser = remote_metadata("remote", 1, 1, b"old");
        assert_eq!(
            storage
                .apply_remote_revision("loser", loser, None, Some(b"old"))
                .unwrap()
                .0,
            RemoteApplyOutcome::AppliedHistory
        );
        assert!(matches!(
            revisions.try_recv(),
            Err(broadcast::error::TryRecvError::Empty)
        ));

        storage.record_inbox(&inbox("winner", 2, "remote")).unwrap();
        let winner = remote_metadata("remote", 2, unix_millis().unwrap() + 10_000, b"new");
        assert_eq!(
            storage
                .apply_remote_revision("winner", winner.clone(), None, Some(b"new"))
                .unwrap()
                .0,
            RemoteApplyOutcome::AppliedWinner
        );
        assert_eq!(
            revisions.try_recv().unwrap().revision_id,
            winner.revision_id
        );
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

    #[test]
    fn acknowledgement_deletes_the_transient_outbox_row() {
        let temp = TempDir::new().unwrap();
        let storage = storage(&temp);
        storage
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
        let message_id = storage.pending_outbox(1).unwrap()[0].message_id.clone();
        storage.acknowledge_outbox(&message_id).unwrap();
        assert!(storage.pending_outbox(1).unwrap().is_empty());
        assert!(
            storage
                .sync_status()
                .unwrap()
                .last_acknowledged_at
                .is_some()
        );
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
    fn completed_inbox_rows_are_removed_as_the_cursor_advances() {
        let temp = TempDir::new().unwrap();
        let storage = storage(&temp);
        storage.record_inbox(&inbox("first", 1, "remote")).unwrap();
        storage
            .apply_remote_revision(
                "first",
                remote_metadata("remote", 1, 1, b"one"),
                None,
                Some(b"one"),
            )
            .unwrap();
        assert_eq!(storage.sync_status().unwrap().server_cursor, 1);
        assert!(storage.pending_inbox().unwrap().is_empty());
        storage.record_inbox(&inbox("second", 2, "remote")).unwrap();
        assert_eq!(
            storage.quarantine_inbox("second", "cryptography").unwrap(),
            2
        );
        let status = storage.sync_status().unwrap();
        assert_eq!(status.server_cursor, 2);
        assert_eq!(status.quarantined_events, 1);
        assert!(storage.pending_inbox().unwrap().is_empty());
    }

    #[test]
    fn retention_floor_advances_atomically_without_synthetic_data_and_survives_restart() {
        let temp = TempDir::new().unwrap();
        {
            let storage = storage(&temp);
            let local = storage.copy("default", b"unchanged", None).unwrap();
            let mut revisions = storage.subscribe_revisions();
            assert_eq!(
                storage.accept_retention_floor(50, 57).unwrap(),
                RetentionFloorOutcome::Advanced(49)
            );
            assert_eq!(
                storage.slot_head("default").unwrap().0.revision_id,
                local.revision_id
            );
            assert!(storage.pending_inbox().unwrap().is_empty());
            assert!(matches!(
                revisions.try_recv(),
                Err(broadcast::error::TryRecvError::Empty)
            ));
            let status = storage.sync_status().unwrap();
            assert_eq!(status.server_cursor, 49);
            assert_eq!(status.last_retention_floor, Some(50));
            assert!(status.last_retention_at.is_some());
            assert_eq!(status.retention_truncation_count, 1);
            assert_eq!(
                storage.accept_retention_floor(50, 57).unwrap(),
                RetentionFloorOutcome::Unchanged(49)
            );
            assert_eq!(
                storage.accept_retention_floor(40, 57).unwrap(),
                RetentionFloorOutcome::Unchanged(49)
            );
            assert_eq!(storage.sync_status().unwrap().retention_truncation_count, 1);
        }
        let reopened = storage(&temp);
        let status = reopened.sync_status().unwrap();
        assert_eq!(status.server_cursor, 49);
        assert_eq!(status.last_retention_floor, Some(50));
        assert_eq!(status.retention_truncation_count, 1);
    }

    #[test]
    fn retention_floor_refuses_unprocessed_inbox_and_invalid_ranges() {
        let temp = TempDir::new().unwrap();
        let storage = storage(&temp);
        storage
            .record_inbox(&inbox("pending", 2, "remote"))
            .unwrap();
        assert!(matches!(
            storage.accept_retention_floor(3, 4),
            Err(StorageError::PendingInboxBelowRetentionFloor(2))
        ));
        assert_eq!(storage.sync_status().unwrap().server_cursor, 0);
        assert!(matches!(
            storage.accept_retention_floor(0, 4),
            Err(StorageError::InvalidRetentionFloor(_))
        ));
        assert!(matches!(
            storage.accept_retention_floor(6, 4),
            Err(StorageError::InvalidRetentionFloor(_))
        ));
    }
}
