use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::io;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const PROTOCOL_VERSION: u16 = 1;
pub const DEFAULT_SLOT: &str = "default";
pub const DEFAULT_MAX_CONTENT_SIZE: u64 = 10 * 1024 * 1024;
pub const MAX_FRAME_SIZE: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Request {
    pub protocol_version: u16,
    pub request_id: u64,
    pub operation: Operation,
}

impl Request {
    pub fn new(request_id: u64, operation: Operation) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            operation,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "operation", content = "payload", rename_all = "snake_case")]
pub enum Operation {
    Copy {
        slot: String,
        #[serde(with = "serde_bytes")]
        content: Vec<u8>,
        content_type: Option<String>,
        #[serde(default)]
        local: bool,
    },
    Paste {
        slot: String,
    },
    List,
    Clear {
        slot: String,
        #[serde(default)]
        local: bool,
    },
    Status,
}

impl Operation {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Copy { .. } => "copy",
            Self::Paste { .. } => "paste",
            Self::List => "list",
            Self::Clear { .. } => "clear",
            Self::Status => "status",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Response {
    pub protocol_version: u16,
    pub request_id: u64,
    #[serde(flatten)]
    pub result: ResponseResult,
}

impl Response {
    pub fn success(request_id: u64, payload: ResponsePayload) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            result: ResponseResult::Success { payload },
        }
    }

    pub fn error(request_id: u64, error: ProtocolError) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            result: ResponseResult::Error { error },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ResponseResult {
    Success { payload: ResponsePayload },
    Error { error: ProtocolError },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum ResponsePayload {
    Stored(RevisionMetadata),
    Value {
        metadata: RevisionMetadata,
        #[serde(with = "serde_bytes")]
        content: Vec<u8>,
    },
    Slots(Vec<RevisionMetadata>),
    Cleared(RevisionMetadata),
    Status(DaemonStatus),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevisionMetadata {
    pub revision_id: String,
    pub slot: String,
    pub origin_device_id: String,
    pub origin_sequence: u64,
    pub hlc_physical: i64,
    pub hlc_logical: u32,
    pub content_hash: Option<String>,
    pub content_size: u64,
    pub content_type: Option<String>,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub is_deleted: bool,
    pub is_local_only: bool,
    pub source_adapter: String,
    pub synchronization_state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonStatus {
    pub daemon_available: bool,
    pub daemon_version: String,
    pub schema_version: u32,
    pub device_id: String,
    pub synchronization_enabled: bool,
    #[serde(default)]
    pub synchronization_configured: bool,
    #[serde(default)]
    pub synchronization_state: String,
    #[serde(default)]
    pub authenticated: bool,
    #[serde(default)]
    pub credential_error: bool,
    #[serde(default)]
    pub pending_outbox_count: u64,
    #[serde(default)]
    pub oldest_pending_age_millis: Option<u64>,
    #[serde(default)]
    pub last_successful_connection: Option<i64>,
    #[serde(default)]
    pub last_acknowledgement: Option<i64>,
    #[serde(default)]
    pub processed_server_cursor: u64,
    #[serde(default)]
    pub last_sync_error_category: Option<String>,
    #[serde(default)]
    pub quarantined_event_count: u64,
    pub plasma_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Error)]
#[error("{code:?}: {message}")]
pub struct ProtocolError {
    pub code: ErrorCode,
    pub message: String,
    pub retryable: bool,
    pub operation: Option<String>,
    pub category: Option<String>,
}

impl ProtocolError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            retryable: false,
            operation: None,
            category: None,
        }
    }

    pub fn for_operation(mut self, operation: impl Into<String>) -> Self {
        self.operation = Some(operation.into());
        self
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    Generic,
    InvalidRequest,
    DaemonUnavailable,
    SlotNotFound,
    RevisionNotFound,
    InvalidSlotName,
    ContentTooLarge,
    StorageFailure,
    PermissionDenied,
    SynchronizationFailure,
    AuthenticationFailed,
    OperationTimedOut,
    UnsupportedOperation,
    Conflict,
    ProtocolMismatch,
    InvalidConfiguration,
}

impl ErrorCode {
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Generic => 1,
            Self::InvalidRequest | Self::InvalidSlotName | Self::InvalidConfiguration => 2,
            Self::DaemonUnavailable => 3,
            Self::SlotNotFound | Self::RevisionNotFound => 4,
            Self::PermissionDenied => 5,
            Self::ContentTooLarge => 6,
            Self::StorageFailure => 7,
            Self::SynchronizationFailure => 8,
            Self::AuthenticationFailed => 9,
            Self::OperationTimedOut => 10,
            Self::UnsupportedOperation => 11,
            Self::Conflict => 12,
            Self::ProtocolMismatch => 1,
        }
    }
}

pub fn validate_slot_name(slot: &str) -> Result<(), ProtocolError> {
    let length = slot.len();
    if !(1..=128).contains(&length) {
        return Err(ProtocolError::new(
            ErrorCode::InvalidSlotName,
            "slot name must be between 1 and 128 bytes",
        ));
    }
    if slot.contains('\0') {
        return Err(ProtocolError::new(
            ErrorCode::InvalidSlotName,
            "slot name must not contain NUL",
        ));
    }
    if slot.starts_with("kclip") {
        return Err(ProtocolError::new(
            ErrorCode::InvalidSlotName,
            "slot name uses the reserved kclip prefix",
        ));
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("frame length {actual} exceeds maximum {maximum}")]
    TooLarge { actual: usize, maximum: usize },
    #[error("invalid CBOR frame: {0}")]
    InvalidCbor(#[from] serde_cbor::Error),
}

pub async fn read_frame<R, T>(reader: &mut R) -> Result<T, FrameError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    read_frame_with_limit(reader, MAX_FRAME_SIZE).await
}

pub async fn read_frame_with_limit<R, T>(reader: &mut R, maximum: usize) -> Result<T, FrameError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let frame_length = reader.read_u32().await? as usize;
    if frame_length > maximum {
        return Err(FrameError::TooLarge {
            actual: frame_length,
            maximum,
        });
    }

    let mut frame = vec![0_u8; frame_length];
    reader.read_exact(&mut frame).await?;
    Ok(serde_cbor::from_slice(&frame)?)
}

pub async fn write_frame<W, T>(writer: &mut W, value: &T) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let frame = serde_cbor::to_vec(value)?;
    if frame.len() > MAX_FRAME_SIZE {
        return Err(FrameError::TooLarge {
            actual: frame.len(),
            maximum: MAX_FRAME_SIZE,
        });
    }

    writer.write_u32(frame.len() as u32).await?;
    writer.write_all(&frame).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_validation_enforces_reserved_names_and_byte_limit() {
        assert!(validate_slot_name("default").is_ok());
        assert!(validate_slot_name("Build-Log").is_ok());
        assert!(validate_slot_name("").is_err());
        assert!(validate_slot_name("kclip-internal").is_err());
        assert!(validate_slot_name(&"x".repeat(129)).is_err());
    }

    #[test]
    fn error_codes_match_the_public_cli_contract() {
        assert_eq!(ErrorCode::SlotNotFound.exit_code(), 4);
        assert_eq!(ErrorCode::ContentTooLarge.exit_code(), 6);
        assert_eq!(ErrorCode::StorageFailure.exit_code(), 7);
    }
}
