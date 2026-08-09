use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use futures_util::{SinkExt, StreamExt};
use kclip_config::ResolvedSyncConfig;
use kclip_crypto::{
    EncryptedEnvelope, RevisionV1, SyncEnvelopeV1, atomic_write_secret, decrypt, encrypt,
    read_sync_key,
};
use kclip_protocol::{PROTOCOL_VERSION, RevisionMetadata};
use kclip_storage::{
    InboxEvent, OutboxItem, RemoteApplyOutcome, Storage, StorageError, unix_millis,
};
use serde::{Deserialize, Serialize};
use snow::{Builder, params::NoiseParams};
use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use tokio::sync::{Notify, RwLock, watch};
use tokio_tungstenite::{
    connect_async_with_config,
    tungstenite::{
        Message,
        client::IntoClientRequest,
        http::{HeaderValue, header::AUTHORIZATION},
        protocol::WebSocketConfig,
    },
};
use tracing::{debug, info, warn};

const MAX_JSON_OVERHEAD: usize = 1024 * 1024;
const PAIRING_CODE_PREFIX: &str = "kclip-pair-v1";
const NOISE_PROTOCOL_NAME: &str = "Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s";
const NOISE_TRANSPORT_NAME: &str = "noise-psk-v1";
const NOISE_MAX_CIPHERTEXT_BYTES: usize = 65_535;
const NOISE_TAG_BYTES: usize = 16;
const CHUNK_HEADER_BYTES: usize = 1;
const MAX_CHUNK_DATA_BYTES: usize =
    NOISE_MAX_CIPHERTEXT_BYTES - NOISE_TAG_BYTES - CHUNK_HEADER_BYTES;
const CHUNK_CONTINUES: u8 = 0;
const CHUNK_FINAL: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    Hello {
        protocol_version: u16,
        device_id: String,
        resume_after: u64,
    },
    Push {
        protocol_version: u16,
        message_id: String,
        algorithm: String,
        nonce: String,
        ciphertext: String,
        tag: String,
    },
    Checkpoint {
        server_sequence: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    Ready {
        protocol_version: u16,
        connection_id: String,
        latest_sequence: u64,
        replay_from: u64,
    },
    PushAck {
        message_id: String,
        server_sequence: u64,
        duplicate: bool,
    },
    Event {
        server_sequence: u64,
        message_id: String,
        sender_device_id: String,
        algorithm: String,
        nonce: String,
        ciphertext: String,
        tag: String,
        accepted_at: i64,
    },
    Error {
        code: String,
        message: String,
        retryable: bool,
        message_id: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenFile {
    pub access_token: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PairingCredential {
    pub version: u8,
    pub pairing_id: String,
    pub pairing_secret: String,
}

enum Authentication {
    Noise {
        credential: PairingCredential,
        psk: [u8; 32],
    },
    LegacyBearer(TokenFile),
}

enum WireSecurity {
    Noise(Box<snow::TransportState>),
    Plain,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeStatus {
    pub state: String,
    pub authenticated: bool,
    pub credential_error: bool,
    pub last_successful_connection: Option<i64>,
    pub last_error_category: Option<String>,
}

#[derive(Clone)]
pub struct WorkerControl {
    status: Arc<RwLock<RuntimeStatus>>,
    wake: Arc<Notify>,
    stop: watch::Sender<bool>,
}

impl WorkerControl {
    pub async fn status(&self) -> RuntimeStatus {
        self.status.read().await.clone()
    }

    pub fn wake(&self) {
        self.wake.notify_one();
    }

    pub fn shutdown(&self) {
        let _ = self.stop.send(true);
    }

    pub async fn wait_stopped(&self, timeout: Duration) -> bool {
        tokio::time::timeout(timeout, async {
            loop {
                if self.status.read().await.state == "stopped" {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .is_ok()
    }
}

pub fn start_worker(
    storage: Arc<Storage>,
    configuration: ResolvedSyncConfig,
    max_content_size: u64,
) -> WorkerControl {
    let status = Arc::new(RwLock::new(RuntimeStatus {
        state: "starting".into(),
        ..RuntimeStatus::default()
    }));
    let wake = Arc::new(Notify::new());
    let (stop, stop_receiver) = watch::channel(false);
    let control = WorkerControl {
        status: status.clone(),
        wake: wake.clone(),
        stop,
    };
    tokio::spawn(async move {
        worker_loop(
            storage,
            configuration,
            max_content_size,
            status,
            wake,
            stop_receiver,
        )
        .await;
    });
    control
}

async fn worker_loop(
    storage: Arc<Storage>,
    configuration: ResolvedSyncConfig,
    max_content_size: u64,
    status: Arc<RwLock<RuntimeStatus>>,
    wake: Arc<Notify>,
    mut stop: watch::Receiver<bool>,
) {
    let mut delay = configuration.reconnect_min_delay;
    loop {
        if *stop.borrow() {
            break;
        }
        set_state(&status, "connecting", false, false, None).await;
        let mut connection_stop = stop.clone();
        let attempt = tokio::select! {
            result = connect_once(
                &storage,
                &configuration,
                max_content_size,
                &status,
                &wake,
                &mut connection_stop,
            ) => result,
            _ = stop.changed() => break,
        };
        if *stop.borrow() {
            break;
        }
        match attempt {
            Ok(()) => {
                delay = configuration.reconnect_min_delay;
            }
            Err(error) => {
                let category = error.category().to_owned();
                let credential =
                    matches!(error, SyncError::Credentials(_) | SyncError::Authentication);
                warn!(category, "synchronization attempt failed");
                set_state(&status, "disconnected", false, credential, Some(category)).await;
                let wait = jittered(delay, configuration.reconnect_max_delay);
                delay = delay
                    .checked_mul(2)
                    .unwrap_or(configuration.reconnect_max_delay)
                    .min(configuration.reconnect_max_delay);
                tokio::select! {
                    _ = tokio::time::sleep(wait) => {},
                    _ = wake.notified() => {},
                    _ = stop.changed() => {},
                }
            }
        }
    }
    set_state(&status, "stopped", false, false, None).await;
}

async fn connect_once(
    storage: &Arc<Storage>,
    configuration: &ResolvedSyncConfig,
    max_content_size: u64,
    status: &Arc<RwLock<RuntimeStatus>>,
    wake: &Arc<Notify>,
    stop: &mut watch::Receiver<bool>,
) -> Result<(), SyncError> {
    let authentication = read_authentication(configuration)?;
    let noise_authenticated = matches!(authentication, Authentication::Noise { .. });
    if !configuration.relay_url.starts_with("wss://")
        && !(noise_authenticated && configuration.relay_url.starts_with("ws://"))
        && !(configuration.allow_insecure_transport && configuration.relay_url.starts_with("ws://"))
    {
        return Err(SyncError::Protocol(
            "relay transport is not permitted by synchronization configuration",
        ));
    }
    let key = read_sync_key(&configuration.sync_key_path)
        .map_err(|error| SyncError::Credentials(error.to_string()))?;

    recover_inbox(storage, &key, max_content_size, status).await?;

    let mut request = configuration.relay_url.as_str().into_client_request()?;
    match &authentication {
        Authentication::Noise { credential, .. } => {
            request.headers_mut().insert(
                "x-kclip-transport",
                HeaderValue::from_static(NOISE_TRANSPORT_NAME),
            );
            request.headers_mut().insert(
                "x-kclip-pairing-id",
                HeaderValue::from_str(&credential.pairing_id)?,
            );
        }
        Authentication::LegacyBearer(token) => {
            let mut authorization =
                HeaderValue::from_str(&format!("Bearer {}", token.access_token)).map_err(|_| {
                    SyncError::Credentials("access token cannot be used in a header".into())
                })?;
            authorization.set_sensitive(true);
            request.headers_mut().insert(AUTHORIZATION, authorization);
        }
    }
    let maximum_frame = usize::try_from(max_content_size)
        .unwrap_or(usize::MAX)
        .saturating_mul(2)
        .saturating_add(MAX_JSON_OVERHEAD);
    let websocket_configuration = WebSocketConfig::default()
        .max_message_size(Some(maximum_frame))
        .max_frame_size(Some(maximum_frame));
    let (mut websocket, _) =
        connect_async_with_config(request, Some(websocket_configuration), false)
            .await
            .map_err(|error| match error {
                tokio_tungstenite::tungstenite::Error::Http(response)
                    if matches!(response.status().as_u16(), 401 | 403) =>
                {
                    SyncError::Authentication
                }
                other => SyncError::WebSocket(other),
            })?;

    let mut wire_security = match authentication {
        Authentication::Noise { psk, .. } => WireSecurity::Noise(Box::new(
            noise_client_handshake(&mut websocket, &psk).await?,
        )),
        Authentication::LegacyBearer(_) => WireSecurity::Plain,
    };

    let sync_status = storage.sync_status()?;
    let resume_after = sync_status.server_cursor;
    send_json(
        &mut websocket,
        &mut wire_security,
        &ClientMessage::Hello {
            protocol_version: PROTOCOL_VERSION,
            device_id: storage.device_id()?,
            resume_after,
        },
    )
    .await?;
    let ready = receive_json(&mut websocket, &mut wire_security, max_content_size).await?;
    match ready {
        ServerMessage::Ready {
            protocol_version,
            latest_sequence,
            replay_from,
            ..
        } if protocol_version == PROTOCOL_VERSION
            && replay_from == resume_after.saturating_add(1)
            && latest_sequence >= resume_after => {}
        ServerMessage::Error { code, .. } if code == "authentication_failed" => {
            return Err(SyncError::Authentication);
        }
        _ => {
            return Err(SyncError::Protocol(
                "server did not send a valid ready message",
            ));
        }
    }
    {
        let mut current = status.write().await;
        current.state = "connected".into();
        current.authenticated = true;
        current.credential_error = false;
        current.last_successful_connection = Some(unix_millis()?);
        current.last_error_category = None;
    }
    info!("synchronization connection established");
    let mut last_ping = tokio::time::Instant::now();

    loop {
        if *stop.borrow() {
            let _ = websocket.close(None).await;
            return Ok(());
        }
        if let Some(item) = storage.pending_outbox(1)?.into_iter().next() {
            let message_id = item.message_id.clone();
            let push = outbox_push(storage, &item, &key)?;
            send_json(&mut websocket, &mut wire_security, &push).await?;
            loop {
                let message = tokio::select! {
                    value = receive_json(&mut websocket, &mut wire_security, max_content_size) => value?,
                    _ = stop.changed() => {
                        let _ = websocket.close(None).await;
                        return Ok(());
                    }
                };
                match handle_server_message(storage, &key, max_content_size, status, message)
                    .await?
                {
                    MessageOutcome::Acknowledged(acknowledged) if acknowledged == message_id => {
                        break;
                    }
                    MessageOutcome::PermanentOutboxError(failed) if failed == message_id => break,
                    MessageOutcome::Event(cursor) => {
                        send_json(
                            &mut websocket,
                            &mut wire_security,
                            &ClientMessage::Checkpoint {
                                server_sequence: cursor,
                            },
                        )
                        .await?;
                    }
                    _ => {}
                }
            }
            continue;
        }

        tokio::select! {
            message = receive_json(&mut websocket, &mut wire_security, max_content_size) => {
                if let MessageOutcome::Event(cursor) =
                    handle_server_message(storage, &key, max_content_size, status, message?).await?
                {
                    send_json(&mut websocket, &mut wire_security, &ClientMessage::Checkpoint { server_sequence: cursor }).await?;
                }
            }
            _ = wake.notified() => {}
            _ = tokio::time::sleep(Duration::from_secs(1)) => {
                if last_ping.elapsed() >= Duration::from_secs(30) {
                    websocket.send(Message::Ping(Vec::new().into())).await?;
                    last_ping = tokio::time::Instant::now();
                }
            }
            _ = stop.changed() => {
                let _ = websocket.close(None).await;
                return Ok(());
            }
        }
    }
}

enum MessageOutcome {
    Event(u64),
    Acknowledged(String),
    PermanentOutboxError(String),
}

async fn handle_server_message(
    storage: &Storage,
    key: &[u8; 32],
    max_content_size: u64,
    status: &Arc<RwLock<RuntimeStatus>>,
    message: ServerMessage,
) -> Result<MessageOutcome, SyncError> {
    match message {
        ServerMessage::PushAck {
            message_id,
            server_sequence,
            ..
        } => {
            if server_sequence == 0 {
                return Err(SyncError::Protocol(
                    "push acknowledgement has an invalid server sequence",
                ));
            }
            storage.acknowledge_outbox(&message_id, server_sequence)?;
            Ok(MessageOutcome::Acknowledged(message_id))
        }
        ServerMessage::Event {
            server_sequence,
            message_id,
            sender_device_id,
            algorithm,
            nonce,
            ciphertext,
            tag,
            accepted_at,
        } => {
            let event = InboxEvent {
                message_id,
                server_sequence,
                source_device_id: sender_device_id,
                algorithm,
                nonce,
                ciphertext,
                tag,
                accepted_at,
            };
            let cursor = process_event(storage, key, max_content_size, &event, status).await?;
            debug!(cursor, "synchronization event durably processed");
            Ok(MessageOutcome::Event(cursor))
        }
        ServerMessage::Error {
            code,
            retryable,
            message_id,
            ..
        } => {
            if code == "authentication_failed" {
                return Err(SyncError::Authentication);
            }
            if let Some(message_id) = message_id {
                let retry_at = if retryable {
                    unix_millis()?.saturating_add(1_000)
                } else {
                    i64::MAX
                };
                storage.fail_outbox(&message_id, &code, retry_at)?;
                if !retryable {
                    status.write().await.last_error_category = Some(code);
                    return Ok(MessageOutcome::PermanentOutboxError(message_id));
                }
            }
            if retryable {
                Err(SyncError::Server(code))
            } else {
                Err(SyncError::Protocol(
                    "server rejected synchronization message",
                ))
            }
        }
        ServerMessage::Ready { .. } => Err(SyncError::Protocol("unexpected ready message")),
    }
}

async fn process_event(
    storage: &Storage,
    key: &[u8; 32],
    max_content_size: u64,
    event: &InboxEvent,
    status: &Arc<RwLock<RuntimeStatus>>,
) -> Result<u64, SyncError> {
    validate_outer_event(event, max_content_size)?;
    storage.record_inbox(event)?;
    match decrypt_and_apply(storage, key, max_content_size, event) {
        Ok((outcome, cursor)) => {
            debug!(?outcome, cursor, "applied synchronization event");
            Ok(cursor)
        }
        Err(error) if error.is_permanent_event_error() => {
            let category = error.category().to_owned();
            let cursor = storage.quarantine_inbox(&event.message_id, &category)?;
            status.write().await.last_error_category = Some(category);
            Ok(cursor)
        }
        Err(error) => Err(error),
    }
}

fn validate_outer_event(event: &InboxEvent, max_content_size: u64) -> Result<(), SyncError> {
    if event.server_sequence == 0
        || event.algorithm != kclip_crypto::ALGORITHM
        || event.accepted_at < 0
        || event.source_device_id.is_empty()
        || event.source_device_id.len() > 128
    {
        return Err(SyncError::Protocol("invalid event routing metadata"));
    }
    let message_id = uuid::Uuid::parse_str(&event.message_id)
        .map_err(|_| SyncError::Protocol("message ID is not a UUID"))?;
    if message_id.to_string() != event.message_id {
        return Err(SyncError::Protocol(
            "message ID is not a canonical lowercase UUID",
        ));
    }
    let maximum_ciphertext = usize::try_from(max_content_size)
        .unwrap_or(usize::MAX)
        .saturating_add(MAX_JSON_OVERHEAD);
    if event.ciphertext.len() > maximum_ciphertext.saturating_mul(4).saturating_add(2) / 3 {
        return Err(SyncError::Protocol("encrypted event exceeds local limit"));
    }
    let nonce = URL_SAFE_NO_PAD
        .decode(&event.nonce)
        .map_err(|_| SyncError::Protocol("invalid nonce encoding"))?;
    let tag = URL_SAFE_NO_PAD
        .decode(&event.tag)
        .map_err(|_| SyncError::Protocol("invalid tag encoding"))?;
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&event.ciphertext)
        .map_err(|_| SyncError::Protocol("invalid ciphertext encoding"))?;
    if nonce.len() != kclip_crypto::NONCE_SIZE
        || tag.len() != kclip_crypto::TAG_SIZE
        || ciphertext.len() > maximum_ciphertext
    {
        return Err(SyncError::Protocol("invalid encrypted event field size"));
    }
    Ok(())
}

fn decrypt_and_apply(
    storage: &Storage,
    key: &[u8; 32],
    max_content_size: u64,
    event: &InboxEvent,
) -> Result<(RemoteApplyOutcome, u64), SyncError> {
    let encrypted = EncryptedEnvelope {
        algorithm: event.algorithm.clone(),
        nonce: event.nonce.clone(),
        ciphertext: event.ciphertext.clone(),
        tag: event.tag.clone(),
    };
    let envelope = decrypt(key, &event.message_id, &encrypted)?;
    envelope.validate(&event.message_id, max_content_size)?;
    if envelope.revision.origin_device_id != event.source_device_id {
        return Err(SyncError::Protocol(
            "encrypted revision origin differs from authenticated sender",
        ));
    }
    let metadata = revision_metadata(&envelope.revision);
    storage
        .apply_remote_revision(
            &event.message_id,
            metadata,
            envelope.revision.parent_revision_id.as_deref(),
            envelope.content.as_ref().map(|content| content.as_slice()),
        )
        .map_err(SyncError::from)
}

async fn recover_inbox(
    storage: &Storage,
    key: &[u8; 32],
    maximum: u64,
    status: &Arc<RwLock<RuntimeStatus>>,
) -> Result<(), SyncError> {
    for event in storage.pending_inbox()? {
        process_event(storage, key, maximum, &event, status).await?;
    }
    Ok(())
}

fn outbox_push(
    storage: &Storage,
    item: &OutboxItem,
    key: &[u8; 32],
) -> Result<ClientMessage, SyncError> {
    let encrypted = if let Some(serialized) = &item.encrypted_envelope {
        serde_json::from_str(serialized)?
    } else {
        let metadata = &item.revision.metadata;
        if metadata.is_local_only {
            return Err(SyncError::Protocol("local-only revision entered outbox"));
        }
        let envelope = SyncEnvelopeV1::new(
            item.message_id.clone(),
            RevisionV1 {
                revision_id: metadata.revision_id.clone(),
                slot: metadata.slot.clone(),
                origin_device_id: metadata.origin_device_id.clone(),
                origin_sequence: metadata.origin_sequence,
                hlc_physical: metadata.hlc_physical,
                hlc_logical: metadata.hlc_logical,
                content_hash: metadata.content_hash.clone(),
                content_size: metadata.content_size,
                content_type: metadata.content_type.clone(),
                created_at: metadata.created_at,
                expires_at: metadata.expires_at,
                is_deleted: metadata.is_deleted,
                source_adapter: metadata.source_adapter.clone(),
                parent_revision_id: item.revision.parent_revision_id.clone(),
            },
            item.revision.content.clone(),
        );
        let encrypted = encrypt(key, &envelope)?;
        storage.store_outbox_envelope(item.outbox_id, &serde_json::to_string(&encrypted)?)?;
        encrypted
    };
    Ok(ClientMessage::Push {
        protocol_version: PROTOCOL_VERSION,
        message_id: item.message_id.clone(),
        algorithm: encrypted.algorithm,
        nonce: encrypted.nonce,
        ciphertext: encrypted.ciphertext,
        tag: encrypted.tag,
    })
}

fn revision_metadata(revision: &RevisionV1) -> RevisionMetadata {
    RevisionMetadata {
        revision_id: revision.revision_id.clone(),
        slot: revision.slot.clone(),
        origin_device_id: revision.origin_device_id.clone(),
        origin_sequence: revision.origin_sequence,
        hlc_physical: revision.hlc_physical,
        hlc_logical: revision.hlc_logical,
        content_hash: revision.content_hash.clone(),
        content_size: revision.content_size,
        content_type: revision.content_type.clone(),
        created_at: revision.created_at,
        expires_at: revision.expires_at,
        is_deleted: revision.is_deleted,
        is_local_only: false,
        source_adapter: revision.source_adapter.clone(),
        synchronization_state: "received".into(),
    }
}

async fn noise_client_handshake<S>(
    socket: &mut S,
    psk: &[u8; 32],
) -> Result<snow::TransportState, SyncError>
where
    S: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
        + futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin,
{
    let parameters: NoiseParams = NOISE_PROTOCOL_NAME
        .parse()
        .map_err(|error: snow::Error| SyncError::Noise(error.to_string()))?;
    let mut handshake = Builder::new(parameters)
        .psk(0, psk)
        .map_err(|error| SyncError::Noise(error.to_string()))?
        .build_initiator()
        .map_err(|error| SyncError::Noise(error.to_string()))?;
    let mut first = [0_u8; 128];
    let first_length = handshake
        .write_message(&[], &mut first)
        .map_err(|error| SyncError::Noise(error.to_string()))?;
    socket
        .send(Message::Binary(first[..first_length].to_vec().into()))
        .await?;

    let response = loop {
        match socket.next().await.ok_or(SyncError::Authentication)?? {
            Message::Binary(value) => break value,
            Message::Ping(payload) => socket.send(Message::Pong(payload)).await?,
            Message::Pong(_) => {}
            Message::Close(_) => return Err(SyncError::Authentication),
            _ => return Err(SyncError::Authentication),
        }
    };
    let mut payload = [0_u8; 128];
    handshake
        .read_message(&response, &mut payload)
        .map_err(|_| SyncError::Authentication)?;
    handshake
        .into_transport_mode()
        .map_err(|error| SyncError::Noise(error.to_string()))
}

async fn send_json<S>(
    socket: &mut S,
    security: &mut WireSecurity,
    message: &ClientMessage,
) -> Result<(), SyncError>
where
    S: futures_util::Sink<Message> + Unpin,
    S::Error: std::error::Error + Send + Sync + 'static,
{
    let serialized = serde_json::to_vec(message)?;
    match security {
        WireSecurity::Plain => socket
            .send(Message::Text(
                String::from_utf8(serialized)
                    .expect("serde_json always emits UTF-8")
                    .into(),
            ))
            .await
            .map_err(|error| SyncError::Transport(error.to_string())),
        WireSecurity::Noise(state) => {
            let chunk_count = serialized.len().div_ceil(MAX_CHUNK_DATA_BYTES).max(1);
            for (index, chunk) in serialized.chunks(MAX_CHUNK_DATA_BYTES).enumerate() {
                let flag = if index + 1 == chunk_count {
                    CHUNK_FINAL
                } else {
                    CHUNK_CONTINUES
                };
                let mut plaintext = Vec::with_capacity(chunk.len() + 1);
                plaintext.push(flag);
                plaintext.extend_from_slice(chunk);
                let mut ciphertext = vec![0_u8; plaintext.len() + NOISE_TAG_BYTES];
                let length = state
                    .write_message(&plaintext, &mut ciphertext)
                    .map_err(|error| SyncError::Noise(error.to_string()))?;
                ciphertext.truncate(length);
                socket
                    .send(Message::Binary(ciphertext.into()))
                    .await
                    .map_err(|error| SyncError::Transport(error.to_string()))?;
            }
            // serde_json messages are non-empty. Keep the framing definition
            // total in case that invariant ever changes.
            if serialized.is_empty() {
                let mut ciphertext = vec![0_u8; 1 + NOISE_TAG_BYTES];
                let length = state
                    .write_message(&[CHUNK_FINAL], &mut ciphertext)
                    .map_err(|error| SyncError::Noise(error.to_string()))?;
                ciphertext.truncate(length);
                socket
                    .send(Message::Binary(ciphertext.into()))
                    .await
                    .map_err(|error| SyncError::Transport(error.to_string()))?;
            }
            Ok(())
        }
    }
}

async fn receive_json<S>(
    socket: &mut S,
    security: &mut WireSecurity,
    max_content_size: u64,
) -> Result<ServerMessage, SyncError>
where
    S: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
        + futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
        + Unpin,
{
    let maximum = usize::try_from(max_content_size)
        .unwrap_or(usize::MAX)
        .saturating_mul(2)
        .saturating_add(MAX_JSON_OVERHEAD);
    let mut assembled = Vec::new();
    loop {
        let message = socket.next().await.ok_or(SyncError::Disconnected)??;
        match message {
            Message::Text(text) if matches!(security, WireSecurity::Plain) => {
                if text.len() > maximum {
                    return Err(SyncError::Protocol("server frame exceeds local limit"));
                }
                return Ok(serde_json::from_str(&text)?);
            }
            Message::Binary(ciphertext) if matches!(security, WireSecurity::Noise(_)) => {
                if ciphertext.is_empty() || ciphertext.len() > NOISE_MAX_CIPHERTEXT_BYTES {
                    return Err(SyncError::Protocol("invalid encrypted transport frame"));
                }
                let WireSecurity::Noise(state) = security else {
                    unreachable!()
                };
                let mut plaintext = vec![0_u8; ciphertext.len()];
                let length = state
                    .read_message(&ciphertext, &mut plaintext)
                    .map_err(|_| SyncError::Authentication)?;
                plaintext.truncate(length);
                let Some((&flag, data)) = plaintext.split_first() else {
                    return Err(SyncError::Protocol("empty encrypted transport chunk"));
                };
                if !matches!(flag, CHUNK_CONTINUES | CHUNK_FINAL) {
                    return Err(SyncError::Protocol("invalid encrypted transport chunk"));
                }
                if assembled.len().saturating_add(data.len()) > maximum {
                    return Err(SyncError::Protocol("server message exceeds local limit"));
                }
                assembled.extend_from_slice(data);
                if flag == CHUNK_FINAL {
                    return Ok(serde_json::from_slice(&assembled)?);
                }
            }
            Message::Ping(payload) => {
                socket.send(Message::Pong(payload)).await?;
                continue;
            }
            Message::Pong(_) => continue,
            Message::Close(_) => return Err(SyncError::Disconnected),
            _ => return Err(SyncError::Protocol("unexpected WebSocket data frame")),
        }
    }
}

async fn set_state(
    status: &RwLock<RuntimeStatus>,
    state: &str,
    authenticated: bool,
    credential_error: bool,
    error: Option<String>,
) {
    let mut current = status.write().await;
    current.state = state.into();
    current.authenticated = authenticated;
    current.credential_error = credential_error;
    current.last_error_category = error;
}

fn jittered(delay: Duration, maximum: Duration) -> Duration {
    let mut random = [0_u8; 8];
    let _ = getrandom::fill(&mut random);
    let fraction = u64::from_le_bytes(random) % 41;
    let percent = 80 + fraction;
    delay.mul_f64(percent as f64 / 100.0).min(maximum)
}

fn read_authentication(configuration: &ResolvedSyncConfig) -> Result<Authentication, SyncError> {
    match fs::symlink_metadata(&configuration.pairing_path) {
        Ok(_) => {
            let credential = read_pairing(&configuration.pairing_path)?;
            let psk = pairing_psk(&credential)?;
            Ok(Authentication::Noise { credential, psk })
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Authentication::LegacyBearer(
            read_token(&configuration.token_path)?,
        )),
        Err(error) => Err(error.into()),
    }
}

fn pairing_psk(credential: &PairingCredential) -> Result<[u8; 32], SyncError> {
    if credential.version != 1
        || credential.pairing_id.is_empty()
        || credential.pairing_id.len() > 36
    {
        return Err(SyncError::Credentials("invalid pairing credential".into()));
    }
    let pairing_id = uuid::Uuid::parse_str(&credential.pairing_id)
        .map_err(|_| SyncError::Credentials("invalid pairing credential".into()))?;
    if pairing_id.to_string() != credential.pairing_id {
        return Err(SyncError::Credentials("invalid pairing credential".into()));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(&credential.pairing_secret)
        .map_err(|_| SyncError::Credentials("invalid pairing credential".into()))?;
    decoded
        .try_into()
        .map_err(|_| SyncError::Credentials("invalid pairing credential".into()))
}

pub fn read_pairing(path: &Path) -> Result<PairingCredential, SyncError> {
    kclip_crypto::validate_secret_file(path)
        .map_err(|error| SyncError::Credentials(error.to_string()))?;
    if fs::metadata(path)?.len() > 4096 {
        return Err(SyncError::Credentials(
            "pairing credential file is too large".into(),
        ));
    }
    let credential: PairingCredential = serde_json::from_slice(&fs::read(path)?)?;
    pairing_psk(&credential)?;
    Ok(credential)
}

pub fn write_pairing_code(path: &Path, code: &str) -> Result<(), SyncError> {
    let parts: Vec<&str> = code.trim().split(':').collect();
    if parts.len() != 3 || parts[0] != PAIRING_CODE_PREFIX {
        return Err(SyncError::Credentials("invalid pairing code".into()));
    }
    let credential = PairingCredential {
        version: 1,
        pairing_id: parts[1].to_owned(),
        pairing_secret: parts[2].to_owned(),
    };
    pairing_psk(&credential).map_err(|_| SyncError::Credentials("invalid pairing code".into()))?;
    let bytes = serde_json::to_vec_pretty(&credential)?;
    atomic_write_secret(path, &bytes).map_err(|error| SyncError::Credentials(error.to_string()))
}

pub fn remove_pairing(path: &Path) -> Result<bool, SyncError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub fn read_token(path: &Path) -> Result<TokenFile, SyncError> {
    kclip_crypto::validate_secret_file(path)
        .map_err(|error| SyncError::Credentials(error.to_string()))?;
    if fs::metadata(path)?.len() > 64 * 1024 {
        return Err(SyncError::Credentials(
            "access token file is too large".into(),
        ));
    }
    let token: TokenFile = serde_json::from_slice(&fs::read(path)?)?;
    if token.access_token.trim().is_empty() || token.access_token.len() > 32 * 1024 {
        return Err(SyncError::Credentials(
            "access token is empty or too large".into(),
        ));
    }
    Ok(token)
}

pub fn write_token(path: &Path, access_token: &str) -> Result<(), SyncError> {
    if access_token.trim().is_empty() || access_token.len() > 32 * 1024 {
        return Err(SyncError::Credentials(
            "access token is empty or too large".into(),
        ));
    }
    let bytes = serde_json::to_vec_pretty(&TokenFile {
        access_token: access_token.into(),
    })?;
    atomic_write_secret(path, &bytes).map_err(|error| SyncError::Credentials(error.to_string()))
}

pub fn remove_token(path: &Path) -> Result<bool, SyncError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

#[derive(Debug, Clone)]
pub struct AuthClient {
    base_url: String,
    token_path: PathBuf,
    client: reqwest::Client,
}

impl AuthClient {
    pub fn from_relay(relay_url: &str, token_path: PathBuf) -> Result<Self, SyncError> {
        let mut base_url = if let Some(rest) = relay_url.strip_prefix("wss://") {
            format!("https://{rest}")
        } else {
            return Err(SyncError::Protocol(
                "password and bearer authentication requires wss://",
            ));
        };
        if let Some(stripped) = base_url.strip_suffix("/sync/v1") {
            base_url = stripped.to_owned();
        }
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            token_path,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()?,
        })
    }

    pub async fn register(
        &self,
        username: &str,
        email: &str,
        password: &str,
    ) -> Result<(), SyncError> {
        #[derive(Serialize)]
        struct Registration<'a> {
            username: &'a str,
            email: &'a str,
            password: &'a str,
        }
        let response = self
            .client
            .post(format!("{}/register", self.base_url))
            .json(&Registration {
                username,
                email,
                password,
            })
            .send()
            .await?;
        self.save_response_token(response).await
    }

    pub async fn login(&self, username: &str, password: &str) -> Result<(), SyncError> {
        let response = self
            .client
            .post(format!("{}/login", self.base_url))
            .form(&[("username", username), ("password", password)])
            .send()
            .await?;
        self.save_response_token(response).await
    }

    pub async fn logout(&self) -> Result<(), SyncError> {
        let token = read_token(&self.token_path)?;
        let response = self
            .client
            .post(format!("{}/logout", self.base_url))
            .bearer_auth(&token.access_token)
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(SyncError::Authentication);
        }
        remove_token(&self.token_path)?;
        Ok(())
    }

    async fn save_response_token(&self, response: reqwest::Response) -> Result<(), SyncError> {
        if !response.status().is_success() {
            return Err(if response.status().as_u16() == 401 {
                SyncError::Authentication
            } else {
                SyncError::Server(format!("http_{}", response.status().as_u16()))
            });
        }
        let token: TokenFile = response.json().await?;
        write_token(&self.token_path, &token.access_token)
    }
}

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("synchronization credentials unavailable: {0}")]
    Credentials(String),
    #[error("server authentication failed")]
    Authentication,
    #[error("server protocol error: {0}")]
    Protocol(&'static str),
    #[error("server rejected request: {0}")]
    Server(String),
    #[error("synchronization transport error: {0}")]
    Transport(String),
    #[error("synchronization connection closed")]
    Disconnected,
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("cryptographic envelope error: {0}")]
    Crypto(#[from] kclip_crypto::CryptoError),
    #[error("JSON protocol error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("credential I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid HTTP header")]
    Header(#[from] tokio_tungstenite::tungstenite::http::header::InvalidHeaderValue),
    #[error("Noise protocol failed: {0}")]
    Noise(String),
}

impl SyncError {
    pub fn category(&self) -> &'static str {
        match self {
            Self::Credentials(_) => "credentials",
            Self::Authentication => "authentication",
            Self::Protocol(_) | Self::Json(_) | Self::Header(_) | Self::Noise(_) => "protocol",
            Self::Server(_) => "server",
            Self::Transport(_) | Self::Disconnected | Self::WebSocket(_) | Self::Http(_) => {
                "connectivity"
            }
            Self::Storage(_) | Self::Io(_) => "storage",
            Self::Crypto(_) => "cryptography",
        }
    }

    fn is_permanent_event_error(&self) -> bool {
        matches!(self, Self::Crypto(_) | Self::Protocol(_) | Self::Json(_))
            || matches!(
                self,
                Self::Storage(
                    StorageError::IdentityConflict(_) | StorageError::ContentTooLarge { .. }
                )
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kclip_storage::MutationOptions;
    use tempfile::TempDir;
    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_hdr_async;

    async fn noise_server_handshake(
        socket: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
        psk: &[u8; 32],
    ) -> snow::TransportState {
        let parameters: NoiseParams = NOISE_PROTOCOL_NAME.parse().unwrap();
        let mut handshake = Builder::new(parameters)
            .psk(0, psk)
            .unwrap()
            .build_responder()
            .unwrap();
        let Message::Binary(first) = socket.next().await.unwrap().unwrap() else {
            panic!("expected binary Noise handshake")
        };
        let mut payload = [0_u8; 128];
        handshake.read_message(&first, &mut payload).unwrap();
        let mut second = [0_u8; 128];
        let length = handshake.write_message(&[], &mut second).unwrap();
        socket
            .send(Message::Binary(second[..length].to_vec().into()))
            .await
            .unwrap();
        handshake.into_transport_mode().unwrap()
    }

    async fn noise_server_receive(
        socket: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
        state: &mut snow::TransportState,
    ) -> ClientMessage {
        let mut assembled = Vec::new();
        loop {
            let Message::Binary(ciphertext) = socket.next().await.unwrap().unwrap() else {
                panic!("expected encrypted binary frame")
            };
            let mut plaintext = vec![0_u8; ciphertext.len()];
            let length = state.read_message(&ciphertext, &mut plaintext).unwrap();
            plaintext.truncate(length);
            let (&flag, data) = plaintext.split_first().unwrap();
            assembled.extend_from_slice(data);
            if flag == CHUNK_FINAL {
                return serde_json::from_slice(&assembled).unwrap();
            }
            assert_eq!(flag, CHUNK_CONTINUES);
        }
    }

    async fn noise_server_send(
        socket: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
        state: &mut snow::TransportState,
        message: &ServerMessage,
    ) {
        let plaintext = serde_json::to_vec(message).unwrap();
        for (index, chunk) in plaintext.chunks(MAX_CHUNK_DATA_BYTES).enumerate() {
            let flag = if (index + 1) * MAX_CHUNK_DATA_BYTES >= plaintext.len() {
                CHUNK_FINAL
            } else {
                CHUNK_CONTINUES
            };
            let mut framed = Vec::with_capacity(chunk.len() + 1);
            framed.push(flag);
            framed.extend_from_slice(chunk);
            let mut ciphertext = vec![0_u8; framed.len() + NOISE_TAG_BYTES];
            let length = state.write_message(&framed, &mut ciphertext).unwrap();
            ciphertext.truncate(length);
            socket
                .send(Message::Binary(ciphertext.into()))
                .await
                .unwrap();
        }
    }

    fn storage(temp: &TempDir) -> Arc<Storage> {
        Arc::new(Storage::open(temp.path().join("db"), temp.path().join("blobs"), 1024).unwrap())
    }

    fn event_from_push(push: ClientMessage, sequence: u64, sender: String) -> InboxEvent {
        let ClientMessage::Push {
            message_id,
            algorithm,
            nonce,
            ciphertext,
            tag,
            ..
        } = push
        else {
            panic!("expected push")
        };
        InboxEvent {
            message_id,
            server_sequence: sequence,
            source_device_id: sender,
            algorithm,
            nonce,
            ciphertext,
            tag,
            accepted_at: sequence as i64,
        }
    }

    #[test]
    fn pairing_codes_round_trip_into_private_credential_files() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let path = temp.path().join("private/pairing.json");
        let pairing_id = "eb6b89c3-6a6f-45fa-8da7-b74ea00bbfd5";
        let psk = [29_u8; 32];
        write_pairing_code(
            &path,
            &format!(
                "{PAIRING_CODE_PREFIX}:{pairing_id}:{}",
                URL_SAFE_NO_PAD.encode(psk)
            ),
        )
        .unwrap();
        let credential = read_pairing(&path).unwrap();
        assert_eq!(credential.version, 1);
        assert_eq!(credential.pairing_id, pairing_id);
        assert_eq!(pairing_psk(&credential).unwrap(), psk);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(remove_pairing(&path).unwrap());
        assert!(!remove_pairing(&path).unwrap());
    }

    #[test]
    fn pairing_codes_reject_wrong_length_and_noncanonical_ids() {
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("pairing.json");
        for code in [
            "not-a-pairing-code",
            "kclip-pair-v1:EB6B89C3-6A6F-45FA-8DA7-B74EA00BBFD5:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "kclip-pair-v1:eb6b89c3-6a6f-45fa-8da7-b74ea00bbfd5:AAAA",
        ] {
            assert!(write_pairing_code(&path, code).is_err());
        }
    }

    #[tokio::test]
    async fn outbox_ciphertext_round_trips_through_durable_inbox() {
        let source_temp = TempDir::new().unwrap();
        let source = storage(&source_temp);
        source
            .copy_with_options(
                "build-log",
                b"binary\0value",
                None,
                MutationOptions {
                    source_adapter: "cli".into(),
                    local_only: false,
                    enqueue_sync: true,
                },
            )
            .unwrap();
        let item = source.pending_outbox(1).unwrap().remove(0);
        let key = [4_u8; 32];
        let first_push = outbox_push(&source, &item, &key).unwrap();
        let retry_item = source.pending_outbox(1).unwrap().remove(0);
        assert_eq!(outbox_push(&source, &retry_item, &key).unwrap(), first_push);
        let ClientMessage::Push {
            message_id,
            algorithm,
            nonce,
            ciphertext,
            tag,
            ..
        } = first_push
        else {
            panic!("expected push")
        };

        let destination_temp = TempDir::new().unwrap();
        let destination = storage(&destination_temp);
        let event = InboxEvent {
            message_id,
            server_sequence: 1,
            source_device_id: source.device_id().unwrap(),
            algorithm,
            nonce,
            ciphertext,
            tag,
            accepted_at: 100,
        };
        let status = Arc::new(RwLock::new(RuntimeStatus::default()));
        assert_eq!(
            process_event(&destination, &key, 1024, &event, &status)
                .await
                .unwrap(),
            1
        );
        assert_eq!(destination.paste("build-log").unwrap().1, b"binary\0value");
        assert!(destination.pending_outbox(10).unwrap().is_empty());
        assert_eq!(
            process_event(&destination, &key, 1024, &event, &status)
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn durable_ciphertext_inbox_recovers_after_storage_restart() {
        let source_temp = TempDir::new().unwrap();
        let source = storage(&source_temp);
        source
            .copy_with_options(
                "default",
                b"recover me",
                None,
                MutationOptions {
                    source_adapter: "cli".into(),
                    local_only: false,
                    enqueue_sync: true,
                },
            )
            .unwrap();
        let key = [19_u8; 32];
        let event = event_from_push(
            outbox_push(&source, &source.pending_outbox(1).unwrap()[0], &key).unwrap(),
            1,
            source.device_id().unwrap(),
        );

        let destination_temp = TempDir::new().unwrap();
        {
            let destination = storage(&destination_temp);
            destination.record_inbox(&event).unwrap();
            assert_eq!(destination.pending_inbox().unwrap().len(), 1);
        }
        let destination = storage(&destination_temp);
        let status = Arc::new(RwLock::new(RuntimeStatus::default()));
        recover_inbox(&destination, &key, 1024, &status)
            .await
            .unwrap();
        assert_eq!(destination.paste("default").unwrap().1, b"recover me");
        assert_eq!(destination.sync_status().unwrap().server_cursor, 1);
    }

    #[tokio::test]
    async fn authenticated_envelope_failure_is_durably_quarantined() {
        let source_temp = TempDir::new().unwrap();
        let source = storage(&source_temp);
        source
            .copy_with_options(
                "default",
                b"secret bytes",
                None,
                MutationOptions {
                    source_adapter: "cli".into(),
                    local_only: false,
                    enqueue_sync: true,
                },
            )
            .unwrap();
        let key = [29_u8; 32];
        let mut event = event_from_push(
            outbox_push(&source, &source.pending_outbox(1).unwrap()[0], &key).unwrap(),
            1,
            source.device_id().unwrap(),
        );
        let replacement = if event.tag.starts_with('A') { "B" } else { "A" };
        event.tag.replace_range(0..1, replacement);
        let destination_temp = TempDir::new().unwrap();
        let destination = storage(&destination_temp);
        let status = Arc::new(RwLock::new(RuntimeStatus::default()));
        assert_eq!(
            process_event(&destination, &key, 1024, &event, &status)
                .await
                .unwrap(),
            1
        );
        assert_eq!(destination.sync_status().unwrap().quarantined_events, 1);
        assert!(matches!(
            destination.paste("default"),
            Err(StorageError::SlotNotFound(_))
        ));
        assert_eq!(
            status.read().await.last_error_category.as_deref(),
            Some("cryptography")
        );
    }

    #[test]
    fn auth_base_url_is_derived_without_weakening_tls() {
        let client =
            AuthClient::from_relay("wss://clipboard.example/sync/v1", PathBuf::from("token"))
                .unwrap();
        assert_eq!(client.base_url, "https://clipboard.example");
    }

    #[test]
    fn websocket_json_matches_the_cross_repository_wire_fixture() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../fixtures/sync-wire-v1.json")).unwrap();
        for name in ["hello", "push", "checkpoint"] {
            let message: ClientMessage = serde_json::from_value(fixture[name].clone()).unwrap();
            assert_eq!(serde_json::to_value(message).unwrap(), fixture[name]);
        }
        for name in ["ready", "push_ack", "event"] {
            let message: ServerMessage = serde_json::from_value(fixture[name].clone()).unwrap();
            assert_eq!(serde_json::to_value(message).unwrap(), fixture[name]);
        }
    }

    #[test]
    fn retry_jitter_stays_inside_the_bounded_window() {
        for _ in 0..1_000 {
            let delay = jittered(Duration::from_secs(10), Duration::from_secs(60));
            assert!(delay >= Duration::from_secs(8));
            assert!(delay <= Duration::from_secs(12));
        }
        assert_eq!(
            jittered(Duration::from_secs(60), Duration::from_secs(30)),
            Duration::from_secs(30)
        );
    }

    #[tokio::test]
    async fn two_offline_devices_converge_and_tombstone_without_feedback() {
        let first_temp = TempDir::new().unwrap();
        let second_temp = TempDir::new().unwrap();
        let first = storage(&first_temp);
        let second = storage(&second_temp);
        let options = MutationOptions {
            source_adapter: "cli".into(),
            local_only: false,
            enqueue_sync: true,
        };
        first
            .copy_with_options("default", b"from first", None, options.clone())
            .unwrap();
        second
            .copy_with_options("default", b"from second", None, options.clone())
            .unwrap();
        let key = [11_u8; 32];
        let first_event = event_from_push(
            outbox_push(&first, &first.pending_outbox(1).unwrap()[0], &key).unwrap(),
            1,
            first.device_id().unwrap(),
        );
        let second_event = event_from_push(
            outbox_push(&second, &second.pending_outbox(1).unwrap()[0], &key).unwrap(),
            2,
            second.device_id().unwrap(),
        );
        let status = Arc::new(RwLock::new(RuntimeStatus::default()));
        for destination in [&first, &second] {
            process_event(destination, &key, 1024, &first_event, &status)
                .await
                .unwrap();
            process_event(destination, &key, 1024, &second_event, &status)
                .await
                .unwrap();
        }
        assert_eq!(
            first.paste("default").unwrap().1,
            second.paste("default").unwrap().1
        );
        // Each device still has exactly its own pending local upload; remote
        // application never feeds an event back into the outbox.
        assert_eq!(first.pending_outbox(10).unwrap().len(), 1);
        assert_eq!(second.pending_outbox(10).unwrap().len(), 1);

        first.clear_with_options("default", options).unwrap();
        let clear_item = first.pending_outbox(10).unwrap().pop().unwrap();
        let clear_event = event_from_push(
            outbox_push(&first, &clear_item, &key).unwrap(),
            3,
            first.device_id().unwrap(),
        );
        for destination in [&first, &second] {
            process_event(destination, &key, 1024, &clear_event, &status)
                .await
                .unwrap();
            assert!(matches!(
                destination.paste("default"),
                Err(StorageError::SlotNotFound(_))
            ));
        }
    }

    #[tokio::test]
    #[allow(clippy::result_large_err)]
    async fn noise_worker_authenticates_uploads_replays_and_checkpoints() {
        let temp = TempDir::new().unwrap();
        let storage = storage(&temp);
        storage
            .copy_with_options(
                "default",
                b"through relay",
                None,
                MutationOptions {
                    source_adapter: "cli".into(),
                    local_only: false,
                    enqueue_sync: true,
                },
            )
            .unwrap();
        let token_path = temp.path().join("config/token.json");
        let pairing_path = temp.path().join("config/pairing.json");
        let key_path = temp.path().join("data/sync.key");
        let pairing_id = "eb6b89c3-6a6f-45fa-8da7-b74ea00bbfd5";
        let psk = [17_u8; 32];
        write_pairing_code(
            &pairing_path,
            &format!(
                "{PAIRING_CODE_PREFIX}:{pairing_id}:{}",
                URL_SAFE_NO_PAD.encode(psk)
            ),
        )
        .unwrap();
        let key = [23_u8; 32];
        kclip_crypto::write_sync_key(&key_path, &key).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let relay = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = accept_hdr_async(
                stream,
                |request: &tokio_tungstenite::tungstenite::handshake::server::Request, response| {
                    assert_eq!(
                        request.headers().get("x-kclip-transport").unwrap(),
                        NOISE_TRANSPORT_NAME
                    );
                    assert_eq!(
                        request.headers().get("x-kclip-pairing-id").unwrap(),
                        pairing_id
                    );
                    assert!(request.headers().get(AUTHORIZATION).is_none());
                    Ok(response)
                },
            )
            .await
            .unwrap();
            let mut noise = noise_server_handshake(&mut socket, &psk).await;

            let hello = noise_server_receive(&mut socket, &mut noise).await;
            let ClientMessage::Hello {
                device_id,
                resume_after,
                ..
            } = hello
            else {
                panic!("expected hello")
            };
            assert_eq!(resume_after, 0);
            noise_server_send(
                &mut socket,
                &mut noise,
                &ServerMessage::Ready {
                    protocol_version: PROTOCOL_VERSION,
                    connection_id: "connection-1".into(),
                    latest_sequence: 0,
                    replay_from: 1,
                },
            )
            .await;

            let push = noise_server_receive(&mut socket, &mut noise).await;
            let ClientMessage::Push {
                message_id,
                algorithm,
                nonce,
                ciphertext,
                tag,
                ..
            } = push
            else {
                panic!("expected push")
            };
            noise_server_send(
                &mut socket,
                &mut noise,
                &ServerMessage::PushAck {
                    message_id: message_id.clone(),
                    server_sequence: 1,
                    duplicate: false,
                },
            )
            .await;
            noise_server_send(
                &mut socket,
                &mut noise,
                &ServerMessage::Event {
                    server_sequence: 1,
                    message_id,
                    sender_device_id: device_id,
                    algorithm,
                    nonce,
                    ciphertext,
                    tag,
                    accepted_at: 1,
                },
            )
            .await;
            let checkpoint = noise_server_receive(&mut socket, &mut noise).await;
            assert_eq!(checkpoint, ClientMessage::Checkpoint { server_sequence: 1 });
        });

        let control = start_worker(
            Arc::clone(&storage),
            ResolvedSyncConfig {
                relay_url: format!("ws://{address}/sync/v1"),
                reconnect_min_delay: Duration::from_millis(10),
                reconnect_max_delay: Duration::from_millis(50),
                device_name: "test".into(),
                token_path,
                pairing_path,
                sync_key_path: key_path,
                allow_insecure_transport: false,
            },
            1024,
        );
        tokio::time::timeout(Duration::from_secs(5), relay)
            .await
            .unwrap()
            .unwrap();
        for _ in 0..100 {
            let sync = storage.sync_status().unwrap();
            if sync.pending_outbox_count == 0 && sync.server_cursor == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let sync = storage.sync_status().unwrap();
        assert_eq!(sync.pending_outbox_count, 0);
        assert_eq!(sync.server_cursor, 1);
        control.shutdown();
    }
}
