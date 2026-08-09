use futures_util::StreamExt;
use kclip_config::ResolvedPlasmaConfig;
use kclip_protocol::RevisionMetadata;
use kclip_storage::{MutationOptions, Storage, StorageError};
use kclip_sync::WorkerControl;
use std::{future::Future, sync::Arc, time::Duration};
use thiserror::Error;
use tokio::sync::{RwLock, broadcast, watch};
use tracing::{debug, warn};
use zbus::{Connection, fdo::DBusProxy, names::BusName};

const KLIPPER_SERVICE: &str = "org.kde.klipper";
const DBUS_TIMEOUT: Duration = Duration::from_secs(5);
const RETRY_DELAY: Duration = Duration::from_secs(2);
const HEALTH_INTERVAL: Duration = Duration::from_secs(10);
const SELF_WRITE_SUPPRESSION: Duration = Duration::from_millis(500);

#[zbus::proxy(
    default_service = "org.kde.klipper",
    default_path = "/klipper",
    interface = "org.kde.klipper.klipper",
    gen_blocking = false
)]
trait Klipper {
    #[zbus(name = "getClipboardContents")]
    fn get_clipboard_contents(&self) -> zbus::Result<String>;

    #[zbus(name = "setClipboardContents")]
    fn set_clipboard_contents(&self, contents: &str) -> zbus::Result<()>;

    #[zbus(name = "clearClipboardContents")]
    fn clear_clipboard_contents(&self) -> zbus::Result<()>;

    #[zbus(signal, name = "clipboardHistoryUpdated")]
    fn clipboard_history_updated(&self) -> zbus::Result<()>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlasmaRuntimeStatus {
    pub state: String,
    pub last_error_category: Option<String>,
}

impl Default for PlasmaRuntimeStatus {
    fn default() -> Self {
        Self {
            state: "starting".into(),
            last_error_category: None,
        }
    }
}

#[derive(Clone)]
pub struct PlasmaControl {
    status: Arc<RwLock<PlasmaRuntimeStatus>>,
    stop: watch::Sender<bool>,
}

impl PlasmaControl {
    pub async fn status(&self) -> PlasmaRuntimeStatus {
        self.status.read().await.clone()
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

#[derive(Debug, Clone)]
pub struct PlasmaAdapterConfig {
    pub plasma: ResolvedPlasmaConfig,
    pub enqueue_sync: bool,
}

pub fn start_worker(
    storage: Arc<Storage>,
    configuration: PlasmaAdapterConfig,
    sync_worker: Option<WorkerControl>,
) -> PlasmaControl {
    let status = Arc::new(RwLock::new(PlasmaRuntimeStatus::default()));
    let (stop, stop_receiver) = watch::channel(false);
    let control = PlasmaControl {
        status: Arc::clone(&status),
        stop,
    };
    let revisions = storage.subscribe_revisions();
    tokio::spawn(async move {
        worker_loop(
            storage,
            configuration,
            sync_worker,
            revisions,
            status,
            stop_receiver,
        )
        .await;
    });
    control
}

async fn worker_loop(
    storage: Arc<Storage>,
    configuration: PlasmaAdapterConfig,
    sync_worker: Option<WorkerControl>,
    mut revisions: broadcast::Receiver<RevisionMetadata>,
    status: Arc<RwLock<PlasmaRuntimeStatus>>,
    mut stop: watch::Receiver<bool>,
) {
    let local_device_id = match storage.device_id() {
        Ok(device_id) => device_id,
        Err(error) => {
            warn!(category = "storage", error = %error, "Plasma adapter could not read the local device identity");
            set_status(&status, "error", Some("storage")).await;
            set_status(&status, "stopped", Some("storage")).await;
            return;
        }
    };

    while !*stop.borrow() {
        set_status(&status, "connecting", None).await;
        let attempt = connected_session(
            &storage,
            &configuration,
            sync_worker.as_ref(),
            &local_device_id,
            &mut revisions,
            &status,
            &mut stop,
        )
        .await;
        if *stop.borrow() {
            break;
        }
        if let Err(error) = attempt {
            let category = error.category();
            let state = if matches!(error, PlasmaError::KlipperUnavailable) {
                "unavailable"
            } else {
                "error"
            };
            warn!(category, "Plasma clipboard adapter is unavailable");
            set_status(&status, state, Some(category)).await;
        }
        tokio::select! {
            _ = tokio::time::sleep(RETRY_DELAY) => {},
            _ = stop.changed() => {},
        }
    }
    set_status(&status, "stopped", None).await;
}

async fn connected_session(
    storage: &Storage,
    configuration: &PlasmaAdapterConfig,
    sync_worker: Option<&WorkerControl>,
    local_device_id: &str,
    revisions: &mut broadcast::Receiver<RevisionMetadata>,
    status: &Arc<RwLock<PlasmaRuntimeStatus>>,
    stop: &mut watch::Receiver<bool>,
) -> Result<(), PlasmaError> {
    let connection = dbus_call(Connection::session()).await?;
    let bus = dbus_call(DBusProxy::new(&connection)).await?;
    if !fdo_call(bus.name_has_owner(BusName::try_from(KLIPPER_SERVICE)?)).await? {
        return Err(PlasmaError::KlipperUnavailable);
    }
    let proxy = dbus_call(KlipperProxy::new(&connection)).await?;
    let mut signals = dbus_call(proxy.receive_clipboard_history_updated()).await?;
    let mut pending_write = None;
    let startup_head = slot_head_revision_id(storage, &configuration.plasma.mirror_slot)?;

    let had_head = if configuration.plasma.slot_to_desktop {
        reconcile_to_desktop(storage, configuration, &proxy, &mut pending_write).await?
    } else {
        false
    };
    let mut startup_import_pending = !had_head && configuration.plasma.desktop_to_slot;
    let mut startup_gate = sync_worker.map(WorkerControl::startup_import_ready);
    if startup_import_pending && startup_gate.as_ref().is_none_or(|gate| *gate.borrow()) {
        complete_startup_import(
            storage,
            configuration,
            sync_worker,
            &proxy,
            &mut pending_write,
            startup_head.as_deref(),
        )
        .await?;
        startup_import_pending = false;
    }
    set_status(status, "connected", None).await;
    debug!("Plasma clipboard adapter connected to Klipper");

    let mut health = tokio::time::interval(HEALTH_INTERVAL);
    health.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    return Ok(());
                }
            }
            revision = revisions.recv() => {
                match revision {
                    Ok(metadata)
                        if configuration.plasma.slot_to_desktop
                            && metadata.slot == configuration.plasma.mirror_slot
                            && !(metadata.origin_device_id == local_device_id
                                && metadata.source_adapter == "plasma") =>
                    {
                        reconcile_to_desktop(
                            storage,
                            configuration,
                            &proxy,
                            &mut pending_write,
                        ).await?;
                    }
                    Ok(_) => {}
                    Err(broadcast::error::RecvError::Lagged(_))
                        if configuration.plasma.slot_to_desktop =>
                    {
                        reconcile_to_desktop(
                            storage,
                            configuration,
                            &proxy,
                            &mut pending_write,
                        ).await?;
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => {
                        return Err(PlasmaError::RevisionChannelClosed);
                    }
                }
            }
            signal = signals.next() => {
                if signal.is_none() {
                    return Err(PlasmaError::SignalStreamEnded);
                }
                if configuration.plasma.desktop_to_slot {
                    import_from_desktop(
                        storage,
                        configuration,
                        sync_worker,
                        &proxy,
                        &mut pending_write,
                    ).await?;
                    // A signal is a post-startup desktop mutation, not the
                    // one-time reconciliation value guarded by the replay gate.
                    startup_import_pending = false;
                }
            }
            _ = wait_for_startup_gate(&mut startup_gate), if startup_import_pending => {
                complete_startup_import(
                    storage,
                    configuration,
                    sync_worker,
                    &proxy,
                    &mut pending_write,
                    startup_head.as_deref(),
                ).await?;
                startup_import_pending = false;
            }
            _ = health.tick() => {
                if !fdo_call(bus.name_has_owner(BusName::try_from(KLIPPER_SERVICE)?)).await? {
                    return Err(PlasmaError::KlipperUnavailable);
                }
            }
        }
    }
}

async fn wait_for_startup_gate(gate: &mut Option<watch::Receiver<bool>>) {
    let Some(gate) = gate else {
        return;
    };
    loop {
        if *gate.borrow() || gate.changed().await.is_err() {
            return;
        }
    }
}

async fn complete_startup_import(
    storage: &Storage,
    configuration: &PlasmaAdapterConfig,
    sync_worker: Option<&WorkerControl>,
    proxy: &KlipperProxy<'_>,
    pending_write: &mut Option<PendingWrite>,
    startup_head: Option<&str>,
) -> Result<(), PlasmaError> {
    let current_head = slot_head_revision_id(storage, &configuration.plasma.mirror_slot)?;
    if startup_import_superseded(startup_head, current_head.as_deref()) {
        debug!("skipped Plasma startup import because sync replay changed the slot head");
        return Ok(());
    }
    import_from_desktop(storage, configuration, sync_worker, proxy, pending_write).await
}

fn startup_import_superseded(startup_head: Option<&str>, current_head: Option<&str>) -> bool {
    current_head != startup_head
}

fn slot_head_revision_id(storage: &Storage, slot: &str) -> Result<Option<String>, StorageError> {
    match storage.slot_head(slot) {
        Ok((metadata, _)) => Ok(Some(metadata.revision_id)),
        Err(StorageError::SlotNotFound(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DesktopValue {
    Text(String),
    Clear,
    Unsupported,
}

#[derive(Debug, Clone)]
struct PendingWrite {
    value: DesktopValue,
    expires_at: tokio::time::Instant,
}

impl PendingWrite {
    fn new(value: DesktopValue) -> Self {
        Self {
            value,
            expires_at: tokio::time::Instant::now() + SELF_WRITE_SUPPRESSION,
        }
    }
}

async fn reconcile_to_desktop(
    storage: &Storage,
    configuration: &PlasmaAdapterConfig,
    proxy: &KlipperProxy<'_>,
    pending_write: &mut Option<PendingWrite>,
) -> Result<bool, PlasmaError> {
    let (metadata, content) = match storage.slot_head(&configuration.plasma.mirror_slot) {
        Ok(head) => head,
        Err(StorageError::SlotNotFound(_)) => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    let value = desktop_value(&metadata, content.as_deref());
    match &value {
        DesktopValue::Text(text) => {
            dbus_call(proxy.set_clipboard_contents(text)).await?;
            *pending_write = Some(PendingWrite::new(value));
        }
        DesktopValue::Clear => {
            dbus_call(proxy.clear_clipboard_contents()).await?;
            *pending_write = Some(PendingWrite::new(value));
        }
        DesktopValue::Unsupported => {
            warn!(
                category = "unsupported_content",
                "mirrored slot head cannot be represented by Klipper's text D-Bus API"
            );
        }
    }
    Ok(true)
}

async fn import_from_desktop(
    storage: &Storage,
    configuration: &PlasmaAdapterConfig,
    sync_worker: Option<&WorkerControl>,
    proxy: &KlipperProxy<'_>,
    pending_write: &mut Option<PendingWrite>,
) -> Result<(), PlasmaError> {
    let text = dbus_call(proxy.get_clipboard_contents()).await?;
    if let Some(pending) = pending_write
        .take()
        .filter(|pending| pending.expires_at >= tokio::time::Instant::now())
    {
        match pending.value {
            DesktopValue::Text(expected) if expected == text => return Ok(()),
            DesktopValue::Clear => return Ok(()),
            _ => {}
        }
    }
    if text.is_empty() || desktop_matches_head(storage, &configuration.plasma.mirror_slot, &text)? {
        return Ok(());
    }

    storage.copy_with_options(
        &configuration.plasma.mirror_slot,
        text.as_bytes(),
        Some("text/plain; charset=utf-8"),
        MutationOptions {
            source_adapter: "plasma".into(),
            local_only: false,
            enqueue_sync: configuration.enqueue_sync,
        },
    )?;
    if let Some(worker) = sync_worker {
        worker.wake();
    }
    Ok(())
}

fn desktop_matches_head(storage: &Storage, slot: &str, text: &str) -> Result<bool, StorageError> {
    match storage.slot_head(slot) {
        Ok((metadata, Some(content))) if !metadata.is_deleted => Ok(content == text.as_bytes()),
        Ok(_) | Err(StorageError::SlotNotFound(_)) => Ok(false),
        Err(error) => Err(error),
    }
}

fn desktop_value(metadata: &RevisionMetadata, content: Option<&[u8]>) -> DesktopValue {
    if metadata.is_deleted {
        return DesktopValue::Clear;
    }
    let is_text = metadata
        .content_type
        .as_deref()
        .is_some_and(|content_type| content_type.to_ascii_lowercase().starts_with("text/"));
    if !is_text {
        return DesktopValue::Unsupported;
    }
    match content.and_then(|content| std::str::from_utf8(content).ok()) {
        Some(text) if !text.is_empty() => DesktopValue::Text(text.to_owned()),
        _ => DesktopValue::Unsupported,
    }
}

async fn dbus_call<T>(future: impl Future<Output = zbus::Result<T>>) -> Result<T, PlasmaError> {
    tokio::time::timeout(DBUS_TIMEOUT, future)
        .await
        .map_err(|_| PlasmaError::Timeout)?
        .map_err(PlasmaError::Dbus)
}

async fn fdo_call<T>(future: impl Future<Output = zbus::fdo::Result<T>>) -> Result<T, PlasmaError> {
    tokio::time::timeout(DBUS_TIMEOUT, future)
        .await
        .map_err(|_| PlasmaError::Timeout)?
        .map_err(PlasmaError::Fdo)
}

async fn set_status(
    status: &RwLock<PlasmaRuntimeStatus>,
    state: &str,
    last_error_category: Option<&str>,
) {
    let mut current = status.write().await;
    current.state = state.into();
    current.last_error_category = last_error_category.map(str::to_owned);
}

#[derive(Debug, Error)]
enum PlasmaError {
    #[error("Klipper does not own its session D-Bus service")]
    KlipperUnavailable,
    #[error("D-Bus operation timed out")]
    Timeout,
    #[error("Klipper D-Bus signal stream ended")]
    SignalStreamEnded,
    #[error("revision notification channel closed")]
    RevisionChannelClosed,
    #[error("D-Bus operation failed: {0}")]
    Dbus(#[source] zbus::Error),
    #[error("D-Bus service query failed: {0}")]
    Fdo(#[source] zbus::fdo::Error),
    #[error("storage operation failed: {0}")]
    Storage(#[from] StorageError),
    #[error("invalid static D-Bus name: {0}")]
    InvalidName(#[from] zbus::names::Error),
}

impl PlasmaError {
    fn category(&self) -> &'static str {
        match self {
            Self::KlipperUnavailable => "klipper_unavailable",
            Self::Timeout => "timeout",
            Self::SignalStreamEnded => "signal_stream",
            Self::RevisionChannelClosed | Self::Storage(_) => "storage",
            Self::Dbus(_) | Self::Fdo(_) | Self::InvalidName(_) => "dbus",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata(content_type: Option<&str>, deleted: bool) -> RevisionMetadata {
        RevisionMetadata {
            revision_id: "device:1".into(),
            slot: "default".into(),
            origin_device_id: "device".into(),
            origin_sequence: 1,
            hlc_physical: 1,
            hlc_logical: 0,
            content_hash: (!deleted).then(|| "hash".into()),
            content_size: if deleted { 0 } else { 5 },
            content_type: content_type.map(str::to_owned),
            created_at: 1,
            expires_at: None,
            is_deleted: deleted,
            is_local_only: false,
            source_adapter: "cli".into(),
            synchronization_state: "local".into(),
        }
    }

    #[test]
    fn text_heads_and_tombstones_map_to_klipper_operations() {
        assert_eq!(
            desktop_value(
                &metadata(Some("text/plain; charset=utf-8"), false),
                Some(b"hello")
            ),
            DesktopValue::Text("hello".into())
        );
        assert_eq!(
            desktop_value(&metadata(Some("text/plain"), true), None),
            DesktopValue::Clear
        );
    }

    #[test]
    fn binary_invalid_utf8_and_empty_values_are_not_exported() {
        assert_eq!(
            desktop_value(
                &metadata(Some("application/octet-stream"), false),
                Some(b"hello")
            ),
            DesktopValue::Unsupported
        );
        assert_eq!(
            desktop_value(&metadata(Some("text/plain"), false), Some(&[0xff])),
            DesktopValue::Unsupported
        );
        assert_eq!(
            desktop_value(&metadata(Some("text/plain"), false), Some(b"")),
            DesktopValue::Unsupported
        );
    }

    #[tokio::test]
    async fn startup_import_gate_waits_for_replay_or_offline_signal() {
        let (ready, receiver) = watch::channel(false);
        let mut gate = Some(receiver);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), wait_for_startup_gate(&mut gate))
                .await
                .is_err()
        );
        ready.send(true).unwrap();
        tokio::time::timeout(Duration::from_millis(100), wait_for_startup_gate(&mut gate))
            .await
            .unwrap();
    }

    #[test]
    fn replayed_slot_head_suppresses_only_the_startup_import() {
        assert!(!startup_import_superseded(None, None));
        assert!(!startup_import_superseded(Some("local"), Some("local")));
        assert!(startup_import_superseded(None, Some("remote")));
        assert!(startup_import_superseded(Some("local"), Some("remote")));
    }
}
