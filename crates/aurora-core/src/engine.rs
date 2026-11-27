use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aurora_protocol::{
    validate_device_name, DeviceId, EmptyPayload, GoodbyePayload, GoodbyeReason, HandshakeIntent,
    HelloPayload, Message, PingPayload, PongPayload, RejectPayload, RejectReason,
    SessionAcceptPayload, ENGINE_EVENT_QUEUE, HEARTBEAT_INTERVAL, HELLO_TIMEOUT,
    INBOUND_FRAME_QUEUE, MAX_RECONNECT_ATTEMPTS, MIN_UNPRIVILEGED_PORT, PAIRING_TIMEOUT,
    SESSION_TIMEOUT,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::auth::DeviceIdentity;
use crate::discovery::{
    unix_now_ms, DiscoveredCache, DiscoveryEvent, MdnsController, DEFAULT_MDNS_SERVICE_TYPE,
};
use crate::error::CoreError;
use crate::network::{
    is_allowed_local_ip, local_lan_addresses, normalize_ip, validate_peer_addr, ConnectionGuard,
    ConnectionLimiter,
};
use crate::pairing::{InboundPairingGuard, PairingDirection, PairingGate, PendingPairingView};
use crate::platform::SecretStore;
use crate::registry::DeviceRegistry;
use crate::session::{
    ActiveSessionView, ConnectOutcome, ConnectionDirection, DiscoveredDeviceView, NoticeLevel,
    NoticeView, PeerConnectionState, TrustedDeviceView,
};
use crate::settings::{Settings, SettingsPatch, SettingsStore};
use crate::transport::{AuthenticatedStream, TlsEndpoint};

const MAX_RECENT_NOTICES: usize = 20;
const RECONNECT_SCHEDULE_SECS: [u64; 10] = [1, 2, 4, 8, 16, 30, 30, 30, 30, 30];

/// Runtime configuration for [`Engine`].
#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub data_dir: PathBuf,
    pub default_device_name: String,
    pub app_version: String,
    pub bind_ip: IpAddr,
    pub allow_ephemeral_port: bool,
    pub enable_mdns: bool,
    pub mdns_service_type: String,
    pub tcp_connect_timeout: Duration,
    pub heartbeat_interval: Duration,
    pub session_timeout: Duration,
    pub pairing_timeout: Duration,
    pub reconnect_base_unit: Duration,
}

impl EngineConfig {
    pub fn production(data_dir: PathBuf, default_device_name: String, app_version: String) -> Self {
        Self {
            data_dir,
            default_device_name,
            app_version,
            bind_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            allow_ephemeral_port: false,
            enable_mdns: true,
            mdns_service_type: DEFAULT_MDNS_SERVICE_TYPE.to_string(),
            tcp_connect_timeout: Duration::from_secs(5),
            heartbeat_interval: HEARTBEAT_INTERVAL,
            session_timeout: SESSION_TIMEOUT,
            pairing_timeout: PAIRING_TIMEOUT,
            reconnect_base_unit: Duration::from_secs(1),
        }
    }
}

/// Complete, consistent UI snapshot emitted whenever state changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineSnapshot {
    pub local_device_id: DeviceId,
    pub local_device_id_short: String,
    pub local_device_id_grouped: String,
    pub settings: Settings,
    pub listening_port: u16,
    pub lan_addresses: Vec<String>,
    pub mdns_active: bool,
    pub discovered_devices: Vec<DiscoveredDeviceView>,
    pub trusted_devices: Vec<TrustedDeviceView>,
    pub pending_pairings: Vec<PendingPairingView>,
    pub active_sessions: Vec<ActiveSessionView>,
    pub recent_notices: Vec<NoticeView>,
}

/// Broadcast notification emitted by [`Engine`].
#[derive(Debug, Clone)]
pub enum EngineEvent {
    SnapshotChanged,
}

struct ActiveSessionEntry {
    instance_num: u64,
    initiator_id: DeviceId,
    view: ActiveSessionView,
    cmd_tx: mpsc::Sender<GoodbyeReason>,
}

struct PendingPairingEntry {
    view: PendingPairingView,
    decision_tx: Option<oneshot::Sender<bool>>,
}

struct ReconnectEntry {
    attempt: u32,
    cancel: CancellationToken,
}

struct ListenerEntry {
    port: u16,
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

struct MutableState {
    settings: Settings,
    registry: DeviceRegistry,
    discovered: DiscoveredCache,
    mdns: MdnsController,
    listening_port: u16,
    listener: Option<ListenerEntry>,
    sessions: BTreeMap<DeviceId, ActiveSessionEntry>,
    connecting_peers: BTreeMap<DeviceId, ()>,
    pairings: BTreeMap<String, PendingPairingEntry>,
    reconnects: BTreeMap<DeviceId, ReconnectEntry>,
    notices: VecDeque<NoticeView>,
    next_notice_id: u64,
    next_instance_num: u64,
}

impl MutableState {
    fn push_notice(&mut self, level: NoticeLevel, message: impl Into<String>) {
        self.next_notice_id += 1;
        if self.notices.len() >= MAX_RECENT_NOTICES {
            self.notices.pop_back();
        }
        self.notices.push_front(NoticeView {
            id: self.next_notice_id,
            timestamp_ms: unix_now_ms(),
            level,
            message: message.into(),
        });
    }

    fn peer_state(&self, id: &DeviceId) -> PeerConnectionState {
        if self.sessions.contains_key(id) {
            PeerConnectionState::Connected
        } else if self.pairings.values().any(|p| &p.view.peer_id == id) {
            PeerConnectionState::Pairing
        } else if self.connecting_peers.contains_key(id) {
            PeerConnectionState::Connecting
        } else if self.reconnects.contains_key(id) {
            PeerConnectionState::Reconnecting
        } else {
            PeerConnectionState::Disconnected
        }
    }
}

/// Central Session, Discovery, Pairing and Network orchestrator.
pub struct Engine {
    config: EngineConfig,
    settings_store: SettingsStore,
    tls: Arc<TlsEndpoint>,
    limiter: ConnectionLimiter,
    pairing_gate: PairingGate,
    discovery_tx: mpsc::Sender<DiscoveryEvent>,
    events_tx: broadcast::Sender<EngineEvent>,
    shutdown_token: CancellationToken,
    state: Mutex<MutableState>,
}

impl Engine {
    /// Initializes identity, persistent stores, TCP/TLS listener and mDNS discovery.
    pub async fn start(
        config: EngineConfig,
        secret_store: Arc<dyn SecretStore>,
    ) -> Result<Arc<Self>, CoreError> {
        let identity = Arc::new(DeviceIdentity::load_or_generate(secret_store.as_ref())?);
        let tls = Arc::new(TlsEndpoint::new(Arc::clone(&identity))?);

        let settings_store = SettingsStore::new(&config.data_dir, config.allow_ephemeral_port);
        let settings = settings_store.load_or_init(&config.default_device_name)?;
        let registry = DeviceRegistry::load(&config.data_dir)?;

        let bind_addr = SocketAddr::new(config.bind_ip, settings.listen_port);
        let tcp_listener = TcpListener::bind(bind_addr).await.map_err(CoreError::Io)?;
        let actual_port = tcp_listener.local_addr()?.port();

        let (discovery_tx, discovery_rx) = mpsc::channel::<DiscoveryEvent>(64);
        let (events_tx, _) = broadcast::channel(ENGINE_EVENT_QUEUE);
        let mdns = MdnsController::new(config.mdns_service_type.clone());

        let engine = Arc::new(Self {
            config,
            settings_store,
            tls,
            limiter: ConnectionLimiter::default(),
            pairing_gate: PairingGate::default(),
            discovery_tx,
            events_tx,
            shutdown_token: CancellationToken::new(),
            state: Mutex::new(MutableState {
                settings,
                registry,
                discovered: DiscoveredCache::default(),
                mdns,
                listening_port: actual_port,
                listener: None,
                sessions: BTreeMap::new(),
                connecting_peers: BTreeMap::new(),
                pairings: BTreeMap::new(),
                reconnects: BTreeMap::new(),
                notices: VecDeque::new(),
                next_notice_id: 0,
                next_instance_num: 0,
            }),
        });

        engine.install_listener(tcp_listener, actual_port);
        engine.spawn_discovery_worker(discovery_rx);
        engine.refresh_mdns();

        info!(
            local_short = %engine.local_device_id().short(),
            port = actual_port,
            "Aurora Connect Engine iniciado"
        );

        Ok(engine)
    }

    pub fn local_device_id(&self) -> &DeviceId {
        self.tls.identity().device_id()
    }

    pub fn listening_port(&self) -> u16 {
        self.lock_state().listening_port
    }

    pub fn subscribe(&self) -> broadcast::Receiver<EngineEvent> {
        self.events_tx.subscribe()
    }

    /// Produces a complete, self-consistent snapshot of engine state.
    pub fn snapshot(&self) -> EngineSnapshot {
        let st = self.lock_state();
        let local_id = self.local_device_id().clone();

        let discovered_devices = st
            .discovered
            .list()
            .into_iter()
            .map(|d| {
                let trusted = st.registry.is_trusted(&d.device_id);
                let connection_state = st.peer_state(&d.device_id);
                DiscoveredDeviceView {
                    device_id_short: d.device_id.short(),
                    device_id_grouped: d.device_id.grouped(),
                    device_id: d.device_id,
                    device_name: d.device_name,
                    addresses: d.addresses.into_iter().map(|ip| ip.to_string()).collect(),
                    port: d.port,
                    last_seen_ms: d.last_seen_ms,
                    verified: false,
                    trusted,
                    connection_state,
                }
            })
            .collect();

        let trusted_devices = st
            .registry
            .list()
            .into_iter()
            .map(|t| {
                let connection_state = st.peer_state(&t.device_id);
                let reconnect_attempt = st.reconnects.get(&t.device_id).map(|r| r.attempt);
                let session = st.sessions.get(&t.device_id).map(|s| s.view.clone());
                TrustedDeviceView {
                    device_id_short: t.device_id.short(),
                    device_id_grouped: t.device_id.grouped(),
                    device_id: t.device_id,
                    device_name: t.device_name,
                    paired_at_ms: t.paired_at_ms,
                    last_connected_ms: t.last_connected_ms,
                    last_known_addr: t.last_known_addr.map(|a| a.to_string()),
                    connection_state,
                    reconnect_attempt,
                    session,
                }
            })
            .collect();

        let pending_pairings = st.pairings.values().map(|p| p.view.clone()).collect();
        let active_sessions = st.sessions.values().map(|s| s.view.clone()).collect();
        let recent_notices = st.notices.iter().cloned().collect();
        let lan_addresses = local_lan_addresses()
            .into_iter()
            .map(|ip| ip.to_string())
            .collect();

        EngineSnapshot {
            local_device_id_short: local_id.short(),
            local_device_id_grouped: local_id.grouped(),
            local_device_id: local_id,
            settings: st.settings.clone(),
            listening_port: st.listening_port,
            lan_addresses,
            mdns_active: st.mdns.is_active(),
            discovered_devices,
            trusted_devices,
            pending_pairings,
            active_sessions,
            recent_notices,
        }
    }

    /// Connects manually to an IP literal and optional port (defaults to local `listen_port` or 47821).
    pub async fn connect_address(
        self: &Arc<Self>,
        ip: IpAddr,
        port: Option<u16>,
    ) -> Result<ConnectOutcome, CoreError> {
        let target_port = port.unwrap_or(aurora_protocol::DEFAULT_PORT);
        let addr = validate_peer_addr(SocketAddr::new(ip, target_port))?;
        self.connect_internal(addr, None, true).await
    }

    /// Connects to a known (trusted or mDNS-discovered) device with strict ID pinning.
    pub async fn connect_device(
        self: &Arc<Self>,
        device_id: DeviceId,
    ) -> Result<ConnectOutcome, CoreError> {
        if &device_id == self.local_device_id() {
            return Err(CoreError::SelfConnection);
        }

        let target_addr = {
            let mut st = self.lock_state();
            if let Some(existing) = st.sessions.get(&device_id) {
                return Ok(ConnectOutcome::SessionEstablished {
                    peer_id: device_id,
                    session_id: existing.view.session_id.clone(),
                });
            }
            if let Some(rec) = st.reconnects.remove(&device_id) {
                rec.cancel.cancel();
            }

            if let Some(disc) = st.discovered.get(&device_id) {
                let first_ip = disc.addresses.first().copied().ok_or_else(|| {
                    CoreError::NotFound("nenhum endereço válido para o dispositivo".to_string())
                })?;
                SocketAddr::new(first_ip, disc.port)
            } else if let Some(trusted) = st.registry.get(&device_id) {
                trusted.last_known_addr.ok_or_else(|| {
                    CoreError::NotFound(
                        "dispositivo offline sem endereço conhecido na rede local".to_string(),
                    )
                })?
            } else {
                return Err(CoreError::NotFound("dispositivo desconhecido".to_string()));
            }
        };

        let validated = validate_peer_addr(target_addr)?;
        self.connect_internal(validated, Some(device_id), true)
            .await
    }

    /// Approves or rejects a pending pairing ceremony.
    pub fn respond_pairing(&self, pairing_id: &str, accept: bool) -> Result<(), CoreError> {
        let tx = {
            let mut st = self.lock_state();
            let entry = st.pairings.get_mut(pairing_id).ok_or_else(|| {
                CoreError::NotFound("solicitação de pareamento expirada".to_string())
            })?;
            let tx = entry.decision_tx.take().ok_or_else(|| {
                CoreError::InvalidInput("resposta de pareamento já registrada".to_string())
            })?;
            if accept {
                entry.view.local_confirmed = true;
            }
            tx
        };

        let _ = tx.send(accept);
        self.notify_changed();
        Ok(())
    }

    /// Disconnects an active session or cancels pending reconnection attempts.
    pub async fn disconnect_device(&self, device_id: &DeviceId) -> Result<(), CoreError> {
        let cmd_tx = {
            let mut st = self.lock_state();
            if let Some(rec) = st.reconnects.remove(device_id) {
                rec.cancel.cancel();
            }
            st.sessions.remove(device_id).map(|s| s.cmd_tx)
        };

        if let Some(tx) = cmd_tx {
            let _ = tx.send(GoodbyeReason::User).await;
            self.push_notice(
                NoticeLevel::Info,
                format!("Sessão encerrada ({})", device_id.short()),
            );
        } else {
            self.notify_changed();
        }
        Ok(())
    }

    /// Revokes trust for `device_id`, immediately terminating any active session
    /// and cancelling reconnection tasks.
    pub async fn revoke_device(&self, device_id: &DeviceId) -> Result<(), CoreError> {
        let (existed, cmd_tx) = {
            let mut st = self.lock_state();
            if let Some(rec) = st.reconnects.remove(device_id) {
                rec.cancel.cancel();
            }
            let existed = st.registry.revoke(device_id)?;
            let cmd = st.sessions.remove(device_id).map(|s| s.cmd_tx);
            (existed, cmd)
        };

        if let Some(tx) = cmd_tx {
            let _ = tx.send(GoodbyeReason::Revoked).await;
        }

        if existed {
            info!(peer_short = %device_id.short(), "confiança revogada pelo usuário");
            self.push_notice(
                NoticeLevel::Warning,
                format!(
                    "Confiança revogada para o dispositivo {}",
                    device_id.short()
                ),
            );
        } else {
            self.notify_changed();
        }
        Ok(())
    }

    /// Validates, persists and applies settings updates at runtime.
    pub async fn update_settings(
        self: &Arc<Self>,
        patch: SettingsPatch,
    ) -> Result<Settings, CoreError> {
        let (candidate, old_port) = {
            let st = self.lock_state();
            let mut next = st.settings.clone();
            if let Some(name) = patch.device_name {
                let trimmed = name.trim().to_string();
                validate_device_name(&trimmed)?;
                next.device_name = trimmed;
            }
            if let Some(port) = patch.listen_port {
                if !(self.config.allow_ephemeral_port && port == 0) && port < MIN_UNPRIVILEGED_PORT
                {
                    return Err(CoreError::InvalidInput(format!(
                        "porta deve estar entre {MIN_UNPRIVILEGED_PORT} e 65535"
                    )));
                }
                next.listen_port = port;
            }
            if let Some(disc) = patch.discovery_enabled {
                next.discovery_enabled = disc;
            }
            if let Some(pair) = patch.allow_pairing {
                next.allow_pairing = pair;
            }
            if let Some(recon) = patch.auto_reconnect {
                next.auto_reconnect = recon;
            }
            next.validate(self.config.allow_ephemeral_port)?;
            (next, st.settings.listen_port)
        };

        if candidate.listen_port != old_port {
            let bind_addr = SocketAddr::new(self.config.bind_ip, candidate.listen_port);
            let new_listener = TcpListener::bind(bind_addr).await.map_err(|e| {
                CoreError::InvalidInput(format!(
                    "não foi possível abrir a porta {}: {e}",
                    candidate.listen_port
                ))
            })?;
            let new_actual_port = new_listener.local_addr()?.port();
            self.settings_store.save(&candidate)?;
            {
                let mut st = self.lock_state();
                st.settings = candidate.clone();
            }
            self.install_listener(new_listener, new_actual_port);
        } else {
            self.settings_store.save(&candidate)?;
            let mut st = self.lock_state();
            if !candidate.auto_reconnect {
                for (_, rec) in std::mem::take(&mut st.reconnects) {
                    rec.cancel.cancel();
                }
            }
            st.settings = candidate.clone();
        }

        self.refresh_mdns();
        self.push_notice(NoticeLevel::Info, "Configurações atualizadas");
        Ok(candidate)
    }

    /// Gracefully stops discovery, listeners, reconnect workers and active sessions.
    pub async fn shutdown(&self) {
        self.shutdown_token.cancel();
        let (listener, sessions) = {
            let mut st = self.lock_state();
            st.mdns.stop();
            for (_, rec) in std::mem::take(&mut st.reconnects) {
                rec.cancel.cancel();
            }
            st.pairings.clear();
            let listener = st.listener.take();
            let sessions: Vec<_> = std::mem::take(&mut st.sessions)
                .into_values()
                .map(|s| s.cmd_tx)
                .collect();
            (listener, sessions)
        };

        if let Some(l) = listener {
            l.cancel.cancel();
            l.task.abort();
            let _ = l.task.await;
        }

        for tx in sessions {
            let _ = tx.send(GoodbyeReason::Shutdown).await;
        }
    }

    fn install_listener(self: &Arc<Self>, tcp_listener: TcpListener, actual_port: u16) {
        let cancel = CancellationToken::new();
        let loop_cancel = cancel.clone();
        let engine = Arc::clone(self);

        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = loop_cancel.cancelled() => break,
                    _ = engine.shutdown_token.cancelled() => break,
                    accepted = tcp_listener.accept() => {
                        match accepted {
                            Ok((tcp, raw_peer_addr)) => {
                                let peer_ip = normalize_ip(raw_peer_addr.ip());
                                let peer_addr = SocketAddr::new(peer_ip, raw_peer_addr.port());
                                if !is_allowed_local_ip(peer_ip) {
                                    warn!("conexão externa fora da LAN rejeitada");
                                    continue;
                                }
                                let Ok(conn_guard) = engine.limiter.try_acquire_connection(peer_ip) else {
                                    warn!("limite de conexões excedido na entrada");
                                    continue;
                                };
                                let Ok(hs_permit) = engine.limiter.try_acquire_handshake() else {
                                    warn!("limite de handshakes TLS simultâneos atingido");
                                    continue;
                                };
                                let eng = Arc::clone(&engine);
                                tokio::spawn(async move {
                                    eng.handle_inbound_connection(tcp, peer_addr, conn_guard, hs_permit).await;
                                });
                            }
                            Err(err) => {
                                warn!("erro ao aceitar socket TCP: {err}");
                                tokio::time::sleep(Duration::from_millis(50)).await;
                            }
                        }
                    }
                }
            }
        });

        let prev = {
            let mut st = self.lock_state();
            st.listening_port = actual_port;
            st.listener.replace(ListenerEntry {
                port: actual_port,
                cancel,
                task,
            })
        };
        if let Some(old) = prev {
            if old.port != actual_port {
                old.cancel.cancel();
                old.task.abort();
            }
        }
    }

    fn spawn_discovery_worker(self: &Arc<Self>, mut rx: mpsc::Receiver<DiscoveryEvent>) {
        let engine = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = engine.shutdown_token.cancelled() => break,
                    maybe_ev = rx.recv() => {
                        let Some(ev) = maybe_ev else { break };
                        let changed = {
                            let mut st = engine.lock_state();
                            if !st.settings.discovery_enabled {
                                false
                            } else {
                                match ev {
                                    DiscoveryEvent::Upsert { fullname, device } => {
                                        st.discovered.upsert(fullname, device);
                                        true
                                    }
                                    DiscoveryEvent::Removed { fullname } => {
                                        st.discovered.remove_by_fullname(&fullname)
                                    }
                                }
                            }
                        };
                        if changed {
                            engine.notify_changed();
                        }
                    }
                }
            }
        });
    }

    fn refresh_mdns(&self) {
        let mut st = self.lock_state();
        if !self.config.enable_mdns || !st.settings.discovery_enabled {
            st.mdns.stop();
            st.discovered.clear();
            return;
        }
        let local_id = self.local_device_id().clone();
        let name = st.settings.device_name.clone();
        let port = st.listening_port;
        let tx = self.discovery_tx.clone();
        st.mdns.start_or_update(&local_id, &name, port, tx);
    }

    async fn connect_internal(
        self: &Arc<Self>,
        addr: SocketAddr,
        expected_peer: Option<DeviceId>,
        user_initiated: bool,
    ) -> Result<ConnectOutcome, CoreError> {
        if let Some(id) = &expected_peer {
            let mut st = self.lock_state();
            st.connecting_peers.insert(id.clone(), ());
        }
        self.notify_changed();

        let result = self
            .connect_internal_inner(addr, expected_peer.clone(), user_initiated)
            .await;

        if let Some(id) = &expected_peer {
            let mut st = self.lock_state();
            st.connecting_peers.remove(id);
        }

        if let Err(err) = &result {
            if user_initiated {
                self.push_notice(
                    NoticeLevel::Error,
                    describe_connection_error(err, expected_peer.as_ref()),
                );
            } else {
                self.notify_changed();
            }
        } else {
            self.notify_changed();
        }

        result
    }

    async fn connect_internal_inner(
        self: &Arc<Self>,
        addr: SocketAddr,
        expected_peer: Option<DeviceId>,
        user_initiated: bool,
    ) -> Result<ConnectOutcome, CoreError> {
        let conn_guard = self.limiter.try_acquire_connection(addr.ip())?;
        let hs_permit = self.limiter.acquire_handshake().await?;

        let tcp = timeout(self.config.tcp_connect_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| CoreError::Timeout)?
            .map_err(CoreError::Io)?;

        let mut stream = self.tls.connect(tcp, expected_peer).await?;
        drop(hs_permit);

        let peer_id = stream.peer_id().clone();
        if &peer_id == self.local_device_id() {
            let _ = stream
                .send_message(Message::Reject(RejectPayload {
                    reason: RejectReason::SelfConnection,
                }))
                .await;
            stream.shutdown().await;
            return Err(CoreError::SelfConnection);
        }

        let (local_name, is_trusted) = {
            let st = self.lock_state();
            (
                st.settings.device_name.clone(),
                st.registry.is_trusted(&peer_id),
            )
        };

        if !is_trusted && !user_initiated {
            // Automatic reconnect must never initiate pairing with an untrusted device.
            let _ = stream
                .send_message(Message::Reject(RejectPayload {
                    reason: RejectReason::NotTrusted,
                }))
                .await;
            stream.shutdown().await;
            return Err(CoreError::PeerRejected(RejectReason::NotTrusted));
        }

        let intent = if is_trusted {
            HandshakeIntent::Session
        } else {
            HandshakeIntent::Pair
        };

        stream
            .send_message(Message::Hello(HelloPayload {
                device_name: local_name,
                app_version: self.config.app_version.clone(),
                intent,
            }))
            .await?;

        let first = timeout(HELLO_TIMEOUT, stream.recv_message())
            .await
            .map_err(|_| CoreError::Timeout)??;

        let peer_hello = match first.body {
            Message::Hello(h) => h,
            Message::Reject(r) => {
                if r.reason == RejectReason::NotTrusted && is_trusted {
                    let mut st = self.lock_state();
                    let _ = st.registry.revoke(&peer_id);
                    if let Some(rec) = st.reconnects.remove(&peer_id) {
                        rec.cancel.cancel();
                    }
                    st.push_notice(
                        NoticeLevel::Warning,
                        format!(
                            "Confiança revogada pelo dispositivo remoto ({})",
                            peer_id.short()
                        ),
                    );
                }
                stream.shutdown().await;
                return Err(CoreError::PeerRejected(r.reason));
            }
            _ => {
                let _ = stream
                    .send_message(Message::Reject(RejectPayload {
                        reason: RejectReason::ProtocolError,
                    }))
                    .await;
                stream.shutdown().await;
                return Err(CoreError::InvalidInput(
                    "resposta inesperada no handshake".to_string(),
                ));
            }
        };

        match intent {
            HandshakeIntent::Session => {
                let still_trusted = self.lock_state().registry.is_trusted(&peer_id);
                if !still_trusted || peer_hello.intent != HandshakeIntent::Session {
                    let _ = stream
                        .send_message(Message::Reject(RejectPayload {
                            reason: RejectReason::NotTrusted,
                        }))
                        .await;
                    stream.shutdown().await;
                    return Err(CoreError::PeerRejected(RejectReason::NotTrusted));
                }

                let second = timeout(HELLO_TIMEOUT, stream.recv_message())
                    .await
                    .map_err(|_| CoreError::Timeout)??;

                match second.body {
                    Message::SessionAccept(acc) => {
                        self.spawn_authenticated_session(
                            stream,
                            conn_guard,
                            peer_hello.device_name,
                            acc.session_id.clone(),
                            addr,
                            ConnectionDirection::Outbound,
                        )
                        .await;
                        Ok(ConnectOutcome::SessionEstablished {
                            peer_id,
                            session_id: acc.session_id,
                        })
                    }
                    Message::Reject(r) => {
                        stream.shutdown().await;
                        Err(CoreError::PeerRejected(r.reason))
                    }
                    _ => {
                        let _ = stream
                            .send_message(Message::Reject(RejectPayload {
                                reason: RejectReason::ProtocolError,
                            }))
                            .await;
                        stream.shutdown().await;
                        Err(CoreError::InvalidInput(
                            "esperado session_accept após hello".to_string(),
                        ))
                    }
                }
            }
            HandshakeIntent::Pair => {
                let second = timeout(HELLO_TIMEOUT, stream.recv_message())
                    .await
                    .map_err(|_| CoreError::Timeout)??;

                match second.body {
                    Message::PairPending(_) => {
                        let pairing_id = random_hex_128();
                        let (decision_tx, decision_rx) = oneshot::channel();
                        let view = PendingPairingView {
                            pairing_id: pairing_id.clone(),
                            peer_id_short: peer_id.short(),
                            peer_id_grouped: peer_id.grouped(),
                            peer_id: peer_id.clone(),
                            peer_name: peer_hello.device_name.clone(),
                            verification_code: stream.pairing_code().to_string(),
                            direction: PairingDirection::Outbound,
                            local_confirmed: false,
                            remote_confirmed: false,
                            expires_at_ms: unix_now_ms()
                                .saturating_add(self.config.pairing_timeout.as_millis() as u64),
                        };

                        {
                            let mut st = self.lock_state();
                            st.pairings.insert(
                                pairing_id.clone(),
                                PendingPairingEntry {
                                    view,
                                    decision_tx: Some(decision_tx),
                                },
                            );
                        }

                        let eng = Arc::clone(self);
                        let pid = pairing_id.clone();
                        let peer_name = peer_hello.device_name;
                        tokio::spawn(async move {
                            eng.run_pairing_ceremony(
                                pid,
                                stream,
                                conn_guard,
                                None,
                                peer_name,
                                addr,
                                ConnectionDirection::Outbound,
                                decision_rx,
                            )
                            .await;
                        });

                        Ok(ConnectOutcome::PairingRequired {
                            peer_id,
                            pairing_id,
                        })
                    }
                    Message::Reject(r) => {
                        stream.shutdown().await;
                        Err(CoreError::PeerRejected(r.reason))
                    }
                    _ => {
                        let _ = stream
                            .send_message(Message::Reject(RejectPayload {
                                reason: RejectReason::ProtocolError,
                            }))
                            .await;
                        stream.shutdown().await;
                        Err(CoreError::InvalidInput(
                            "esperado pair_pending após hello".to_string(),
                        ))
                    }
                }
            }
        }
    }

    async fn handle_inbound_connection(
        self: Arc<Self>,
        tcp: TcpStream,
        peer_addr: SocketAddr,
        conn_guard: ConnectionGuard,
        hs_permit: tokio::sync::OwnedSemaphorePermit,
    ) {
        let mut stream = match self.tls.accept(tcp).await {
            Ok(s) => s,
            Err(err) => {
                debug!("handshake TLS de entrada falhou: {err}");
                return;
            }
        };
        drop(hs_permit);

        let peer_id = stream.peer_id().clone();
        if &peer_id == self.local_device_id() {
            let _ = stream
                .send_message(Message::Reject(RejectPayload {
                    reason: RejectReason::SelfConnection,
                }))
                .await;
            stream.shutdown().await;
            return;
        }

        let first = match timeout(HELLO_TIMEOUT, stream.recv_message()).await {
            Ok(Ok(env)) => env,
            Ok(Err(CoreError::Protocol(aurora_protocol::ProtocolError::UnsupportedVersion(_)))) => {
                let _ = stream
                    .send_message(Message::Reject(RejectPayload {
                        reason: RejectReason::UnsupportedVersion,
                    }))
                    .await;
                stream.shutdown().await;
                return;
            }
            _ => {
                let _ = stream
                    .send_message(Message::Reject(RejectPayload {
                        reason: RejectReason::ProtocolError,
                    }))
                    .await;
                stream.shutdown().await;
                return;
            }
        };

        let client_hello = match first.body {
            Message::Hello(h) => h,
            Message::Reject(_) => {
                stream.shutdown().await;
                return;
            }
            _ => {
                let _ = stream
                    .send_message(Message::Reject(RejectPayload {
                        reason: RejectReason::ProtocolError,
                    }))
                    .await;
                stream.shutdown().await;
                return;
            }
        };

        match client_hello.intent {
            HandshakeIntent::Session => {
                let (local_name, trusted) = {
                    let st = self.lock_state();
                    (
                        st.settings.device_name.clone(),
                        st.registry.is_trusted(&peer_id),
                    )
                };

                if !trusted {
                    warn!(peer_short = %peer_id.short(), "tentativa de sessão não autorizada bloqueada");
                    self.push_notice(
                        NoticeLevel::Warning,
                        format!(
                            "Tentativa de conexão não autorizada bloqueada ({})",
                            peer_id.short()
                        ),
                    );
                    let _ = stream
                        .send_message(Message::Reject(RejectPayload {
                            reason: RejectReason::NotTrusted,
                        }))
                        .await;
                    stream.shutdown().await;
                    return;
                }

                if stream
                    .send_message(Message::Hello(HelloPayload {
                        device_name: local_name,
                        app_version: self.config.app_version.clone(),
                        intent: HandshakeIntent::Session,
                    }))
                    .await
                    .is_err()
                {
                    return;
                }

                let session_id = random_hex_128();
                if stream
                    .send_message(Message::SessionAccept(SessionAcceptPayload {
                        session_id: session_id.clone(),
                    }))
                    .await
                    .is_err()
                {
                    return;
                }

                self.spawn_authenticated_session(
                    stream,
                    conn_guard,
                    client_hello.device_name,
                    session_id,
                    peer_addr,
                    ConnectionDirection::Inbound,
                )
                .await;
            }
            HandshakeIntent::Pair => {
                let (local_name, allow_pairing) = {
                    let st = self.lock_state();
                    (st.settings.device_name.clone(), st.settings.allow_pairing)
                };

                if !allow_pairing {
                    let _ = stream
                        .send_message(Message::Reject(RejectPayload {
                            reason: RejectReason::PairingUnavailable,
                        }))
                        .await;
                    stream.shutdown().await;
                    return;
                }

                let inbound_guard = match self.pairing_gate.try_acquire_inbound() {
                    Ok(g) => g,
                    Err(reason) => {
                        warn!(peer_short = %peer_id.short(), ?reason, "pedido de pareamento limitado");
                        let _ = stream
                            .send_message(Message::Reject(RejectPayload { reason }))
                            .await;
                        stream.shutdown().await;
                        return;
                    }
                };

                if stream
                    .send_message(Message::Hello(HelloPayload {
                        device_name: local_name,
                        app_version: self.config.app_version.clone(),
                        intent: HandshakeIntent::Pair,
                    }))
                    .await
                    .is_err()
                {
                    return;
                }

                if stream
                    .send_message(Message::PairPending(EmptyPayload::default()))
                    .await
                    .is_err()
                {
                    return;
                }

                let pairing_id = random_hex_128();
                let (decision_tx, decision_rx) = oneshot::channel();
                let view = PendingPairingView {
                    pairing_id: pairing_id.clone(),
                    peer_id_short: peer_id.short(),
                    peer_id_grouped: peer_id.grouped(),
                    peer_id: peer_id.clone(),
                    peer_name: client_hello.device_name.clone(),
                    verification_code: stream.pairing_code().to_string(),
                    direction: PairingDirection::Inbound,
                    local_confirmed: false,
                    remote_confirmed: false,
                    expires_at_ms: unix_now_ms()
                        .saturating_add(self.config.pairing_timeout.as_millis() as u64),
                };

                {
                    let mut st = self.lock_state();
                    st.pairings.insert(
                        pairing_id.clone(),
                        PendingPairingEntry {
                            view,
                            decision_tx: Some(decision_tx),
                        },
                    );
                    st.push_notice(
                        NoticeLevel::Info,
                        format!("Solicitação de pareamento recebida ({})", peer_id.short()),
                    );
                }
                self.notify_changed();

                self.run_pairing_ceremony(
                    pairing_id,
                    stream,
                    conn_guard,
                    Some(inbound_guard),
                    client_hello.device_name,
                    peer_addr,
                    ConnectionDirection::Inbound,
                    decision_rx,
                )
                .await;
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_pairing_ceremony(
        self: Arc<Self>,
        pairing_id: String,
        mut stream: AuthenticatedStream,
        conn_guard: ConnectionGuard,
        _inbound_guard: Option<InboundPairingGuard>,
        peer_name: String,
        peer_addr: SocketAddr,
        direction: ConnectionDirection,
        mut decision_rx: oneshot::Receiver<bool>,
    ) {
        let peer_id = stream.peer_id().clone();
        let deadline = tokio::time::Instant::now() + self.config.pairing_timeout;
        let mut local_confirmed = false;
        let mut remote_confirmed = false;
        let mut decision_open = true;

        loop {
            if local_confirmed && remote_confirmed {
                break;
            }

            tokio::select! {
                _ = self.shutdown_token.cancelled() => {
                    self.clear_pairing(&pairing_id);
                    stream.shutdown().await;
                    return;
                }
                _ = tokio::time::sleep_until(deadline) => {
                    let _ = stream
                        .send_message(Message::Reject(RejectPayload {
                            reason: RejectReason::Timeout,
                        }))
                        .await;
                    stream.shutdown().await;
                    self.clear_pairing(&pairing_id);
                    self.push_notice(
                        NoticeLevel::Warning,
                        format!("Tempo de pareamento esgotado ({})", peer_id.short()),
                    );
                    return;
                }
                decision = &mut decision_rx, if decision_open => {
                    decision_open = false;
                    match decision {
                        Ok(true) => {
                            local_confirmed = true;
                            if stream
                                .send_message(Message::PairConfirm(EmptyPayload::default()))
                                .await
                                .is_err()
                            {
                                self.clear_pairing(&pairing_id);
                                return;
                            }
                            self.notify_changed();
                        }
                        _ => {
                            let _ = stream
                                .send_message(Message::Reject(RejectPayload {
                                    reason: RejectReason::UserRejected,
                                }))
                                .await;
                            stream.shutdown().await;
                            self.clear_pairing(&pairing_id);
                            self.push_notice(
                                NoticeLevel::Info,
                                format!("Pareamento recusado ({})", peer_id.short()),
                            );
                            return;
                        }
                    }
                }
                inbound = stream.recv_message() => {
                    match inbound {
                        Ok(env) => match env.body {
                            Message::PairConfirm(_) if !remote_confirmed => {
                                remote_confirmed = true;
                                {
                                    let mut st = self.lock_state();
                                    if let Some(entry) = st.pairings.get_mut(&pairing_id) {
                                        entry.view.remote_confirmed = true;
                                    }
                                }
                                self.notify_changed();
                            }
                            Message::Reject(r) => {
                                stream.shutdown().await;
                                self.clear_pairing(&pairing_id);
                                self.push_notice(
                                    NoticeLevel::Warning,
                                    format!(
                                        "Pareamento não concluído ({}): {:?}",
                                        peer_id.short(),
                                        r.reason
                                    ),
                                );
                                return;
                            }
                            _ => {
                                let _ = stream
                                    .send_message(Message::Reject(RejectPayload {
                                        reason: RejectReason::ProtocolError,
                                    }))
                                    .await;
                                stream.shutdown().await;
                                self.clear_pairing(&pairing_id);
                                return;
                            }
                        },
                        Err(_) => {
                            self.clear_pairing(&pairing_id);
                            self.push_notice(
                                NoticeLevel::Warning,
                                format!("Conexão interrompida durante o pareamento ({})", peer_id.short()),
                            );
                            return;
                        }
                    }
                }
            }
        }

        // Both sides explicitly confirmed the SAS code: persist trust before opening session.
        let store_addr = match direction {
            ConnectionDirection::Outbound => Some(peer_addr),
            ConnectionDirection::Inbound => {
                // Prefer the peer's advertised mDNS port when inbound socket uses an ephemeral port.
                let st = self.lock_state();
                st.discovered
                    .get(&peer_id)
                    .map(|d| SocketAddr::new(peer_addr.ip(), d.port))
            }
        };

        let persist_res = {
            let mut st = self.lock_state();
            st.pairings.remove(&pairing_id);
            st.registry.upsert_trusted(
                peer_id.clone(),
                peer_name.clone(),
                unix_now_ms(),
                store_addr,
            )
        };
        if let Err(err) = persist_res {
            warn!("falha ao salvar dispositivo confiável: {err}");
            let _ = stream
                .send_message(Message::Reject(RejectPayload {
                    reason: RejectReason::ProtocolError,
                }))
                .await;
            stream.shutdown().await;
            self.notify_changed();
            return;
        }

        let session_id = match direction {
            ConnectionDirection::Inbound => {
                let sid = random_hex_128();
                if stream
                    .send_message(Message::SessionAccept(SessionAcceptPayload {
                        session_id: sid.clone(),
                    }))
                    .await
                    .is_err()
                {
                    self.notify_changed();
                    return;
                }
                sid
            }
            ConnectionDirection::Outbound => {
                match timeout(HELLO_TIMEOUT, stream.recv_message()).await {
                    Ok(Ok(env)) => match env.body {
                        Message::SessionAccept(acc) => acc.session_id,
                        _ => {
                            stream.shutdown().await;
                            self.notify_changed();
                            return;
                        }
                    },
                    _ => {
                        stream.shutdown().await;
                        self.notify_changed();
                        return;
                    }
                }
            }
        };

        info!(peer_short = %peer_id.short(), "pareamento confirmado e sessão iniciada");
        self.push_notice(
            NoticeLevel::Success,
            format!("Dispositivo pareado com sucesso ({})", peer_id.short()),
        );

        self.spawn_authenticated_session(
            stream, conn_guard, peer_name, session_id, peer_addr, direction,
        )
        .await;
    }

    fn clear_pairing(&self, pairing_id: &str) {
        let mut st = self.lock_state();
        st.pairings.remove(pairing_id);
        drop(st);
        self.notify_changed();
    }

    async fn spawn_authenticated_session(
        self: &Arc<Self>,
        mut stream: AuthenticatedStream,
        conn_guard: ConnectionGuard,
        peer_name: String,
        session_id: String,
        remote_addr: SocketAddr,
        direction: ConnectionDirection,
    ) {
        let peer_id = stream.peer_id().clone();
        let local_id = self.local_device_id().clone();
        let new_initiator = match direction {
            ConnectionDirection::Outbound => local_id.clone(),
            ConnectionDirection::Inbound => peer_id.clone(),
        };
        let preferred_initiator = if local_id <= peer_id {
            local_id
        } else {
            peer_id.clone()
        };

        let (cmd_tx, cmd_rx) = mpsc::channel::<GoodbyeReason>(4);
        let now_ms = unix_now_ms();
        let view = ActiveSessionView {
            session_id: session_id.clone(),
            peer_id_short: peer_id.short(),
            peer_id: peer_id.clone(),
            peer_name: peer_name.clone(),
            remote_addr: remote_addr.to_string(),
            direction,
            connected_at_ms: now_ms,
            last_rtt_ms: None,
            smoothed_rtt_ms: None,
        };

        let (accepted, replaced_tx, instance_num) = {
            let mut st = self.lock_state();
            if let Some(rec) = st.reconnects.remove(&peer_id) {
                rec.cancel.cancel();
            }

            if let Some(existing) = st.sessions.get(&peer_id) {
                let same_initiator = existing.initiator_id == new_initiator;
                let new_wins = same_initiator || new_initiator == preferred_initiator;
                if !new_wins {
                    (false, None, 0)
                } else {
                    let prev = st.sessions.remove(&peer_id).map(|e| e.cmd_tx);
                    st.next_instance_num += 1;
                    let inst = st.next_instance_num;
                    st.sessions.insert(
                        peer_id.clone(),
                        ActiveSessionEntry {
                            instance_num: inst,
                            initiator_id: new_initiator,
                            view,
                            cmd_tx,
                        },
                    );
                    if direction == ConnectionDirection::Outbound {
                        let _ =
                            st.registry
                                .record_connected(&peer_id, &peer_name, now_ms, remote_addr);
                    }
                    (true, prev, inst)
                }
            } else {
                st.next_instance_num += 1;
                let inst = st.next_instance_num;
                st.sessions.insert(
                    peer_id.clone(),
                    ActiveSessionEntry {
                        instance_num: inst,
                        initiator_id: new_initiator,
                        view,
                        cmd_tx,
                    },
                );
                if direction == ConnectionDirection::Outbound {
                    let _ = st
                        .registry
                        .record_connected(&peer_id, &peer_name, now_ms, remote_addr);
                }
                (true, None, inst)
            }
        };

        if let Some(old_tx) = replaced_tx {
            let _ = old_tx.send(GoodbyeReason::Replaced).await;
        }

        if !accepted {
            let _ = stream
                .send_message(Message::Goodbye(GoodbyePayload {
                    reason: GoodbyeReason::Replaced,
                }))
                .await;
            stream.shutdown().await;
            return;
        }

        info!(peer_short = %peer_id.short(), ?direction, "sessão autenticada ativa");
        self.push_notice(
            NoticeLevel::Success,
            format!("Conectado a {peer_name} ({})", peer_id.short()),
        );

        let eng = Arc::clone(self);
        tokio::spawn(async move {
            eng.run_session_loop(instance_num, peer_id, direction, stream, conn_guard, cmd_rx)
                .await;
        });
    }

    async fn run_session_loop(
        self: Arc<Self>,
        instance_num: u64,
        peer_id: DeviceId,
        direction: ConnectionDirection,
        stream: AuthenticatedStream,
        _conn_guard: ConnectionGuard,
        mut cmd_rx: mpsc::Receiver<GoodbyeReason>,
    ) {
        // Split reading onto a dedicated task feeding a bounded channel (backpressure = 32 frames)
        // while keeping frame sequence/rate-limiting inside AuthenticatedStream via split I/O?
        // Actually, `tokio::io::split` lets reader and writer run concurrently with independent
        // inbound/outbound sequence trackers and bounded channel! Let's use select! directly on
        // stream or split I/O cleanly. Let's inspect: in `select!`, `stream.recv_message()` is only
        // paused during `send_message` (which writes <=64 KiB locally with timeout), OR even better:
        // let's split `AuthenticatedStream` or run a reader task over the read half with its own
        // inbound sequence + TokenBucket feeding `mpsc::channel(INBOUND_FRAME_QUEUE)`!
        let (mut reader, mut writer) = split_authenticated_stream(stream);
        let (inbound_tx, mut inbound_rx) =
            mpsc::channel::<Result<aurora_protocol::Envelope, CoreError>>(INBOUND_FRAME_QUEUE);
        let reader_cancel = CancellationToken::new();
        let rc_clone = reader_cancel.clone();

        let reader_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = rc_clone.cancelled() => break,
                    res = reader.recv_message() => {
                        let is_err = res.is_err();
                        if inbound_tx.send(res).await.is_err() || is_err {
                            break;
                        }
                    }
                }
            }
        });

        let mut hb_ticker = tokio::time::interval(self.config.heartbeat_interval);
        hb_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut last_inbound = tokio::time::Instant::now();
        let mut next_ping_id: u64 = 1;
        let mut pending_ping: Option<(u64, Instant)> = None;
        let mut clean_disconnect = false;
        let mut disconnect_notice: Option<(NoticeLevel, String)> = None;

        loop {
            let loss_deadline = last_inbound + self.config.session_timeout;

            tokio::select! {
                _ = self.shutdown_token.cancelled() => {
                    let _ = writer.send_message(Message::Goodbye(GoodbyePayload {
                        reason: GoodbyeReason::Shutdown,
                    })).await;
                    clean_disconnect = true;
                    break;
                }
                maybe_cmd = cmd_rx.recv() => {
                    if let Some(reason) = maybe_cmd {
                        let _ = writer.send_message(Message::Goodbye(GoodbyePayload { reason })).await;
                    }
                    clean_disconnect = true;
                    break;
                }
                _ = tokio::time::sleep_until(loss_deadline) => {
                    warn!(peer_short = %peer_id.short(), "timeout de heartbeat; sessão perdida");
                    disconnect_notice = Some((
                        NoticeLevel::Warning,
                        format!("Conexão perdida com {}", peer_id.short()),
                    ));
                    break;
                }
                _ = hb_ticker.tick() => {
                    let id = next_ping_id;
                    next_ping_id = next_ping_id.wrapping_add(1);
                    pending_ping = Some((id, Instant::now()));
                    if writer.send_message(Message::Ping(PingPayload { id })).await.is_err() {
                        disconnect_notice = Some((
                            NoticeLevel::Warning,
                            format!("Falha ao enviar heartbeat para {}", peer_id.short()),
                        ));
                        break;
                    }
                }
                maybe_frame = inbound_rx.recv() => {
                    match maybe_frame {
                        Some(Ok(env)) => {
                            last_inbound = tokio::time::Instant::now();
                            match env.body {
                                Message::Ping(PingPayload { id }) => {
                                    if writer.send_message(Message::Pong(PongPayload { id })).await.is_err() {
                                        break;
                                    }
                                }
                                Message::Pong(PongPayload { id }) => {
                                    if let Some((expected_id, sent_at)) = pending_ping {
                                        if expected_id == id {
                                            pending_ping = None;
                                            let rtt_ms = sent_at.elapsed().as_secs_f64() * 1000.0;
                                            self.update_session_rtt(&peer_id, instance_num, rtt_ms);
                                        }
                                    }
                                }
                                Message::Goodbye(GoodbyePayload { reason }) => {
                                    clean_disconnect = true;
                                    if reason == GoodbyeReason::Revoked {
                                        let mut st = self.lock_state();
                                        let _ = st.registry.revoke(&peer_id);
                                        disconnect_notice = Some((
                                            NoticeLevel::Warning,
                                            format!(
                                                "Confiança revogada pelo dispositivo remoto ({})",
                                                peer_id.short()
                                            ),
                                        ));
                                    } else if reason != GoodbyeReason::Replaced {
                                        disconnect_notice = Some((
                                            NoticeLevel::Info,
                                            format!("Dispositivo {} desconectou", peer_id.short()),
                                        ));
                                    }
                                    break;
                                }
                                _ => {
                                    // Handshake messages are forbidden on an established session.
                                    warn!(peer_short = %peer_id.short(), "mensagem fora de fase encerrando sessão");
                                    clean_disconnect = true;
                                    disconnect_notice = Some((
                                        NoticeLevel::Error,
                                        format!("Violação de protocolo encerrada ({})", peer_id.short()),
                                    ));
                                    break;
                                }
                            }
                        }
                        Some(Err(err)) => {
                            warn!(peer_short = %peer_id.short(), "erro na leitura da sessão: {err}");
                            if matches!(err, CoreError::Protocol(_) | CoreError::RateLimited) {
                                clean_disconnect = true;
                                disconnect_notice = Some((
                                    NoticeLevel::Error,
                                    format!("Sessão encerrada por mensagem inválida ou excesso de taxa ({})", peer_id.short()),
                                ));
                            } else {
                                disconnect_notice = Some((
                                    NoticeLevel::Warning,
                                    format!("Desconexão inesperada ({})", peer_id.short()),
                                ));
                            }
                            break;
                        }
                        None => {
                            disconnect_notice = Some((
                                NoticeLevel::Warning,
                                format!("Desconexão inesperada ({})", peer_id.short()),
                            ));
                            break;
                        }
                    }
                }
            }
        }

        reader_cancel.cancel();
        reader_task.abort();

        let should_reconnect = {
            let mut st = self.lock_state();
            let was_current = st
                .sessions
                .get(&peer_id)
                .map(|s| s.instance_num == instance_num)
                .unwrap_or(false);
            if was_current {
                st.sessions.remove(&peer_id);
            }
            if let Some((lvl, msg)) = disconnect_notice {
                st.push_notice(lvl, msg);
            }
            was_current
                && !clean_disconnect
                && direction == ConnectionDirection::Outbound
                && st.settings.auto_reconnect
                && st.registry.is_trusted(&peer_id)
                && !self.shutdown_token.is_cancelled()
        };

        if should_reconnect {
            self.spawn_reconnect_worker(peer_id);
        } else {
            self.notify_changed();
        }
    }

    fn update_session_rtt(&self, peer_id: &DeviceId, instance_num: u64, rtt_ms: f64) {
        let updated = {
            let mut st = self.lock_state();
            if let Some(entry) = st.sessions.get_mut(peer_id) {
                if entry.instance_num == instance_num {
                    entry.view.last_rtt_ms = Some(rtt_ms);
                    let smoothed = match entry.view.smoothed_rtt_ms {
                        Some(prev) => prev * 0.7 + rtt_ms * 0.3,
                        None => rtt_ms,
                    };
                    entry.view.smoothed_rtt_ms = Some(smoothed);
                    true
                } else {
                    false
                }
            } else {
                false
            }
        };
        if updated {
            self.notify_changed();
        }
    }

    fn spawn_reconnect_worker(self: &Arc<Self>, peer_id: DeviceId) {
        let cancel = CancellationToken::new();
        {
            let mut st = self.lock_state();
            if let Some(prev) = st.reconnects.insert(
                peer_id.clone(),
                ReconnectEntry {
                    attempt: 1,
                    cancel: cancel.clone(),
                },
            ) {
                prev.cancel.cancel();
            }
        }
        self.notify_changed();

        let engine = Arc::clone(self);
        tokio::spawn(async move {
            for idx in 0..(MAX_RECONNECT_ATTEMPTS as usize) {
                let attempt_num = (idx + 1) as u32;
                {
                    let mut st = engine.lock_state();
                    if !st.settings.auto_reconnect
                        || !st.registry.is_trusted(&peer_id)
                        || st.sessions.contains_key(&peer_id)
                    {
                        st.reconnects.remove(&peer_id);
                        drop(st);
                        engine.notify_changed();
                        return;
                    }
                    if let Some(rec) = st.reconnects.get_mut(&peer_id) {
                        rec.attempt = attempt_num;
                    }
                }
                engine.notify_changed();

                let mult = RECONNECT_SCHEDULE_SECS.get(idx).copied().unwrap_or(30) as u32;
                let wait = engine.config.reconnect_base_unit.saturating_mul(mult);

                tokio::select! {
                    _ = engine.shutdown_token.cancelled() => return,
                    _ = cancel.cancelled() => return,
                    _ = tokio::time::sleep(wait) => {}
                }

                let target = {
                    let st = engine.lock_state();
                    if st.sessions.contains_key(&peer_id) || !st.registry.is_trusted(&peer_id) {
                        break;
                    }
                    st.discovered
                        .get(&peer_id)
                        .and_then(|d| d.addresses.first().map(|ip| SocketAddr::new(*ip, d.port)))
                        .or_else(|| st.registry.get(&peer_id).and_then(|t| t.last_known_addr))
                };

                if let Some(addr) = target {
                    if let Ok(valid) = validate_peer_addr(addr) {
                        if engine
                            .connect_internal(valid, Some(peer_id.clone()), false)
                            .await
                            .is_ok()
                        {
                            return;
                        }
                    }
                }
            }

            {
                let mut st = engine.lock_state();
                st.reconnects.remove(&peer_id);
                st.push_notice(
                    NoticeLevel::Warning,
                    format!(
                        "Não foi possível reconectar automaticamente a {}",
                        peer_id.short()
                    ),
                );
            }
            engine.notify_changed();
        });
    }

    fn push_notice(&self, level: NoticeLevel, message: impl Into<String>) {
        let mut st = self.lock_state();
        st.push_notice(level, message);
        drop(st);
        self.notify_changed();
    }

    fn notify_changed(&self) {
        let _ = self.events_tx.send(EngineEvent::SnapshotChanged);
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, MutableState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn random_hex_128() -> String {
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn describe_connection_error(err: &CoreError, peer: Option<&DeviceId>) -> String {
    let suffix = peer
        .map(|p| format!(" ({})", p.short()))
        .unwrap_or_default();
    match err {
        CoreError::AddressPolicyViolation => {
            "Conexão bloqueada: apenas endereços de rede local são permitidos".to_string()
        }
        CoreError::IdentityMismatch => {
            format!("Alerta de segurança: identidade divergente bloqueada{suffix}")
        }
        CoreError::SelfConnection => "Não é permitido conectar ao próprio dispositivo".to_string(),
        CoreError::Timeout => format!("Tempo esgotado ao conectar ao dispositivo{suffix}"),
        CoreError::PeerRejected(reason) => {
            format!("Conexão recusada pelo dispositivo remoto ({reason:?}){suffix}")
        }
        CoreError::ConnectionLimitExceeded => "Limite de conexões simultâneas atingido".to_string(),
        _ => format!("Falha de rede ao conectar{suffix}: {err}"),
    }
}

struct StreamReader {
    inner: tokio::io::ReadHalf<tokio_rustls::TlsStream<TcpStream>>,
    seq: aurora_protocol::SequenceTracker,
    rate_limiter: crate::transport::TokenBucket,
}

impl StreamReader {
    async fn recv_message(&mut self) -> Result<aurora_protocol::Envelope, CoreError> {
        use tokio::io::AsyncReadExt;
        let mut header = [0u8; 4];
        match self.inner.read_exact(&mut header).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(CoreError::ConnectionClosed);
            }
            Err(e) => return Err(CoreError::Io(e)),
        }

        if !self.rate_limiter.try_consume(1.0) {
            return Err(CoreError::RateLimited);
        }

        let payload_len = aurora_protocol::decode_frame_header(header)?;
        let mut payload = vec![0u8; payload_len];
        self.inner
            .read_exact(&mut payload)
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::UnexpectedEof => CoreError::ConnectionClosed,
                _ => CoreError::Io(e),
            })?;

        let envelope = aurora_protocol::decode_frame_payload(&payload)?;
        self.seq.accept_inbound(envelope.seq)?;
        Ok(envelope)
    }
}

struct StreamWriter {
    inner: tokio::io::WriteHalf<tokio_rustls::TlsStream<TcpStream>>,
    seq: aurora_protocol::SequenceTracker,
}

impl StreamWriter {
    async fn send_message(&mut self, body: Message) -> Result<(), CoreError> {
        use tokio::io::AsyncWriteExt;
        let seq = self.seq.next_outbound()?;
        let envelope = aurora_protocol::Envelope::new(seq, body);
        let frame = aurora_protocol::encode_frame(&envelope)?;

        timeout(aurora_protocol::FRAME_WRITE_TIMEOUT, async {
            self.inner.write_all(&frame).await?;
            self.inner.flush().await
        })
        .await
        .map_err(|_| CoreError::Timeout)?
        .map_err(CoreError::Io)
    }
}

fn split_authenticated_stream(stream: AuthenticatedStream) -> (StreamReader, StreamWriter) {
    let (tls_stream, seq, rate_limiter) = stream.into_parts();
    let (read_half, write_half) = tokio::io::split(tls_stream);
    let mut in_seq = aurora_protocol::SequenceTracker::new();
    for _ in 0..seq.inbound_expected() {
        let _ = in_seq.accept_inbound(in_seq.inbound_expected());
    }
    let mut out_seq = aurora_protocol::SequenceTracker::new();
    for _ in 0..seq.outbound_next() {
        let _ = out_seq.next_outbound();
    }

    (
        StreamReader {
            inner: read_half,
            seq: in_seq,
            rate_limiter,
        },
        StreamWriter {
            inner: write_half,
            seq: out_seq,
        },
    )
}
