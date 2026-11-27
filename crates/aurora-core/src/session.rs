use aurora_protocol::DeviceId;
use serde::{Deserialize, Serialize};

/// Direction of an authenticated session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionDirection {
    Inbound,
    Outbound,
}

/// High-level connectivity state for a peer device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerConnectionState {
    Disconnected,
    Connecting,
    Pairing,
    Connected,
    Reconnecting,
}

/// Public view of an active authenticated session, including live RTT telemetry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActiveSessionView {
    pub session_id: String,
    pub peer_id: DeviceId,
    pub peer_id_short: String,
    pub peer_name: String,
    pub remote_addr: String,
    pub direction: ConnectionDirection,
    pub connected_at_ms: u64,
    pub last_rtt_ms: Option<f64>,
    pub smoothed_rtt_ms: Option<f64>,
}

/// Public view of a discovered (unverified) peer on the LAN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredDeviceView {
    pub device_id: DeviceId,
    pub device_id_short: String,
    pub device_id_grouped: String,
    pub device_name: String,
    pub addresses: Vec<String>,
    pub port: u16,
    pub last_seen_ms: u64,
    pub verified: bool,
    pub trusted: bool,
    pub connection_state: PeerConnectionState,
}

/// Public view of a persisted trusted device and its current session state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrustedDeviceView {
    pub device_id: DeviceId,
    pub device_id_short: String,
    pub device_id_grouped: String,
    pub device_name: String,
    pub paired_at_ms: u64,
    pub last_connected_ms: Option<u64>,
    pub last_known_addr: Option<String>,
    pub connection_state: PeerConnectionState,
    pub reconnect_attempt: Option<u32>,
    pub session: Option<ActiveSessionView>,
}

/// Severity level for status/security notices surfaced to the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoticeLevel {
    Info,
    Success,
    Warning,
    Error,
}

/// User-facing status/security notice (contains no secrets or raw keys).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoticeView {
    pub id: u64,
    pub timestamp_ms: u64,
    pub level: NoticeLevel,
    pub message: String,
}

/// Result returned when initiating an outbound connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ConnectOutcome {
    SessionEstablished {
        peer_id: DeviceId,
        session_id: String,
    },
    PairingRequired {
        peer_id: DeviceId,
        pairing_id: String,
    },
}
