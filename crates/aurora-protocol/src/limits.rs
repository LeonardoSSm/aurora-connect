use std::time::Duration;

/// Current wire protocol version.
pub const PROTOCOL_VERSION: u16 = 1;

/// ALPN identifier negotiated during the TLS 1.3 handshake.
pub const ALPN_PROTOCOL: &[u8] = b"aurora-connect/1";

/// Default TCP listening port for Aurora Connect.
pub const DEFAULT_PORT: u16 = 47_821;

/// Minimum allowed unprivileged TCP port.
pub const MIN_UNPRIVILEGED_PORT: u16 = 1024;

/// Minimum serialized JSON payload size in bytes.
pub const MIN_FRAME_BYTES: usize = 1;

/// Maximum serialized JSON payload size in bytes (64 KiB).
pub const MAX_FRAME_BYTES: usize = 65_536;

/// Length of a canonical Base32 (no-padding) SHA-256 device identifier.
pub const DEVICE_ID_LEN: usize = 52;

/// Maximum characters allowed in a device display name.
pub const MAX_DEVICE_NAME_CHARS: usize = 64;

/// Maximum characters allowed in an application version string.
pub const MAX_APP_VERSION_CHARS: usize = 32;

/// Exact hex character length of a session identifier (128-bit random).
pub const SESSION_ID_HEX_LEN: usize = 32;

/// Maximum simultaneous TCP/TLS connections per node.
pub const MAX_TOTAL_CONNECTIONS: usize = 32;

/// Maximum concurrent in-flight TLS handshakes.
pub const MAX_CONCURRENT_HANDSHAKES: usize = 8;

/// Maximum simultaneous connections from a single source IP address.
pub const MAX_CONNECTIONS_PER_IP: usize = 4;

/// Sustained inbound message rate per connection (frames per second).
pub const RATE_LIMIT_PER_SEC: f64 = 50.0;

/// Maximum inbound burst size per connection (frames).
pub const RATE_LIMIT_BURST: f64 = 100.0;

/// Bounded per-connection channel capacity for validated inbound frames.
pub const INBOUND_FRAME_QUEUE: usize = 32;

/// Bounded broadcast channel capacity for engine events.
pub const ENGINE_EVENT_QUEUE: usize = 256;

/// Maximum simultaneous pending inbound pairing requests.
pub const MAX_PENDING_INBOUND_PAIRINGS: usize = 1;

/// Maximum inbound pairing requests accepted per 60-second window.
pub const MAX_PAIRING_REQUESTS_PER_MIN: usize = 5;

/// Maximum persisted trusted devices.
pub const MAX_TRUSTED_DEVICES: usize = 64;

/// Maximum cached mDNS discovered devices.
pub const MAX_DISCOVERED_DEVICES: usize = 64;

/// Maximum duration allowed for a TLS 1.3 handshake.
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum duration allowed to receive the initial `hello` or `session_accept`.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum duration allowed to write and flush a single frame.
pub const FRAME_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Default interval between outbound `ping` frames on an active session.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(2);

/// Default inactivity window after which a session is declared lost.
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(6);

/// Maximum time waiting for both users to confirm a pairing code.
pub const PAIRING_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum automatic reconnection attempts after unexpected session loss.
pub const MAX_RECONNECT_ATTEMPTS: u32 = 10;
