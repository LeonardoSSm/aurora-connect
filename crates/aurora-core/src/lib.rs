#![forbid(unsafe_code)]

pub mod auth;
pub mod discovery;
pub mod engine;
pub mod error;
pub mod network;
pub mod pairing;
pub mod platform;
pub mod registry;
pub mod session;
pub mod settings;
pub mod transport;

pub use aurora_protocol as protocol;
pub use auth::{device_id_from_spki_der, DeviceIdentity};
pub use discovery::{DiscoveredDevice, DEFAULT_MDNS_SERVICE_TYPE};
pub use engine::{Engine, EngineConfig, EngineEvent, EngineSnapshot};
pub use error::CoreError;
pub use network::{is_allowed_local_ip, local_lan_addresses, normalize_ip, validate_peer_addr};
pub use pairing::{PairingDirection, PendingPairingView};
pub use platform::{MemorySecretStore, SecretStore};
pub use registry::{DeviceRegistry, TrustedDevice};
pub use session::{
    ActiveSessionView, ConnectOutcome, ConnectionDirection, DiscoveredDeviceView, NoticeLevel,
    NoticeView, PeerConnectionState, TrustedDeviceView,
};
pub use settings::{Settings, SettingsPatch, SettingsStore};
