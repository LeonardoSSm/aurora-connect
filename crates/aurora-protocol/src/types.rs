use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::limits::{
    DEVICE_ID_LEN, MAX_APP_VERSION_CHARS, MAX_DEVICE_NAME_CHARS, PROTOCOL_VERSION,
    SESSION_ID_HEX_LEN,
};

/// Errors produced when encoding, decoding or validating protocol frames.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("frame size {size} bytes is outside allowed bounds (1..={max})")]
    FrameSizeOutOfBounds { size: usize, max: usize },

    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(u16),

    #[error("malformed frame payload: {0}")]
    MalformedPayload(String),

    #[error("invalid sequence number: expected {expected}, got {actual}")]
    InvalidSequence { expected: u64, actual: u64 },

    #[error("sequence number overflow")]
    SequenceOverflow,

    #[error("invalid device id")]
    InvalidDeviceId,

    #[error("invalid field '{field}': {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
}

/// Canonical device identifier: 52 uppercase RFC 4648 Base32 characters
/// encoding the SHA-256 digest of the device's Ed25519 SubjectPublicKeyInfo.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId(String);

impl DeviceId {
    /// Parses and validates a canonical 52-character Base32 device identifier.
    /// Hyphens and whitespace are stripped, and ASCII letters are uppercased
    /// before validation so user-copied grouped IDs are accepted safely.
    pub fn parse_normalized(input: &str) -> Result<Self, ProtocolError> {
        let cleaned: String = input
            .chars()
            .filter(|c| !c.is_ascii_whitespace() && *c != '-')
            .map(|c| c.to_ascii_uppercase())
            .collect();
        Self::from_canonical(cleaned)
    }

    /// Validates a strict canonical 52-character uppercase Base32 string.
    pub fn from_canonical(s: String) -> Result<Self, ProtocolError> {
        if s.len() != DEVICE_ID_LEN {
            return Err(ProtocolError::InvalidDeviceId);
        }
        if !s.bytes().all(|b| matches!(b, b'A'..=b'Z' | b'2'..=b'7')) {
            return Err(ProtocolError::InvalidDeviceId);
        }
        Ok(Self(s))
    }

    /// Full 52-character canonical representation.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Short 8-character representation (`ABCD-EFGH`) safe for logs and badges.
    pub fn short(&self) -> String {
        format!("{}-{}", &self.0[0..4], &self.0[4..8])
    }

    /// Full human-readable representation grouped in blocks of 4 characters.
    pub fn grouped(&self) -> String {
        self.0
            .as_bytes()
            .chunks(4)
            .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("-")
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DeviceId({})", self.short())
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for DeviceId {
    type Err = ProtocolError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_canonical(s.to_string())
    }
}

impl Serialize for DeviceId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for DeviceId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::from_canonical(raw).map_err(serde::de::Error::custom)
    }
}

/// Wire envelope wrapping every protocol message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub v: u16,
    pub seq: u64,
    pub body: Message,
}

impl Envelope {
    pub fn new(seq: u64, body: Message) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            seq,
            body,
        }
    }

    /// Validates protocol version and all message fields strictly.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.v != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.v));
        }
        self.body.validate()
    }
}

/// Purpose declared during the initial `hello` exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandshakeIntent {
    Pair,
    Session,
}

/// Explicit rejection reasons during handshake or pairing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    NotTrusted,
    Busy,
    UnsupportedVersion,
    PairingUnavailable,
    RateLimited,
    UserRejected,
    Timeout,
    IdentityMismatch,
    ProtocolError,
    SelfConnection,
}

/// Orderly session termination reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GoodbyeReason {
    User,
    Shutdown,
    Revoked,
    Replaced,
}

/// Strict empty object payload (`{}`) rejecting unknown properties.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmptyPayload {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloPayload {
    pub device_name: String,
    pub app_version: String,
    pub intent: HandshakeIntent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionAcceptPayload {
    pub session_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RejectPayload {
    pub reason: RejectReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PingPayload {
    pub id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PongPayload {
    pub id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GoodbyePayload {
    pub reason: GoodbyeReason,
}

/// Typed Aurora Connect v1 messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum Message {
    Hello(HelloPayload),
    PairPending(EmptyPayload),
    PairConfirm(EmptyPayload),
    SessionAccept(SessionAcceptPayload),
    Reject(RejectPayload),
    Ping(PingPayload),
    Pong(PongPayload),
    Goodbye(GoodbyePayload),
}

impl Message {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Hello(_) => "hello",
            Self::PairPending(_) => "pair_pending",
            Self::PairConfirm(_) => "pair_confirm",
            Self::SessionAccept(_) => "session_accept",
            Self::Reject(_) => "reject",
            Self::Ping(_) => "ping",
            Self::Pong(_) => "pong",
            Self::Goodbye(_) => "goodbye",
        }
    }

    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Hello(h) => {
                validate_device_name(&h.device_name)?;
                validate_app_version(&h.app_version)?;
                Ok(())
            }
            Self::SessionAccept(s) => validate_session_id(&s.session_id),
            Self::PairPending(_)
            | Self::PairConfirm(_)
            | Self::Reject(_)
            | Self::Ping(_)
            | Self::Pong(_)
            | Self::Goodbye(_) => Ok(()),
        }
    }
}

/// Validates a device name: 1..=64 Unicode scalar values, no control chars,
/// and no leading/trailing whitespace.
pub fn validate_device_name(name: &str) -> Result<(), ProtocolError> {
    let count = name.chars().count();
    if count == 0 || count > MAX_DEVICE_NAME_CHARS {
        return Err(ProtocolError::InvalidField {
            field: "device_name",
            reason: "length must be between 1 and 64 characters",
        });
    }
    if name.trim() != name {
        return Err(ProtocolError::InvalidField {
            field: "device_name",
            reason: "must not contain leading or trailing whitespace",
        });
    }
    if name.chars().any(|c| c.is_control()) {
        return Err(ProtocolError::InvalidField {
            field: "device_name",
            reason: "must not contain control characters",
        });
    }
    Ok(())
}

/// Sanitizes untrusted display strings (such as mDNS TXT names or OS hostnames)
/// into a valid device name, returning `None` if nothing usable remains.
pub fn sanitize_device_name(raw: &str) -> Option<String> {
    let filtered: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(MAX_DEVICE_NAME_CHARS)
        .collect::<String>()
        .trim()
        .to_string();

    if filtered.is_empty() {
        None
    } else {
        Some(filtered)
    }
}

/// Validates an application version string: 1..=32 visible ASCII characters.
pub fn validate_app_version(version: &str) -> Result<(), ProtocolError> {
    let len = version.len();
    if len == 0 || len > MAX_APP_VERSION_CHARS {
        return Err(ProtocolError::InvalidField {
            field: "app_version",
            reason: "length must be between 1 and 32 characters",
        });
    }
    if !version.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
        return Err(ProtocolError::InvalidField {
            field: "app_version",
            reason: "must contain only visible ASCII characters",
        });
    }
    Ok(())
}

/// Validates a 32-character lowercase hexadecimal session identifier.
pub fn validate_session_id(session_id: &str) -> Result<(), ProtocolError> {
    if session_id.len() != SESSION_ID_HEX_LEN {
        return Err(ProtocolError::InvalidField {
            field: "session_id",
            reason: "must be exactly 32 hexadecimal characters",
        });
    }
    if !session_id
        .bytes()
        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ProtocolError::InvalidField {
            field: "session_id",
            reason: "must contain only lowercase hexadecimal characters",
        });
    }
    Ok(())
}
