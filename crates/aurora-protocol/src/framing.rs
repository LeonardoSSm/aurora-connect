use serde::Deserialize;

use crate::limits::{MAX_FRAME_BYTES, MIN_FRAME_BYTES, PROTOCOL_VERSION};
use crate::types::{Envelope, ProtocolError};

#[derive(Deserialize)]
struct VersionProbe {
    v: u16,
}

/// Validates a 4-byte big-endian frame header before allocating a payload buffer.
pub fn decode_frame_header(header: [u8; 4]) -> Result<usize, ProtocolError> {
    let size = u32::from_be_bytes(header) as usize;
    if !(MIN_FRAME_BYTES..=MAX_FRAME_BYTES).contains(&size) {
        return Err(ProtocolError::FrameSizeOutOfBounds {
            size,
            max: MAX_FRAME_BYTES,
        });
    }
    Ok(size)
}

/// Validates and serializes an [`Envelope`] into a length-prefixed wire frame.
pub fn encode_frame(envelope: &Envelope) -> Result<Vec<u8>, ProtocolError> {
    envelope.validate()?;
    let json =
        serde_json::to_vec(envelope).map_err(|e| ProtocolError::MalformedPayload(e.to_string()))?;
    let size = json.len();
    if !(MIN_FRAME_BYTES..=MAX_FRAME_BYTES).contains(&size) {
        return Err(ProtocolError::FrameSizeOutOfBounds {
            size,
            max: MAX_FRAME_BYTES,
        });
    }
    let len_be = (size as u32).to_be_bytes();
    let mut frame = Vec::with_capacity(4 + size);
    frame.extend_from_slice(&len_be);
    frame.extend_from_slice(&json);
    Ok(frame)
}

/// Decodes and validates a UTF-8 JSON frame payload into an [`Envelope`].
pub fn decode_frame_payload(payload: &[u8]) -> Result<Envelope, ProtocolError> {
    let size = payload.len();
    if !(MIN_FRAME_BYTES..=MAX_FRAME_BYTES).contains(&size) {
        return Err(ProtocolError::FrameSizeOutOfBounds {
            size,
            max: MAX_FRAME_BYTES,
        });
    }

    let text = std::str::from_utf8(payload)
        .map_err(|_| ProtocolError::MalformedPayload("payload is not valid UTF-8".to_string()))?;

    // Probe `v` first so future protocol versions report UnsupportedVersion
    // even if their body schema has new message variants.
    if let Ok(probe) = serde_json::from_str::<VersionProbe>(text) {
        if probe.v != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(probe.v));
        }
    }

    let envelope: Envelope =
        serde_json::from_str(text).map_err(|e| ProtocolError::MalformedPayload(e.to_string()))?;
    envelope.validate()?;
    Ok(envelope)
}
