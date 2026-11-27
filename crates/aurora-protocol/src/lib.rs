#![forbid(unsafe_code)]

pub mod framing;
pub mod limits;
pub mod sequence;
pub mod types;

pub use framing::{decode_frame_header, decode_frame_payload, encode_frame};
pub use limits::*;
pub use sequence::SequenceTracker;
pub use types::{
    sanitize_device_name, validate_app_version, validate_device_name, validate_session_id,
    DeviceId, EmptyPayload, Envelope, GoodbyePayload, GoodbyeReason, HandshakeIntent, HelloPayload,
    Message, PingPayload, PongPayload, ProtocolError, RejectPayload, RejectReason,
    SessionAcceptPayload,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_valid_frames_and_enforces_sequence() {
        let mut sender_seq = SequenceTracker::new();
        let mut receiver_seq = SequenceTracker::new();

        for i in 0..5 {
            let seq = sender_seq.next_outbound().unwrap();
            assert_eq!(seq, i);
            let env = Envelope::new(
                seq,
                Message::Hello(HelloPayload {
                    device_name: "Estacao Aurora".to_string(),
                    app_version: "0.1.0".to_string(),
                    intent: HandshakeIntent::Session,
                }),
            );
            let raw = encode_frame(&env).unwrap();
            let len = decode_frame_header([raw[0], raw[1], raw[2], raw[3]]).unwrap();
            assert_eq!(len, raw.len() - 4);
            let decoded = decode_frame_payload(&raw[4..]).unwrap();
            receiver_seq.accept_inbound(decoded.seq).unwrap();
            assert_eq!(decoded, env);
        }

        // Replay of seq 0 or 4 must fail immediately.
        assert_eq!(
            receiver_seq.accept_inbound(0),
            Err(ProtocolError::InvalidSequence {
                expected: 5,
                actual: 0
            })
        );
        // Skipping seq 5 to 6 must also fail.
        assert_eq!(
            receiver_seq.accept_inbound(6),
            Err(ProtocolError::InvalidSequence {
                expected: 5,
                actual: 6
            })
        );
    }

    #[test]
    fn rejects_zero_and_oversized_frame_headers() {
        assert!(matches!(
            decode_frame_header(0u32.to_be_bytes()),
            Err(ProtocolError::FrameSizeOutOfBounds { size: 0, .. })
        ));
        let too_big = (MAX_FRAME_BYTES as u32) + 1;
        assert!(matches!(
            decode_frame_header(too_big.to_be_bytes()),
            Err(ProtocolError::FrameSizeOutOfBounds { .. })
        ));
    }

    #[test]
    fn rejects_unknown_fields_and_unknown_versions() {
        let unknown_ver = br#"{"v":2,"seq":0,"body":{"type":"future_msg","data":{"x":1}}}"#;
        assert_eq!(
            decode_frame_payload(unknown_ver),
            Err(ProtocolError::UnsupportedVersion(2))
        );

        let unknown_top_field =
            br#"{"v":1,"seq":0,"extra":true,"body":{"type":"pair_confirm","data":{}}}"#;
        assert!(matches!(
            decode_frame_payload(unknown_top_field),
            Err(ProtocolError::MalformedPayload(_))
        ));

        let unknown_inner_field =
            br#"{"v":1,"seq":0,"body":{"type":"pair_confirm","data":{"cmd":"calc.exe"}}}"#;
        assert!(matches!(
            decode_frame_payload(unknown_inner_field),
            Err(ProtocolError::MalformedPayload(_))
        ));
    }

    #[test]
    fn validates_device_id_and_text_fields() {
        let valid_id = "A".repeat(DEVICE_ID_LEN);
        let parsed = DeviceId::parse_normalized(&format!("aaaa-{}", &valid_id[4..])).unwrap();
        assert_eq!(parsed.as_str(), valid_id);
        assert_eq!(parsed.short(), "AAAA-AAAA");

        assert!(DeviceId::from_canonical("SHORT".to_string()).is_err());
        assert!(DeviceId::from_canonical("1".repeat(DEVICE_ID_LEN)).is_err()); // '1' not in RFC4648 base32

        assert!(validate_device_name("Notebook Principal").is_ok());
        assert!(validate_device_name("").is_err());
        assert!(validate_device_name(" leading").is_err());
        assert!(validate_device_name("bad\u{0007}char").is_err());
        assert!(validate_device_name(&"x".repeat(MAX_DEVICE_NAME_CHARS + 1)).is_err());

        assert!(validate_session_id("0123456789abcdef0123456789abcdef").is_ok());
        assert!(validate_session_id("UPPERCASE789abcdef0123456789abcd").is_err());
        assert!(validate_session_id("short").is_err());
    }
}
