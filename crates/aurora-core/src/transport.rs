use std::io::ErrorKind;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aurora_protocol::{
    decode_frame_header, decode_frame_payload, encode_frame, DeviceId, Envelope, Message,
    SequenceTracker, ALPN_PROTOCOL, FRAME_WRITE_TIMEOUT, RATE_LIMIT_BURST, RATE_LIMIT_PER_SEC,
    TLS_HANDSHAKE_TIMEOUT,
};
use rustls::client::Resumption;
use rustls::crypto::{ring as ring_provider, CryptoProvider};
use rustls::pki_types::{ServerName, UnixTime};
use rustls::{ClientConfig, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};
use zeroize::Zeroizing;

use crate::auth::{
    derive_pairing_code, extract_verified_peer_id, DeviceIdentity, MutualClientVerifier,
    PinnedServerVerifier, TLS_SERVER_NAME,
};
use crate::error::CoreError;

/// Monotonic token-bucket rate limiter protecting a connection against frame floods.
#[derive(Debug)]
pub struct TokenBucket {
    rate_per_sec: f64,
    burst: f64,
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    pub fn new(rate_per_sec: f64, burst: f64) -> Self {
        Self {
            rate_per_sec,
            burst,
            tokens: burst,
            last_refill: Instant::now(),
        }
    }

    pub fn try_consume(&mut self, amount: f64) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;
        self.tokens = (self.tokens + elapsed * self.rate_per_sec).min(self.burst);
        if self.tokens >= amount {
            self.tokens -= amount;
            true
        } else {
            false
        }
    }
}

/// Builder for mutually-authenticated TLS 1.3 server and client endpoints.
pub struct TlsEndpoint {
    identity: Arc<DeviceIdentity>,
    provider: Arc<CryptoProvider>,
    acceptor: TlsAcceptor,
}

impl TlsEndpoint {
    pub fn new(identity: Arc<DeviceIdentity>) -> Result<Self, CoreError> {
        let provider = Arc::new(ring_provider::default_provider());
        let client_verifier = Arc::new(MutualClientVerifier::new(Arc::clone(&provider)));

        let mut server_cfg = ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(CoreError::Tls)?
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(
                vec![identity.certificate_der()],
                identity.clone_private_key_der()?,
            )
            .map_err(CoreError::Tls)?;

        server_cfg.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];
        server_cfg.send_tls13_tickets = 0;
        server_cfg.max_early_data_size = 0;

        Ok(Self {
            identity,
            provider,
            acceptor: TlsAcceptor::from(Arc::new(server_cfg)),
        })
    }

    pub fn identity(&self) -> &DeviceIdentity {
        &self.identity
    }

    /// Performs an inbound TLS 1.3 mutual-auth handshake with timeout and ALPN verification.
    pub async fn accept(&self, tcp: TcpStream) -> Result<AuthenticatedStream, CoreError> {
        let _ = tcp.set_nodelay(true);
        let tls = timeout(TLS_HANDSHAKE_TIMEOUT, self.acceptor.accept(tcp))
            .await
            .map_err(|_| CoreError::Timeout)?
            .map_err(CoreError::Io)?;

        let (_, server_conn) = tls.get_ref();
        verify_alpn(server_conn)?;
        let peer_id = peer_id_from_conn(server_conn)?;
        let pairing_code = derive_pairing_code(server_conn, self.identity.device_id(), &peer_id)?;

        Ok(AuthenticatedStream::new(
            TlsStream::Server(tls),
            peer_id,
            pairing_code,
        ))
    }

    /// Performs an outbound TLS 1.3 mutual-auth handshake, optionally pinning `expected_peer`.
    pub async fn connect(
        &self,
        tcp: TcpStream,
        expected_peer: Option<DeviceId>,
    ) -> Result<AuthenticatedStream, CoreError> {
        let _ = tcp.set_nodelay(true);
        let server_verifier = Arc::new(PinnedServerVerifier::new(
            expected_peer.clone(),
            Arc::clone(&self.provider),
        ));

        let mut client_cfg = ClientConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(CoreError::Tls)?
            .dangerous()
            .with_custom_certificate_verifier(server_verifier)
            .with_client_auth_cert(
                vec![self.identity.certificate_der()],
                self.identity.clone_private_key_der()?,
            )
            .map_err(CoreError::Tls)?;

        client_cfg.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];
        client_cfg.resumption = Resumption::disabled();
        client_cfg.enable_early_data = false;

        let connector = TlsConnector::from(Arc::new(client_cfg));
        let server_name = ServerName::try_from(TLS_SERVER_NAME)
            .map_err(|e| CoreError::Crypto(format!("SNI inválido: {e}")))?;

        let tls = timeout(TLS_HANDSHAKE_TIMEOUT, connector.connect(server_name, tcp))
            .await
            .map_err(|_| CoreError::Timeout)?
            .map_err(|io_err| {
                if io_err
                    .to_string()
                    .contains("ApplicationVerificationFailure")
                {
                    CoreError::IdentityMismatch
                } else {
                    CoreError::Io(io_err)
                }
            })?;

        let (_, client_conn) = tls.get_ref();
        verify_alpn(client_conn)?;
        let peer_id = peer_id_from_conn(client_conn)?;
        if let Some(expected) = &expected_peer {
            if &peer_id != expected {
                return Err(CoreError::IdentityMismatch);
            }
        }
        let pairing_code = derive_pairing_code(client_conn, self.identity.device_id(), &peer_id)?;

        Ok(AuthenticatedStream::new(
            TlsStream::Client(tls),
            peer_id,
            pairing_code,
        ))
    }
}

fn verify_alpn(conn: &rustls::CommonState) -> Result<(), CoreError> {
    if conn.alpn_protocol() != Some(ALPN_PROTOCOL) {
        return Err(CoreError::Crypto(
            "protocolo ALPN não negociado ou incompatível".to_string(),
        ));
    }
    Ok(())
}

fn peer_id_from_conn(conn: &rustls::CommonState) -> Result<DeviceId, CoreError> {
    let certs = conn
        .peer_certificates()
        .ok_or_else(|| CoreError::Crypto("par não apresentou certificado".to_string()))?;
    let (first, rest) = certs
        .split_first()
        .ok_or_else(|| CoreError::Crypto("cadeia de certificados vazia".to_string()))?;
    extract_verified_peer_id(first, rest, UnixTime::now()).map_err(CoreError::Tls)
}

/// Authenticated TLS 1.3 framed stream enforcing frame size bounds, strict
/// monotonic sequence numbers, write timeouts, and inbound rate limits.
pub struct AuthenticatedStream {
    inner: TlsStream<TcpStream>,
    peer_id: DeviceId,
    pairing_code: Zeroizing<String>,
    seq: SequenceTracker,
    rate_limiter: TokenBucket,
}

impl AuthenticatedStream {
    fn new(
        inner: TlsStream<TcpStream>,
        peer_id: DeviceId,
        pairing_code: Zeroizing<String>,
    ) -> Self {
        Self {
            inner,
            peer_id,
            pairing_code,
            seq: SequenceTracker::new(),
            rate_limiter: TokenBucket::new(RATE_LIMIT_PER_SEC, RATE_LIMIT_BURST),
        }
    }

    pub fn peer_id(&self) -> &DeviceId {
        &self.peer_id
    }

    pub fn pairing_code(&self) -> &str {
        self.pairing_code.as_str()
    }

    /// Sends a single typed protocol message with the next monotonic sequence number.
    pub async fn send_message(&mut self, body: Message) -> Result<(), CoreError> {
        let seq = self.seq.next_outbound()?;
        let envelope = Envelope::new(seq, body);
        let frame = encode_frame(&envelope)?;

        timeout(FRAME_WRITE_TIMEOUT, async {
            self.inner.write_all(&frame).await?;
            self.inner.flush().await
        })
        .await
        .map_err(|_| CoreError::Timeout)?
        .map_err(CoreError::Io)
    }

    /// Reads, rate-limits, decodes, validates, and sequence-checks one inbound frame.
    pub async fn recv_message(&mut self) -> Result<Envelope, CoreError> {
        let mut header = [0u8; 4];
        match self.inner.read_exact(&mut header).await {
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::UnexpectedEof => {
                return Err(CoreError::ConnectionClosed);
            }
            Err(e) => return Err(CoreError::Io(e)),
        }

        if !self.rate_limiter.try_consume(1.0) {
            return Err(CoreError::RateLimited);
        }

        let payload_len = decode_frame_header(header)?;
        let mut payload = vec![0u8; payload_len];
        self.inner
            .read_exact(&mut payload)
            .await
            .map_err(|e| match e.kind() {
                ErrorKind::UnexpectedEof => CoreError::ConnectionClosed,
                _ => CoreError::Io(e),
            })?;

        let envelope = decode_frame_payload(&payload)?;
        self.seq.accept_inbound(envelope.seq)?;
        Ok(envelope)
    }

    pub async fn shutdown(&mut self) {
        let _ = timeout(Duration::from_millis(500), self.inner.shutdown()).await;
    }

    pub(crate) fn into_parts(self) -> (TlsStream<TcpStream>, SequenceTracker, TokenBucket) {
        (self.inner, self.seq, self.rate_limiter)
    }
}
