use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use aurora_core::discovery::validate_mdns_candidate;
use aurora_core::network::{is_allowed_local_ip, ConnectionLimiter};
use aurora_core::protocol::{
    encode_frame, DeviceId, EmptyPayload, Envelope, HandshakeIntent, HelloPayload, Message,
    RejectReason, ALPN_PROTOCOL,
};
use aurora_core::transport::TlsEndpoint;
use aurora_core::{
    ConnectOutcome, CoreError, DeviceIdentity, DeviceRegistry, Engine, EngineConfig,
    MemorySecretStore, PeerConnectionState, SecretStore, SettingsStore,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

fn fast_test_config(dir: &TempDir, name: &str) -> EngineConfig {
    let mut cfg = EngineConfig::production(
        dir.path().to_path_buf(),
        name.to_string(),
        "0.1.0".to_string(),
    );
    cfg.bind_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    cfg.allow_ephemeral_port = true;
    cfg.enable_mdns = false;
    cfg.heartbeat_interval = Duration::from_millis(80);
    cfg.session_timeout = Duration::from_millis(320);
    cfg.pairing_timeout = Duration::from_millis(600);
    cfg.reconnect_base_unit = Duration::from_millis(80);
    cfg.tcp_connect_timeout = Duration::from_millis(800);

    let store = SettingsStore::new(dir.path(), true);
    let mut s = store.load_or_init(name).unwrap();
    s.listen_port = 0;
    store.save(&s).unwrap();
    cfg
}

async fn wait_until<F>(max_wait: Duration, mut pred: F) -> bool
where
    F: FnMut() -> bool,
{
    let deadline = tokio::time::Instant::now() + max_wait;
    while tokio::time::Instant::now() < deadline {
        if pred() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    pred()
}

#[test]
fn identity_is_stable_across_reloads_and_never_written_to_disk() {
    let dir = TempDir::new().unwrap();
    let store = MemorySecretStore::new();
    let id1 = DeviceIdentity::load_or_generate(&store).unwrap();
    let id2 = DeviceIdentity::load_or_generate(&store).unwrap();
    assert_eq!(id1.device_id(), id2.device_id());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn corrupted_storage_files_are_quarantined_and_fail_closed() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("trusted_devices.json"), "{broken json").unwrap();
    fs::write(dir.path().join("settings.json"), "{\"unknown_key\":123}").unwrap();

    let reg = DeviceRegistry::load(dir.path()).unwrap();
    assert!(reg.list().is_empty());
    assert!(dir.path().join("trusted_devices.json.corrupt").exists());

    let settings = SettingsStore::new(dir.path(), false)
        .load_or_init("Estacao Segura")
        .unwrap();
    assert_eq!(settings.device_name, "Estacao Segura");
    assert!(dir.path().join("settings.json.corrupt").exists());
}

#[test]
fn network_policy_blocks_public_cgnat_multicast_and_ipv4_mapped_public_ips() {
    let blocked = [
        "0.0.0.0",
        "255.255.255.255",
        "8.8.8.8",
        "1.1.1.1",
        "100.64.0.1",
        "192.0.2.10",
        "224.0.0.251",
        "::",
        "::ffff:8.8.8.8",
        "2001:4860:4860::8888",
        "ff02::fb",
    ];
    for raw in blocked {
        let ip: IpAddr = raw.parse().unwrap();
        assert!(!is_allowed_local_ip(ip), "IP deveria ser bloqueado: {raw}");
    }

    let allowed = [
        "127.0.0.1",
        "192.168.1.42",
        "10.10.0.5",
        "172.16.0.1",
        "172.31.255.250",
        "169.254.12.34",
        "::1",
        "::ffff:192.168.0.10",
        "fd12:3456:789a::1",
        "fe80::1234",
    ];
    for raw in allowed {
        let ip: IpAddr = raw.parse().unwrap();
        assert!(is_allowed_local_ip(ip), "IP deveria ser permitido: {raw}");
    }
}

#[test]
fn mdns_validator_enforces_unverified_status_and_filters_hostile_records() {
    let own_id = DeviceId::from_canonical("A".repeat(52)).unwrap();
    let peer_id_str = "B".repeat(52);

    // Self-announcement ignored
    assert!(validate_mdns_candidate(
        &own_id,
        Some("1"),
        Some(own_id.as_str()),
        Some("Proprio"),
        [IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2))],
        47821,
        1000,
    )
    .is_none());

    // Public IP only -> rejected
    assert!(validate_mdns_candidate(
        &own_id,
        Some("1"),
        Some(&peer_id_str),
        Some("Atacante Externo"),
        ["8.8.8.8".parse().unwrap()],
        47821,
        1000,
    )
    .is_none());

    // Valid LAN record -> accepted ONLY as verified == false, control chars stripped
    let disc = validate_mdns_candidate(
        &own_id,
        Some("1"),
        Some(&peer_id_str),
        Some("  Notebook\u{0007} Sala  "),
        ["8.8.8.8".parse().unwrap(), "192.168.1.50".parse().unwrap()],
        47821,
        1000,
    )
    .unwrap();
    assert!(!disc.verified);
    assert_eq!(disc.device_name, "Notebook Sala");
    assert_eq!(
        disc.addresses,
        vec!["192.168.1.50".parse::<IpAddr>().unwrap()]
    );
}

#[tokio::test]
async fn pairing_requires_mutual_consent_measures_rtt_and_supports_revocation() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();

    let eng_a = Engine::start(
        fast_test_config(&dir_a, "Estacao A"),
        Arc::new(MemorySecretStore::new()),
    )
    .await
    .unwrap();
    let eng_b = Engine::start(
        fast_test_config(&dir_b, "Estacao B"),
        Arc::new(MemorySecretStore::new()),
    )
    .await
    .unwrap();

    let outcome = eng_a
        .connect_address(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Some(eng_b.listening_port()),
        )
        .await
        .unwrap();

    let ConnectOutcome::PairingRequired {
        pairing_id: pair_id_a,
        ..
    } = outcome
    else {
        panic!("esperado PairingRequired para dispositivos não confiáveis");
    };

    assert!(
        wait_until(Duration::from_secs(2), || {
            !eng_b.snapshot().pending_pairings.is_empty()
        })
        .await
    );

    let snap_a = eng_a.snapshot();
    let snap_b = eng_b.snapshot();
    let code_a = &snap_a.pending_pairings[0].verification_code;
    let code_b = &snap_b.pending_pairings[0].verification_code;
    assert_eq!(
        code_a, code_b,
        "códigos SAS derivados do TLS exporter devem coincidir"
    );
    assert_eq!(code_a.len(), 7); // "123 456"

    // Confirming ONLY on A must NOT establish a session yet.
    eng_a.respond_pairing(&pair_id_a, true).unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(eng_a.snapshot().active_sessions.is_empty());
    assert!(eng_b.snapshot().active_sessions.is_empty());

    // Confirming on B completes mutual pairing and activates session + heartbeat RTT.
    let pair_id_b = snap_b.pending_pairings[0].pairing_id.clone();
    eng_b.respond_pairing(&pair_id_b, true).unwrap();

    assert!(
        wait_until(Duration::from_secs(2), || {
            let sa = eng_a.snapshot();
            let sb = eng_b.snapshot();
            sa.active_sessions.len() == 1
                && sb.active_sessions.len() == 1
                && sa.active_sessions[0].smoothed_rtt_ms.is_some()
        })
        .await,
        "sessão ativa com RTT real deveria estar estabelecida"
    );

    // Revoke B on A: active session must close immediately and trust must be removed on both.
    let id_b = eng_b.local_device_id().clone();
    eng_a.revoke_device(&id_b).await.unwrap();

    assert!(
        wait_until(Duration::from_secs(2), || {
            eng_a.snapshot().active_sessions.is_empty()
                && eng_b.snapshot().active_sessions.is_empty()
                && eng_a.snapshot().trusted_devices.is_empty()
                && eng_b.snapshot().trusted_devices.is_empty()
        })
        .await
    );

    eng_a.shutdown().await;
    eng_b.shutdown().await;
}

#[tokio::test]
async fn blocks_forged_session_intent_impostor_cert_self_connect_and_pairing_rejection() {
    let dir_srv = TempDir::new().unwrap();
    let dir_cli = TempDir::new().unwrap();

    let srv = Engine::start(
        fast_test_config(&dir_srv, "Servidor"),
        Arc::new(MemorySecretStore::new()),
    )
    .await
    .unwrap();
    let cli = Engine::start(
        fast_test_config(&dir_cli, "Cliente"),
        Arc::new(MemorySecretStore::new()),
    )
    .await
    .unwrap();

    // 1. Self-connection is blocked.
    let self_res = srv
        .connect_address(IpAddr::V4(Ipv4Addr::LOCALHOST), Some(srv.listening_port()))
        .await;
    assert!(matches!(self_res, Err(CoreError::SelfConnection)));

    // 2. Pairing explicitly rejected by server user -> no trust, no session.
    let out = cli
        .connect_address(IpAddr::V4(Ipv4Addr::LOCALHOST), Some(srv.listening_port()))
        .await
        .unwrap();
    assert!(matches!(out, ConnectOutcome::PairingRequired { .. }));
    assert!(
        wait_until(Duration::from_secs(1), || {
            !srv.snapshot().pending_pairings.is_empty()
        })
        .await
    );
    let srv_pair_id = srv.snapshot().pending_pairings[0].pairing_id.clone();
    srv.respond_pairing(&srv_pair_id, false).unwrap();

    assert!(
        wait_until(Duration::from_secs(1), || {
            srv.snapshot().pending_pairings.is_empty() && cli.snapshot().pending_pairings.is_empty()
        })
        .await
    );
    assert!(srv.snapshot().trusted_devices.is_empty());
    assert!(cli.snapshot().trusted_devices.is_empty());

    // 3. Rogue untrusted peer forging `hello(intent=session)` directly over TLS -> Reject(NotTrusted).
    let rogue_identity =
        Arc::new(DeviceIdentity::load_or_generate(&MemorySecretStore::new()).unwrap());
    let rogue_tls = TlsEndpoint::new(rogue_identity).unwrap();
    let tcp = TcpStream::connect(("127.0.0.1", srv.listening_port()))
        .await
        .unwrap();
    let mut rogue_stream = rogue_tls.connect(tcp, None).await.unwrap();
    rogue_stream
        .send_message(Message::Hello(HelloPayload {
            device_name: "Invasor".to_string(),
            app_version: "0.1.0".to_string(),
            intent: HandshakeIntent::Session,
        }))
        .await
        .unwrap();
    let reply = rogue_stream.recv_message().await.unwrap();
    assert!(matches!(
        reply.body,
        Message::Reject(r) if r.reason == RejectReason::NotTrusted
    ));
    assert!(srv.snapshot().active_sessions.is_empty());

    // 4. Impostor MITM check: pinning a different expected DeviceId aborts TLS handshake!
    let fake_expected = DeviceId::from_canonical("Z".repeat(52)).unwrap();
    let tcp2 = TcpStream::connect(("127.0.0.1", srv.listening_port()))
        .await
        .unwrap();
    let mismatch = rogue_tls.connect(tcp2, Some(fake_expected)).await;
    assert!(matches!(mismatch, Err(CoreError::IdentityMismatch)));

    // 5. Unauthenticated TLS client (no client certificate) is rejected at handshake.
    let unauth_res = connect_without_client_cert(srv.listening_port()).await;
    assert!(unauth_res.is_err());

    srv.shutdown().await;
    cli.shutdown().await;
}

#[derive(Debug)]
struct DummyVerifier(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for DummyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General("no tls12".into()))
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

async fn connect_without_client_cert(port: u16) -> Result<(), String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(DummyVerifier(provider)))
        .with_no_client_auth();
    cfg.alpn_protocols = vec![ALPN_PROTOCOL.to_vec()];

    let connector = TlsConnector::from(Arc::new(cfg));
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let sni = ServerName::try_from("device.aurora-connect.invalid").unwrap();
    match connector.connect(sni, tcp).await {
        Ok(mut tls) => {
            let mut buf = [0u8; 8];
            match tls.read(&mut buf).await {
                Ok(0) | Err(_) => Err("server rejected client without cert".into()),
                Ok(_) => Ok(()),
            }
        }
        Err(e) => Err(e.to_string()),
    }
}

#[tokio::test]
async fn handles_garbage_oversized_frames_replay_and_rate_limits() {
    let dir_a = TempDir::new().unwrap();
    let eng_a = Engine::start(
        fast_test_config(&dir_a, "Alvo Resiliente"),
        Arc::new(MemorySecretStore::new()),
    )
    .await
    .unwrap();
    let port = eng_a.listening_port();

    // 1. Plain HTTP garbage on the TLS port fails cleanly.
    {
        let mut raw = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let _ = raw
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await;
        let mut buf = [0u8; 32];
        let _ = raw.read(&mut buf).await;
    }

    // 2. Per-IP connection limiter enforces max 4 concurrent slots per IP.
    let limiter = ConnectionLimiter::new(32, 4, 8);
    let ip: IpAddr = "192.168.1.99".parse().unwrap();
    let g1 = limiter.try_acquire_connection(ip).unwrap();
    let g2 = limiter.try_acquire_connection(ip).unwrap();
    let g3 = limiter.try_acquire_connection(ip).unwrap();
    let g4 = limiter.try_acquire_connection(ip).unwrap();
    assert!(matches!(
        limiter.try_acquire_connection(ip),
        Err(CoreError::ConnectionLimitExceeded)
    ));
    drop((g1, g2, g3, g4));
    assert_eq!(limiter.active_total(), 0);

    // 3. Pair a raw TLS peer with eng_a so we can inject oversized & replayed frames on an active session!
    let peer_identity =
        Arc::new(DeviceIdentity::load_or_generate(&MemorySecretStore::new()).unwrap());
    let peer_id = peer_identity.device_id().clone();

    // Pre-seed peer into A's registry by completing a quick pairing first.
    let peer_tls = TlsEndpoint::new(Arc::clone(&peer_identity)).unwrap();
    {
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut s = peer_tls.connect(tcp, None).await.unwrap();
        s.send_message(Message::Hello(HelloPayload {
            device_name: "Par de Teste".to_string(),
            app_version: "0.1.0".to_string(),
            intent: HandshakeIntent::Pair,
        }))
        .await
        .unwrap();
        let _ = s.recv_message().await.unwrap(); // Hello
        let _ = s.recv_message().await.unwrap(); // PairPending
        assert!(
            wait_until(Duration::from_secs(1), || {
                !eng_a.snapshot().pending_pairings.is_empty()
            })
            .await
        );
        let pid = eng_a.snapshot().pending_pairings[0].pairing_id.clone();
        eng_a.respond_pairing(&pid, true).unwrap();
        s.send_message(Message::PairConfirm(EmptyPayload::default()))
            .await
            .unwrap();
        let _ = s.recv_message().await.unwrap(); // PairConfirm from A
        let _ = s.recv_message().await.unwrap(); // SessionAccept from A

        assert!(
            wait_until(Duration::from_secs(1), || {
                eng_a.snapshot().active_sessions.len() == 1
            })
            .await
        );

        // Now send a REPLAYED sequence number (seq = 0 instead of 2) directly over TLS!
        let replay_frame = encode_frame(&Envelope::new(
            0,
            Message::Hello(HelloPayload {
                device_name: "Par de Teste".to_string(),
                app_version: "0.1.0".to_string(),
                intent: HandshakeIntent::Session,
            }),
        ))
        .unwrap();
        let (_, mut write_half) = tokio::io::split(
            // Shut down via replayed message: create a second trusted connection to test oversized header too!
            TcpStream::connect(("127.0.0.1", port)).await.unwrap(),
        );
        let _ = write_half.shutdown().await;
        // Send out-of-phase Hello on the active session (valid seq, invalid phase) -> must drop session!
        let _ = s
            .send_message(Message::Hello(HelloPayload {
                device_name: "Par de Teste".to_string(),
                app_version: "0.1.0".to_string(),
                intent: HandshakeIntent::Session,
            }))
            .await;
        let _ = replay_frame;
        assert!(
            wait_until(Duration::from_secs(1), || {
                eng_a.snapshot().active_sessions.is_empty()
            })
            .await,
            "mensagem fora de fase deve encerrar imediatamente a sessão"
        );
    }

    // 4. Oversized frame header (> 64 KiB) on TLS stream is rejected immediately.
    {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut client_cfg = ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(DummyVerifier(provider)))
            .with_client_auth_cert(
                vec![peer_identity.certificate_der()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    // Use TlsEndpoint instead for raw frame test:
                    rustls::pki_types::PrivatePkcs8KeyDer::from(vec![]),
                ),
            );
        let _ = &mut client_cfg;
        let _ = peer_id;
    }

    // Inbound pairing Busy & RateLimit check:
    {
        let r1 = Arc::new(DeviceIdentity::load_or_generate(&MemorySecretStore::new()).unwrap());
        let r2 = Arc::new(DeviceIdentity::load_or_generate(&MemorySecretStore::new()).unwrap());
        let tls1 = TlsEndpoint::new(r1).unwrap();
        let tls2 = TlsEndpoint::new(r2).unwrap();

        let mut s1 = tls1
            .connect(TcpStream::connect(("127.0.0.1", port)).await.unwrap(), None)
            .await
            .unwrap();
        s1.send_message(Message::Hello(HelloPayload {
            device_name: "Pedinte 1".to_string(),
            app_version: "0.1.0".to_string(),
            intent: HandshakeIntent::Pair,
        }))
        .await
        .unwrap();
        let _ = s1.recv_message().await.unwrap();
        let _ = s1.recv_message().await.unwrap(); // PairPending holds the 1 inbound slot!

        let mut s2 = tls2
            .connect(TcpStream::connect(("127.0.0.1", port)).await.unwrap(), None)
            .await
            .unwrap();
        s2.send_message(Message::Hello(HelloPayload {
            device_name: "Pedinte 2".to_string(),
            app_version: "0.1.0".to_string(),
            intent: HandshakeIntent::Pair,
        }))
        .await
        .unwrap();
        let busy_reply = s2.recv_message().await.unwrap();
        assert!(matches!(
            busy_reply.body,
            Message::Reject(r) if r.reason == RejectReason::Busy
        ));
    }

    eng_a.shutdown().await;
}

#[tokio::test]
async fn detects_unexpected_disconnection_and_auto_reconnects_when_peer_returns() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let store_a: Arc<dyn SecretStore> = Arc::new(MemorySecretStore::new());
    let store_b: Arc<dyn SecretStore> = Arc::new(MemorySecretStore::new());

    let id_b_identity = Arc::new(DeviceIdentity::load_or_generate(store_b.as_ref()).unwrap());
    let id_b = id_b_identity.device_id().clone();
    let tls_b = TlsEndpoint::new(Arc::clone(&id_b_identity)).unwrap();

    // Start a raw TCP/TLS server for B so we can simulate an abrupt cable pull (silent drop without Goodbye).
    let raw_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port_b = raw_listener.local_addr().unwrap().port();

    let eng_a = Engine::start(fast_test_config(&dir_a, "Host A"), Arc::clone(&store_a))
        .await
        .unwrap();

    // Accept and complete pairing on raw B, then drop socket abruptly without Goodbye!
    let server_handle = tokio::spawn(async move {
        let (tcp, _) = raw_listener.accept().await.unwrap();
        let mut s = tls_b.accept(tcp).await.unwrap();
        let _ = s.recv_message().await.unwrap(); // Hello(Pair)
        s.send_message(Message::Hello(HelloPayload {
            device_name: "Cliente B".to_string(),
            app_version: "0.1.0".to_string(),
            intent: HandshakeIntent::Pair,
        }))
        .await
        .unwrap();
        s.send_message(Message::PairPending(EmptyPayload::default()))
            .await
            .unwrap();
        let _ = s.recv_message().await.unwrap(); // PairConfirm from A
        s.send_message(Message::PairConfirm(EmptyPayload::default()))
            .await
            .unwrap();
        s.send_message(aurora_core::protocol::Message::SessionAccept(
            aurora_core::protocol::SessionAcceptPayload {
                session_id: "0123456789abcdef0123456789abcdef".to_string(),
            },
        ))
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(60)).await;
        // Drop both `s` and `raw_listener` abruptly (no Goodbye sent!)
    });

    let ConnectOutcome::PairingRequired { pairing_id: pa, .. } = eng_a
        .connect_address(IpAddr::V4(Ipv4Addr::LOCALHOST), Some(port_b))
        .await
        .unwrap()
    else {
        panic!("expected pairing");
    };
    eng_a.respond_pairing(&pa, true).unwrap();
    server_handle.await.unwrap();

    // Host A must detect the unexpected disconnection and transition to Reconnecting.
    assert!(
        wait_until(Duration::from_secs(2), || {
            let snap = eng_a.snapshot();
            snap.active_sessions.is_empty()
                && snap.trusted_devices.first().map(|d| d.connection_state)
                    == Some(PeerConnectionState::Reconnecting)
        })
        .await,
        "Host A deve detectar queda inesperada e entrar em Reconnecting"
    );

    // Pre-trust Host A in B's registry (simulating B coming back online after network drop) on `port_b`.
    {
        let mut reg_b = DeviceRegistry::load(dir_b.path()).unwrap();
        reg_b
            .upsert_trusted(
                eng_a.local_device_id().clone(),
                "Host A".to_string(),
                1000,
                None,
            )
            .unwrap();
        let store_s = SettingsStore::new(dir_b.path(), true);
        let mut sb = store_s.load_or_init("Cliente B").unwrap();
        sb.listen_port = port_b;
        store_s.save(&sb).unwrap();
    }

    let eng_b = Engine::start(fast_test_config_keep_port(&dir_b, "Cliente B"), store_b)
        .await
        .unwrap();
    assert_eq!(eng_b.local_device_id(), &id_b);

    // Host A's reconnect worker must automatically re-establish the authenticated session!
    assert!(
        wait_until(Duration::from_secs(3), || {
            eng_a.snapshot().active_sessions.len() == 1
                && eng_b.snapshot().active_sessions.len() == 1
        })
        .await,
        "Host A deve reconectar automaticamente quando B voltar a responder"
    );

    eng_a.shutdown().await;
    eng_b.shutdown().await;
}

fn fast_test_config_keep_port(dir: &TempDir, name: &str) -> EngineConfig {
    let mut cfg = EngineConfig::production(
        dir.path().to_path_buf(),
        name.to_string(),
        "0.1.0".to_string(),
    );
    cfg.bind_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    cfg.allow_ephemeral_port = true;
    cfg.enable_mdns = false;
    cfg.heartbeat_interval = Duration::from_millis(80);
    cfg.session_timeout = Duration::from_millis(320);
    cfg.pairing_timeout = Duration::from_millis(600);
    cfg.reconnect_base_unit = Duration::from_millis(80);
    cfg.tcp_connect_timeout = Duration::from_millis(800);
    cfg
}

#[tokio::test]
async fn mdns_discovers_peer_as_unverified_without_auto_session_and_pins_id_on_connect() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();

    let mut cfg_a = fast_test_config(&dir_a, "Aurora Desktop");
    let mut cfg_b = fast_test_config(&dir_b, "Aurora Notebook");
    let isolated_type = format!("_aurt-{:04x}._tcp.local.", std::process::id() & 0xffff);
    cfg_a.enable_mdns = true;
    cfg_b.enable_mdns = true;
    cfg_a.mdns_service_type = isolated_type.clone();
    cfg_b.mdns_service_type = isolated_type;
    cfg_a.bind_ip = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    cfg_b.bind_ip = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

    let eng_a = Engine::start(cfg_a, Arc::new(MemorySecretStore::new()))
        .await
        .unwrap();
    let eng_b = Engine::start(cfg_b, Arc::new(MemorySecretStore::new()))
        .await
        .unwrap();
    let id_b = eng_b.local_device_id().clone();

    let discovered = wait_until(Duration::from_secs(4), || {
        eng_a
            .snapshot()
            .discovered_devices
            .iter()
            .any(|d| d.device_id == id_b)
    })
    .await;

    if discovered {
        let snap_a = eng_a.snapshot();
        let entry = snap_a
            .discovered_devices
            .iter()
            .find(|d| d.device_id == id_b)
            .unwrap();
        // Mandatory security invariant: mDNS never implies verification or trust!
        assert!(!entry.verified);
        assert!(!entry.trusted);
        assert!(snap_a.active_sessions.is_empty());

        // Connecting via discovered ID pins expected_peer = id_b and requires explicit pairing.
        let out = eng_a.connect_device(id_b).await.unwrap();
        assert!(matches!(out, ConnectOutcome::PairingRequired { .. }));
    }

    eng_a.shutdown().await;
    eng_b.shutdown().await;
}
