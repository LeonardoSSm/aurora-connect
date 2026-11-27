use std::fmt;
use std::sync::Arc;

use aurora_protocol::DeviceId;
use data_encoding::BASE32_NOPAD;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ED25519,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::ParsedCertificate;
use rustls::{
    CertificateError, ConnectionCommon, DigitallySignedStruct, DistinguishedName as TlsDn,
    Error as TlsError, PeerIncompatible, PeerMisbehaved, SignatureScheme,
};
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};
use zeroize::Zeroizing;

use crate::error::CoreError;
use crate::platform::SecretStore;

/// OID for Ed25519 public keys (RFC 8410).
const ED25519_OID: &str = "1.3.101.112";

/// SNI placeholder used for self-signed peer-to-peer certificates.
pub const TLS_SERVER_NAME: &str = "device.aurora-connect.invalid";

/// TLS 1.3 Exporter label (RFC 8446 §7.5 / RFC 5705) for pairing SAS derivation.
const PAIRING_EXPORTER_LABEL: &[u8] = b"EXPORTER-aurora-connect-pair-v1";

/// Domain separator for pairing exporter context.
const PAIRING_CONTEXT_DOMAIN: &[u8] = b"aurora-connect/pair/v1";

/// Cryptographic identity of the local device.
///
/// Private key material is held in a [`Zeroizing`] buffer and never exposed via `Debug`.
pub struct DeviceIdentity {
    device_id: DeviceId,
    cert_der: CertificateDer<'static>,
    pkcs8_der: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for DeviceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceIdentity")
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}

impl DeviceIdentity {
    /// Loads the existing Ed25519 identity from `store` or generates and stores a new one.
    pub fn load_or_generate(store: &dyn SecretStore) -> Result<Self, CoreError> {
        if let Some(existing_pkcs8) = store.load_identity_key()? {
            return Self::from_pkcs8_der(existing_pkcs8);
        }

        let key_pair = KeyPair::generate_for(&PKCS_ED25519)
            .map_err(|e| CoreError::Crypto(format!("falha ao gerar chave Ed25519: {e}")))?;
        let pkcs8 = Zeroizing::new(key_pair.serialize_der());
        store.store_identity_key(&pkcs8)?;
        Self::from_key_pair(key_pair, pkcs8)
    }

    /// Reconstructs the device identity and ephemeral self-signed X.509 certificate
    /// from a PKCS#8 v1/v2 Ed25519 private key DER blob.
    pub fn from_pkcs8_der(pkcs8_der: Zeroizing<Vec<u8>>) -> Result<Self, CoreError> {
        let key_ref = PrivatePkcs8KeyDer::from(pkcs8_der.as_slice());
        let key_pair = KeyPair::from_pkcs8_der_and_sign_algo(&key_ref, &PKCS_ED25519)
            .map_err(|e| CoreError::Crypto(format!("chave privada Ed25519 inválida: {e}")))?;
        Self::from_key_pair(key_pair, pkcs8_der)
    }

    fn from_key_pair(key_pair: KeyPair, pkcs8_der: Zeroizing<Vec<u8>>) -> Result<Self, CoreError> {
        let spki_der = key_pair.public_key_der();
        let device_id = device_id_from_spki_der(&spki_der);

        let mut params = CertificateParams::new(vec![TLS_SERVER_NAME.to_string()])
            .map_err(|e| CoreError::Crypto(format!("parâmetros X.509 inválidos: {e}")))?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Aurora Connect Device");
        params.distinguished_name = dn;
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];

        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| CoreError::Crypto(format!("falha ao assinar certificado: {e}")))?;

        Ok(Self {
            device_id,
            cert_der: cert.into(),
            pkcs8_der,
        })
    }

    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    pub fn certificate_der(&self) -> CertificateDer<'static> {
        self.cert_der.clone()
    }

    pub(crate) fn clone_private_key_der(&self) -> Result<PrivateKeyDer<'static>, CoreError> {
        let pkcs8 = PrivatePkcs8KeyDer::from(self.pkcs8_der.to_vec());
        Ok(PrivateKeyDer::Pkcs8(pkcs8))
    }
}

/// Computes `BASE32_NOPAD(SHA-256(spki_der))` (52 uppercase characters).
pub fn device_id_from_spki_der(spki_der: &[u8]) -> DeviceId {
    let digest = Sha256::digest(spki_der);
    let encoded = BASE32_NOPAD.encode(&digest);
    DeviceId::from_canonical(encoded).expect("SHA-256 Base32 is always 52 valid chars")
}

/// Parses and validates a peer's X.509 end-entity certificate:
/// - No intermediate certificates allowed.
/// - Valid X.509 DER structure with no trailing bytes.
/// - Validity window encompasses `now`.
/// - SubjectPublicKeyInfo uses Ed25519 (`1.3.101.112`).
/// - Compatible with `webpki` end-entity parsing.
///
/// Returns the derived [`DeviceId`].
pub fn extract_verified_peer_id(
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
    now: UnixTime,
) -> Result<DeviceId, TlsError> {
    if !intermediates.is_empty() {
        return Err(TlsError::InvalidCertificate(CertificateError::BadEncoding));
    }

    let (rem, x509) = X509Certificate::from_der(end_entity.as_ref())
        .map_err(|_| TlsError::InvalidCertificate(CertificateError::BadEncoding))?;
    if !rem.is_empty() {
        return Err(TlsError::InvalidCertificate(CertificateError::BadEncoding));
    }

    let now_secs = i64::try_from(now.as_secs())
        .map_err(|_| TlsError::InvalidCertificate(CertificateError::Expired))?;
    let validity = x509.validity();
    if now_secs < validity.not_before.timestamp() {
        return Err(TlsError::InvalidCertificate(CertificateError::NotValidYet));
    }
    if now_secs > validity.not_after.timestamp() {
        return Err(TlsError::InvalidCertificate(CertificateError::Expired));
    }

    let spki = x509.public_key();
    if spki.algorithm.algorithm.to_id_string() != ED25519_OID {
        return Err(TlsError::InvalidCertificate(CertificateError::BadSignature));
    }

    // Ensure `webpki` agrees on the certificate and SPKI bytes used in TLS 1.3 signature checks.
    let parsed = ParsedCertificate::try_from(end_entity)?;
    let webpki_spki = parsed.subject_public_key_info();
    if webpki_spki.as_ref() != spki.raw {
        return Err(TlsError::InvalidCertificate(CertificateError::BadEncoding));
    }

    Ok(device_id_from_spki_der(webpki_spki.as_ref()))
}

/// Derives a 6-digit verification code (`"123 456"`) bound to the TLS 1.3 session
/// via RFC 8446 §7.5 key exporter and both endpoints' canonical [`DeviceId`]s.
pub fn derive_pairing_code<Data>(
    tls_conn: &ConnectionCommon<Data>,
    id_a: &DeviceId,
    id_b: &DeviceId,
) -> Result<Zeroizing<String>, CoreError> {
    let (min_id, max_id) = if id_a <= id_b {
        (id_a.as_str(), id_b.as_str())
    } else {
        (id_b.as_str(), id_a.as_str())
    };

    let mut hasher = Sha256::new();
    hasher.update(PAIRING_CONTEXT_DOMAIN);
    hasher.update(min_id.as_bytes());
    hasher.update(max_id.as_bytes());
    let context = hasher.finalize();

    let mut ekm = Zeroizing::new([0u8; 8]);
    tls_conn
        .export_keying_material(ekm.as_mut(), PAIRING_EXPORTER_LABEL, Some(&context))
        .map_err(CoreError::Tls)?;

    let raw = u64::from_be_bytes(*ekm) % 1_000_000;
    let formatted = format!("{:03} {:03}", raw / 1_000, raw % 1_000);
    Ok(Zeroizing::new(formatted))
}

/// TLS 1.3 server certificate verifier using Ed25519 public-key pinning.
#[derive(Debug)]
pub struct PinnedServerVerifier {
    expected_peer: Option<DeviceId>,
    provider: Arc<CryptoProvider>,
}

impl PinnedServerVerifier {
    pub fn new(expected_peer: Option<DeviceId>, provider: Arc<CryptoProvider>) -> Self {
        Self {
            expected_peer,
            provider,
        }
    }
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        let peer_id = extract_verified_peer_id(end_entity, intermediates, now)?;
        if let Some(expected) = &self.expected_peer {
            if &peer_id != expected {
                return Err(TlsError::InvalidCertificate(
                    CertificateError::ApplicationVerificationFailure,
                ));
            }
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::PeerIncompatible(
            PeerIncompatible::Tls12NotOfferedOrEnabled,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        if dss.scheme != SignatureScheme::ED25519 {
            return Err(TlsError::PeerMisbehaved(
                PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme,
            ));
        }
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

/// Mandatory TLS 1.3 client certificate verifier enforcing Ed25519 possession.
#[derive(Debug)]
pub struct MutualClientVerifier {
    provider: Arc<CryptoProvider>,
    empty_hints: [TlsDn; 0],
}

impl MutualClientVerifier {
    pub fn new(provider: Arc<CryptoProvider>) -> Self {
        Self {
            provider,
            empty_hints: [],
        }
    }
}

impl ClientCertVerifier for MutualClientVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[TlsDn] {
        &self.empty_hints
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        let _peer_id = extract_verified_peer_id(end_entity, intermediates, now)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::PeerIncompatible(
            PeerIncompatible::Tls12NotOfferedOrEnabled,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        if dss.scheme != SignatureScheme::ED25519 {
            return Err(TlsError::PeerMisbehaved(
                PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme,
            ));
        }
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}
