//! Platform adapter abstractions for `aurora-core`.
//!
//! Cycle 01 defines [`SecretStore`] so cryptographic private keys are stored
//! exclusively in the operating system credential vault (Windows Credential
//! Manager / DPAPI on Windows) without coupling `aurora-core` to OS crates.
//!
//! Future cycles will add native input capture/injection (Cycle 02) and native
//! clipboard adapters (Cycle 04) in this boundary without altering transport
//! or session logic.

use std::sync::Mutex;

use zeroize::Zeroizing;

use crate::error::CoreError;

/// Secure storage interface for the local device's Ed25519 private key (PKCS#8 DER).
pub trait SecretStore: Send + Sync {
    /// Loads the persisted PKCS#8 DER private key, if one exists.
    fn load_identity_key(&self) -> Result<Option<Zeroizing<Vec<u8>>>, CoreError>;

    /// Persists the PKCS#8 DER private key into secure storage.
    fn store_identity_key(&self, pkcs8_der: &[u8]) -> Result<(), CoreError>;

    /// Deletes the persisted private key from secure storage.
    fn delete_identity_key(&self) -> Result<(), CoreError>;
}

/// Ephemeral in-memory [`SecretStore`] wrapped in [`Zeroizing`] buffers.
///
/// Used exclusively for automated tests and ephemeral `aurora-node` validation
/// processes; never writes key material to disk.
#[derive(Default)]
pub struct MemorySecretStore {
    key: Mutex<Option<Zeroizing<Vec<u8>>>>,
}

impl MemorySecretStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecretStore for MemorySecretStore {
    fn load_identity_key(&self) -> Result<Option<Zeroizing<Vec<u8>>>, CoreError> {
        let guard = self
            .key
            .lock()
            .map_err(|_| CoreError::SecretStore("lock poisoned".to_string()))?;
        Ok(guard.clone())
    }

    fn store_identity_key(&self, pkcs8_der: &[u8]) -> Result<(), CoreError> {
        let mut guard = self
            .key
            .lock()
            .map_err(|_| CoreError::SecretStore("lock poisoned".to_string()))?;
        *guard = Some(Zeroizing::new(pkcs8_der.to_vec()));
        Ok(())
    }

    fn delete_identity_key(&self) -> Result<(), CoreError> {
        let mut guard = self
            .key
            .lock()
            .map_err(|_| CoreError::SecretStore("lock poisoned".to_string()))?;
        *guard = None;
        Ok(())
    }
}
