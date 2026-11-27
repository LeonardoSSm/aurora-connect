use aurora_core::{CoreError, SecretStore};
use keyring::{Entry, Error as KeyringError};
use zeroize::Zeroizing;

const KEYRING_SERVICE: &str = "dev.aurora.connect";
const KEYRING_ACCOUNT: &str = "device-identity-ed25519-v1";

/// Operating-system credential vault adapter backed by `keyring`
/// (Windows Credential Manager / DPAPI on Windows, Keychain on macOS,
/// Secret Service on Linux). Never falls back to plaintext files.
pub struct OsKeyringSecretStore {
    service: String,
    account: String,
}

impl Default for OsKeyringSecretStore {
    fn default() -> Self {
        Self {
            service: KEYRING_SERVICE.to_string(),
            account: KEYRING_ACCOUNT.to_string(),
        }
    }
}

impl OsKeyringSecretStore {
    fn entry(&self) -> Result<Entry, CoreError> {
        Entry::new(&self.service, &self.account)
            .map_err(|e| CoreError::SecretStore(format!("falha ao acessar cofre do SO: {e}")))
    }
}

impl SecretStore for OsKeyringSecretStore {
    fn load_identity_key(&self) -> Result<Option<Zeroizing<Vec<u8>>>, CoreError> {
        let entry = self.entry()?;
        match entry.get_secret() {
            Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(err) => Err(CoreError::SecretStore(format!(
                "falha ao ler chave do cofre do SO: {err}"
            ))),
        }
    }

    fn store_identity_key(&self, pkcs8_der: &[u8]) -> Result<(), CoreError> {
        let entry = self.entry()?;
        entry.set_secret(pkcs8_der).map_err(|e| {
            CoreError::SecretStore(format!("falha ao gravar chave no cofre do SO: {e}"))
        })
    }

    fn delete_identity_key(&self) -> Result<(), CoreError> {
        let entry = self.entry()?;
        match entry.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
            Err(err) => Err(CoreError::SecretStore(format!(
                "falha ao remover chave do cofre do SO: {err}"
            ))),
        }
    }
}
