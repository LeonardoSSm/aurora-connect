use std::fs;
use std::path::{Path, PathBuf};

use aurora_protocol::{validate_device_name, DEFAULT_PORT, MIN_UNPRIVILEGED_PORT};
use serde::{Deserialize, Serialize};

use crate::error::CoreError;

/// Local user preferences persisted in `settings.json` (contains no secrets).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub device_name: String,
    pub listen_port: u16,
    pub discovery_enabled: bool,
    pub allow_pairing: bool,
    pub auto_reconnect: bool,
}

impl Settings {
    pub fn default_with_name(default_name: &str) -> Self {
        let device_name = if validate_device_name(default_name).is_ok() {
            default_name.to_string()
        } else {
            "Computador Aurora".to_string()
        };
        Self {
            device_name,
            listen_port: DEFAULT_PORT,
            discovery_enabled: true,
            allow_pairing: true,
            auto_reconnect: true,
        }
    }

    pub fn validate(&self, allow_ephemeral_port: bool) -> Result<(), CoreError> {
        validate_device_name(&self.device_name)?;
        if !(allow_ephemeral_port && self.listen_port == 0)
            && self.listen_port < MIN_UNPRIVILEGED_PORT
        {
            return Err(CoreError::InvalidInput(format!(
                "porta deve estar entre {MIN_UNPRIVILEGED_PORT} e 65535"
            )));
        }
        Ok(())
    }
}

/// Partial update sent by the UI or CLI.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsPatch {
    pub device_name: Option<String>,
    pub listen_port: Option<u16>,
    pub discovery_enabled: Option<bool>,
    pub allow_pairing: Option<bool>,
    pub auto_reconnect: Option<bool>,
}

/// Atomic JSON persistence for [`Settings`].
pub struct SettingsStore {
    path: PathBuf,
    allow_ephemeral_port: bool,
}

impl SettingsStore {
    pub fn new(data_dir: &Path, allow_ephemeral_port: bool) -> Self {
        Self {
            path: data_dir.join("settings.json"),
            allow_ephemeral_port,
        }
    }

    pub fn load_or_init(&self, fallback_name: &str) -> Result<Settings, CoreError> {
        if !self.path.exists() {
            let defaults = Settings::default_with_name(fallback_name);
            self.save(&defaults)?;
            return Ok(defaults);
        }

        let raw = fs::read_to_string(&self.path)
            .map_err(|e| CoreError::Storage(format!("falha ao ler settings.json: {e}")))?;

        match serde_json::from_str::<Settings>(&raw) {
            Ok(settings) if settings.validate(self.allow_ephemeral_port).is_ok() => Ok(settings),
            _ => {
                quarantine_corrupt_file(&self.path);
                let defaults = Settings::default_with_name(fallback_name);
                self.save(&defaults)?;
                Ok(defaults)
            }
        }
    }

    pub fn save(&self, settings: &Settings) -> Result<(), CoreError> {
        settings.validate(self.allow_ephemeral_port)?;
        atomic_write_json(&self.path, settings)
    }
}

pub(crate) fn quarantine_corrupt_file(path: &Path) {
    let mut corrupt = path.as_os_str().to_os_string();
    corrupt.push(".corrupt");
    let _ = fs::rename(path, PathBuf::from(corrupt));
}

pub(crate) fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), CoreError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| CoreError::Storage(format!("falha ao criar diretório de dados: {e}")))?;
    }
    let mut tmp_os = path.as_os_str().to_os_string();
    tmp_os.push(".tmp");
    let tmp_path = PathBuf::from(tmp_os);

    let payload = serde_json::to_vec_pretty(value)
        .map_err(|e| CoreError::Storage(format!("falha ao serializar JSON: {e}")))?;
    fs::write(&tmp_path, payload)
        .map_err(|e| CoreError::Storage(format!("falha ao gravar arquivo temporário: {e}")))?;
    fs::rename(&tmp_path, path)
        .map_err(|e| CoreError::Storage(format!("falha ao substituir arquivo: {e}")))?;
    Ok(())
}
