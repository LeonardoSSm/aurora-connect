use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use aurora_protocol::{validate_device_name, DeviceId, MAX_TRUSTED_DEVICES};
use serde::{Deserialize, Serialize};

use crate::error::CoreError;
use crate::network::is_allowed_local_ip;
use crate::settings::{atomic_write_json, quarantine_corrupt_file};

/// Public metadata of an explicitly paired and trusted peer device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedDevice {
    pub device_id: DeviceId,
    pub device_name: String,
    pub paired_at_ms: u64,
    pub last_connected_ms: Option<u64>,
    pub last_known_addr: Option<SocketAddr>,
}

impl TrustedDevice {
    fn validate(&self) -> Result<(), CoreError> {
        validate_device_name(&self.device_name)?;
        if let Some(addr) = self.last_known_addr {
            if !is_allowed_local_ip(addr.ip()) {
                return Err(CoreError::AddressPolicyViolation);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryFile {
    devices: Vec<TrustedDevice>,
}

/// Persistent registry of trusted devices (`trusted_devices.json`).
///
/// Fails closed (empty trust set) if on-disk JSON is corrupted or tampered with.
pub struct DeviceRegistry {
    path: PathBuf,
    devices: BTreeMap<DeviceId, TrustedDevice>,
}

impl DeviceRegistry {
    pub fn load(data_dir: &Path) -> Result<Self, CoreError> {
        let path = data_dir.join("trusted_devices.json");
        if !path.exists() {
            let empty = Self {
                path,
                devices: BTreeMap::new(),
            };
            empty.persist()?;
            return Ok(empty);
        }

        let raw = fs::read_to_string(&path)
            .map_err(|e| CoreError::Storage(format!("falha ao ler trusted_devices.json: {e}")))?;

        match serde_json::from_str::<RegistryFile>(&raw) {
            Ok(parsed) if parsed.devices.len() <= MAX_TRUSTED_DEVICES => {
                let mut map = BTreeMap::new();
                let mut all_valid = true;
                for dev in parsed.devices {
                    if dev.validate().is_err() {
                        all_valid = false;
                        break;
                    }
                    map.insert(dev.device_id.clone(), dev);
                }
                if all_valid {
                    return Ok(Self { path, devices: map });
                }
                quarantine_corrupt_file(&path);
                let clean = Self {
                    path,
                    devices: BTreeMap::new(),
                };
                clean.persist()?;
                Ok(clean)
            }
            _ => {
                quarantine_corrupt_file(&path);
                let clean = Self {
                    path,
                    devices: BTreeMap::new(),
                };
                clean.persist()?;
                Ok(clean)
            }
        }
    }

    pub fn is_trusted(&self, device_id: &DeviceId) -> bool {
        self.devices.contains_key(device_id)
    }

    pub fn get(&self, device_id: &DeviceId) -> Option<&TrustedDevice> {
        self.devices.get(device_id)
    }

    pub fn list(&self) -> Vec<TrustedDevice> {
        self.devices.values().cloned().collect()
    }

    pub fn upsert_trusted(
        &mut self,
        device_id: DeviceId,
        device_name: String,
        now_ms: u64,
        remote_addr: Option<SocketAddr>,
    ) -> Result<TrustedDevice, CoreError> {
        validate_device_name(&device_name)?;
        let safe_addr = remote_addr.filter(|a| is_allowed_local_ip(a.ip()));

        if !self.devices.contains_key(&device_id) && self.devices.len() >= MAX_TRUSTED_DEVICES {
            return Err(CoreError::Storage(
                "limite máximo de dispositivos confiáveis atingido".to_string(),
            ));
        }

        let paired_at = self
            .devices
            .get(&device_id)
            .map(|d| d.paired_at_ms)
            .unwrap_or(now_ms);

        let entry = TrustedDevice {
            device_id: device_id.clone(),
            device_name,
            paired_at_ms: paired_at,
            last_connected_ms: Some(now_ms),
            last_known_addr: safe_addr.or_else(|| {
                self.devices
                    .get(&device_id)
                    .and_then(|existing| existing.last_known_addr)
            }),
        };
        self.devices.insert(device_id, entry.clone());
        self.persist()?;
        Ok(entry)
    }

    pub fn record_connected(
        &mut self,
        device_id: &DeviceId,
        device_name: &str,
        now_ms: u64,
        remote_addr: SocketAddr,
    ) -> Result<(), CoreError> {
        if let Some(entry) = self.devices.get_mut(device_id) {
            if validate_device_name(device_name).is_ok() {
                entry.device_name = device_name.to_string();
            }
            entry.last_connected_ms = Some(now_ms);
            if is_allowed_local_ip(remote_addr.ip()) {
                entry.last_known_addr = Some(remote_addr);
            }
            self.persist()?;
        }
        Ok(())
    }

    pub fn revoke(&mut self, device_id: &DeviceId) -> Result<bool, CoreError> {
        let existed = self.devices.remove(device_id).is_some();
        if existed {
            self.persist()?;
        }
        Ok(existed)
    }

    fn persist(&self) -> Result<(), CoreError> {
        let file = RegistryFile {
            devices: self.devices.values().cloned().collect(),
        };
        atomic_write_json(&self.path, &file)
    }
}
