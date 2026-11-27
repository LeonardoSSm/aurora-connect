use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use aurora_protocol::{
    sanitize_device_name, DeviceId, MAX_DISCOVERED_DEVICES, MIN_UNPRIVILEGED_PORT,
};
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::network::{is_allowed_local_ip, local_lan_addresses, normalize_ip};

/// Default DNS-SD service type for Aurora Connect discovery.
pub const DEFAULT_MDNS_SERVICE_TYPE: &str = "_aurora-connect._tcp.local.";

/// Untrusted peer announcement observed via mDNS.
///
/// `verified` is unconditionally `false`: mDNS discovery never implies trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredDevice {
    pub device_id: DeviceId,
    pub device_name: String,
    pub addresses: Vec<IpAddr>,
    pub port: u16,
    pub last_seen_ms: u64,
    pub verified: bool,
}

/// Internal events emitted by the mDNS browser worker.
#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    Upsert {
        fullname: String,
        device: DiscoveredDevice,
    },
    Removed {
        fullname: String,
    },
}

/// Bounded cache of mDNS-discovered peers (`<= MAX_DISCOVERED_DEVICES`).
#[derive(Debug, Default)]
pub struct DiscoveredCache {
    by_id: BTreeMap<DeviceId, DiscoveredDevice>,
    fullname_to_id: HashMap<String, DeviceId>,
}

impl DiscoveredCache {
    pub fn upsert(&mut self, fullname: String, device: DiscoveredDevice) {
        let id = device.device_id.clone();
        if !self.by_id.contains_key(&id) && self.by_id.len() >= MAX_DISCOVERED_DEVICES {
            if let Some(oldest_id) = self
                .by_id
                .values()
                .min_by_key(|d| d.last_seen_ms)
                .map(|d| d.device_id.clone())
            {
                self.by_id.remove(&oldest_id);
                self.fullname_to_id.retain(|_, v| v != &oldest_id);
            }
        }
        self.fullname_to_id.insert(fullname, id.clone());
        self.by_id.insert(id, device);
    }

    pub fn remove_by_fullname(&mut self, fullname: &str) -> bool {
        if let Some(id) = self.fullname_to_id.remove(fullname) {
            let still_referenced = self.fullname_to_id.values().any(|other| other == &id);
            if !still_referenced {
                self.by_id.remove(&id);
                return true;
            }
        }
        false
    }

    pub fn clear(&mut self) {
        self.by_id.clear();
        self.fullname_to_id.clear();
    }

    pub fn get(&self, id: &DeviceId) -> Option<&DiscoveredDevice> {
        self.by_id.get(id)
    }

    pub fn list(&self) -> Vec<DiscoveredDevice> {
        self.by_id.values().cloned().collect()
    }
}

/// Validates raw mDNS TXT attributes and resolved addresses before admitting
/// an entry into [`DiscoveredCache`].
pub fn validate_mdns_candidate(
    local_id: &DeviceId,
    txt_version: Option<&str>,
    txt_id: Option<&str>,
    txt_name: Option<&str>,
    raw_addresses: impl IntoIterator<Item = IpAddr>,
    port: u16,
    now_ms: u64,
) -> Option<DiscoveredDevice> {
    if txt_version != Some("1") {
        return None;
    }
    if port < MIN_UNPRIVILEGED_PORT {
        return None;
    }

    let id_str = txt_id?;
    let device_id = DeviceId::from_canonical(id_str.to_string()).ok()?;
    if &device_id == local_id {
        return None;
    }

    let device_name = sanitize_device_name(txt_name?)?;

    let mut addresses: Vec<IpAddr> = Vec::new();
    for raw_ip in raw_addresses {
        let ip = normalize_ip(raw_ip);
        if is_allowed_local_ip(ip) && !addresses.contains(&ip) {
            addresses.push(ip);
        }
    }
    if addresses.is_empty() {
        return None;
    }
    addresses.sort_by_key(|ip| match ip {
        IpAddr::V4(v4) if !v4.is_loopback() => 0u8,
        IpAddr::V6(v6) if !v6.is_loopback() => 1u8,
        IpAddr::V4(_) => 2u8,
        IpAddr::V6(_) => 3u8,
    });

    Some(DiscoveredDevice {
        device_id,
        device_name,
        addresses,
        port,
        last_seen_ms: now_ms,
        verified: false,
    })
}

/// Handle managing local mDNS service advertisement and browsing.
pub struct MdnsController {
    service_type: String,
    daemon: Option<ServiceDaemon>,
    registered_fullname: Option<String>,
    browse_task: Option<JoinHandle<()>>,
}

impl MdnsController {
    pub fn new(service_type: String) -> Self {
        Self {
            service_type,
            daemon: None,
            registered_fullname: None,
            browse_task: None,
        }
    }

    pub fn is_active(&self) -> bool {
        self.daemon.is_some()
    }

    /// Starts or refreshes mDNS advertisement and browsing.
    pub fn start_or_update(
        &mut self,
        local_id: &DeviceId,
        device_name: &str,
        listen_port: u16,
        events_tx: mpsc::Sender<DiscoveryEvent>,
    ) {
        if self.daemon.is_none() {
            match ServiceDaemon::new() {
                Ok(daemon) => match daemon.browse(&self.service_type) {
                    Ok(receiver) => {
                        let own_id = local_id.clone();
                        let task = tokio::spawn(async move {
                            while let Ok(ev) = receiver.recv_async().await {
                                match ev {
                                    ServiceEvent::ServiceResolved(info) => {
                                        let now_ms = unix_now_ms();
                                        let candidate = validate_mdns_candidate(
                                            &own_id,
                                            info.get_property_val_str("v"),
                                            info.get_property_val_str("id"),
                                            info.get_property_val_str("name"),
                                            info.get_addresses().iter().copied(),
                                            info.get_port(),
                                            now_ms,
                                        );
                                        if let Some(device) = candidate {
                                            let _ = events_tx
                                                .send(DiscoveryEvent::Upsert {
                                                    fullname: info.get_fullname().to_string(),
                                                    device,
                                                })
                                                .await;
                                        }
                                    }
                                    ServiceEvent::ServiceRemoved(_, fullname) => {
                                        let _ = events_tx
                                            .send(DiscoveryEvent::Removed { fullname })
                                            .await;
                                    }
                                    _ => {}
                                }
                            }
                        });
                        self.daemon = Some(daemon);
                        self.browse_task = Some(task);
                    }
                    Err(err) => {
                        warn!("falha ao iniciar busca mDNS: {err}");
                        let _ = daemon.shutdown();
                        return;
                    }
                },
                Err(err) => {
                    warn!("mDNS indisponível neste ambiente: {err}");
                    return;
                }
            }
        }

        let Some(daemon) = &self.daemon else {
            return;
        };

        if let Some(prev_fullname) = self.registered_fullname.take() {
            let _ = daemon.unregister(&prev_fullname);
        }

        let short_lower = local_id.as_str()[..12].to_ascii_lowercase();
        let instance_name = format!("aurora-{short_lower}");
        let host_name = format!("aurora-{short_lower}.local.");
        let safe_name =
            sanitize_device_name(device_name).unwrap_or_else(|| "Aurora Connect".to_string());
        let properties = [
            ("v", "1"),
            ("id", local_id.as_str()),
            ("name", safe_name.as_str()),
        ];

        let lan_ips = local_lan_addresses();
        let service_result = if lan_ips.is_empty() {
            ServiceInfo::new(
                &self.service_type,
                &instance_name,
                &host_name,
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                listen_port,
                &properties[..],
            )
        } else {
            ServiceInfo::new(
                &self.service_type,
                &instance_name,
                &host_name,
                lan_ips.as_slice(),
                listen_port,
                &properties[..],
            )
            .map(ServiceInfo::enable_addr_auto)
        };

        match service_result {
            Ok(mut info) => {
                info.set_requires_probe(false);
                let fullname = info.get_fullname().to_string();
                match daemon.register(info) {
                    Ok(()) => {
                        debug!(peer_short = %local_id.short(), "anúncio mDNS registrado");
                        self.registered_fullname = Some(fullname);
                    }
                    Err(err) => {
                        warn!("falha ao registrar anúncio mDNS: {err}");
                    }
                }
            }
            Err(err) => {
                warn!("falha ao construir registro mDNS: {err}");
            }
        }
    }

    /// Stops mDNS advertisement and browsing cleanly.
    pub fn stop(&mut self) {
        if let Some(task) = self.browse_task.take() {
            task.abort();
        }
        if let Some(daemon) = self.daemon.take() {
            if let Some(fullname) = self.registered_fullname.take() {
                let _ = daemon.unregister(&fullname);
            }
            if let Ok(rx) = daemon.shutdown() {
                let _ = rx.recv_timeout(std::time::Duration::from_millis(250));
            }
        }
    }
}

impl Drop for MdnsController {
    fn drop(&mut self) {
        self.stop();
    }
}

pub(crate) fn unix_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}
