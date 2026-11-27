use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use aurora_protocol::{
    MAX_CONCURRENT_HANDSHAKES, MAX_CONNECTIONS_PER_IP, MAX_TOTAL_CONNECTIONS, MIN_UNPRIVILEGED_PORT,
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::error::CoreError;

/// Normalizes IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) to `IpAddr::V4`
/// so IPv4 security rules cannot be bypassed via dual-stack sockets.
pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
    }
}

/// Evaluates whether an IP address belongs to a permitted local scope:
/// loopback, RFC 1918 private IPv4, IPv4 link-local (`169.254.0.0/16`),
/// IPv6 Unique Local (`fc00::/7`), or IPv6 unicast link-local (`fe80::/10`).
///
/// Unspecified, broadcast, multicast, documentation, CGNAT, and all public
/// internet addresses are unconditionally rejected.
pub fn is_allowed_local_ip(ip: IpAddr) -> bool {
    match normalize_ip(ip) {
        IpAddr::V4(v4) => is_allowed_ipv4(v4),
        IpAddr::V6(v6) => is_allowed_ipv6(v6),
    }
}

fn is_allowed_ipv4(v4: Ipv4Addr) -> bool {
    if v4.is_unspecified() || v4.is_broadcast() || v4.is_multicast() || v4.is_documentation() {
        return false;
    }
    v4.is_loopback() || v4.is_private() || v4.is_link_local()
}

fn is_allowed_ipv6(v6: Ipv6Addr) -> bool {
    if v6.is_unspecified() || v6.is_multicast() {
        return false;
    }
    if v6.is_loopback() {
        return true;
    }
    let seg0 = v6.segments()[0];
    let is_unique_local = (seg0 & 0xfe00) == 0xfc00; // fc00::/7
    let is_unicast_link_local = (seg0 & 0xffc0) == 0xfe80; // fe80::/10
    is_unique_local || is_unicast_link_local
}

/// Validates a peer socket address against local-network policy and port bounds.
pub fn validate_peer_addr(addr: SocketAddr) -> Result<SocketAddr, CoreError> {
    let ip = normalize_ip(addr.ip());
    if !is_allowed_local_ip(ip) {
        return Err(CoreError::AddressPolicyViolation);
    }
    if addr.port() < MIN_UNPRIVILEGED_PORT {
        return Err(CoreError::InvalidInput(format!(
            "porta deve estar entre {MIN_UNPRIVILEGED_PORT} e 65535"
        )));
    }
    Ok(SocketAddr::new(ip, addr.port()))
}

/// Enumerates non-loopback LAN IP addresses currently assigned to the host.
pub fn local_lan_addresses() -> Vec<IpAddr> {
    let Ok(interfaces) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };
    let mut addrs = Vec::new();
    for iface in interfaces {
        if iface.is_loopback() {
            continue;
        }
        let ip = normalize_ip(iface.ip());
        if is_allowed_local_ip(ip) && !ip.is_loopback() && !addrs.contains(&ip) {
            addrs.push(ip);
        }
    }
    // Prefer IPv4 first for user readability when typing manual IP addresses.
    addrs.sort_by_key(|ip| match ip {
        IpAddr::V4(_) => 0u8,
        IpAddr::V6(_) => 1u8,
    });
    addrs
}

#[derive(Default)]
struct ConnectionCounts {
    total: usize,
    per_ip: HashMap<IpAddr, usize>,
}

/// Enforces global connection count, per-IP connection count, and concurrent
/// TLS handshake limits.
#[derive(Clone)]
pub struct ConnectionLimiter {
    max_total: usize,
    max_per_ip: usize,
    counts: Arc<Mutex<ConnectionCounts>>,
    handshake_sem: Arc<Semaphore>,
}

impl Default for ConnectionLimiter {
    fn default() -> Self {
        Self::new(
            MAX_TOTAL_CONNECTIONS,
            MAX_CONNECTIONS_PER_IP,
            MAX_CONCURRENT_HANDSHAKES,
        )
    }
}

impl ConnectionLimiter {
    pub fn new(max_total: usize, max_per_ip: usize, max_handshakes: usize) -> Self {
        Self {
            max_total,
            max_per_ip,
            counts: Arc::new(Mutex::new(ConnectionCounts::default())),
            handshake_sem: Arc::new(Semaphore::new(max_handshakes)),
        }
    }

    /// Reserves a connection slot for `raw_ip` or fails immediately if global
    /// or per-IP limits are reached.
    pub fn try_acquire_connection(&self, raw_ip: IpAddr) -> Result<ConnectionGuard, CoreError> {
        let ip = normalize_ip(raw_ip);
        if !is_allowed_local_ip(ip) {
            return Err(CoreError::AddressPolicyViolation);
        }

        let mut counts = self
            .counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if counts.total >= self.max_total {
            return Err(CoreError::ConnectionLimitExceeded);
        }
        let ip_entry = counts.per_ip.entry(ip).or_insert(0);
        if *ip_entry >= self.max_per_ip {
            return Err(CoreError::ConnectionLimitExceeded);
        }
        *ip_entry += 1;
        counts.total += 1;

        Ok(ConnectionGuard {
            ip,
            counts: Arc::clone(&self.counts),
        })
    }

    /// Acquires a bounded TLS handshake permit (non-blocking fail-fast on flood
    /// for inbound or async wait for outbound).
    pub fn try_acquire_handshake(&self) -> Result<OwnedSemaphorePermit, CoreError> {
        Arc::clone(&self.handshake_sem)
            .try_acquire_owned()
            .map_err(|_| CoreError::ConnectionLimitExceeded)
    }

    pub async fn acquire_handshake(&self) -> Result<OwnedSemaphorePermit, CoreError> {
        Arc::clone(&self.handshake_sem)
            .acquire_owned()
            .await
            .map_err(|_| CoreError::ConnectionLimitExceeded)
    }

    pub fn active_total(&self) -> usize {
        self.counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .total
    }
}

/// RAII guard decrementing total and per-IP connection counters on drop.
pub struct ConnectionGuard {
    ip: IpAddr,
    counts: Arc<Mutex<ConnectionCounts>>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let mut counts = self
            .counts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        counts.total = counts.total.saturating_sub(1);
        if let Some(ip_count) = counts.per_ip.get_mut(&self.ip) {
            *ip_count = ip_count.saturating_sub(1);
            if *ip_count == 0 {
                counts.per_ip.remove(&self.ip);
            }
        }
    }
}
