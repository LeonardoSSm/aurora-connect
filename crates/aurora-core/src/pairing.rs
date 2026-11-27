use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aurora_protocol::{
    DeviceId, RejectReason, MAX_PAIRING_REQUESTS_PER_MIN, MAX_PENDING_INBOUND_PAIRINGS,
};
use serde::{Deserialize, Serialize};

/// Direction of a pairing request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairingDirection {
    Inbound,
    Outbound,
}

/// Public snapshot of an active pairing confirmation ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingPairingView {
    pub pairing_id: String,
    pub peer_id: DeviceId,
    pub peer_id_short: String,
    pub peer_id_grouped: String,
    pub peer_name: String,
    pub verification_code: String,
    pub direction: PairingDirection,
    pub local_confirmed: bool,
    pub remote_confirmed: bool,
    pub expires_at_ms: u64,
}

#[derive(Default)]
struct PairingGateState {
    active_inbound: usize,
    recent_requests: VecDeque<Instant>,
}

/// Rate-limits and serializes inbound pairing requests against UI dialog spam.
#[derive(Clone)]
pub struct PairingGate {
    max_pending_inbound: usize,
    max_per_minute: usize,
    state: Arc<Mutex<PairingGateState>>,
}

impl Default for PairingGate {
    fn default() -> Self {
        Self::new(MAX_PENDING_INBOUND_PAIRINGS, MAX_PAIRING_REQUESTS_PER_MIN)
    }
}

impl PairingGate {
    pub fn new(max_pending_inbound: usize, max_per_minute: usize) -> Self {
        Self {
            max_pending_inbound,
            max_per_minute,
            state: Arc::new(Mutex::new(PairingGateState::default())),
        }
    }

    pub fn try_acquire_inbound(&self) -> Result<InboundPairingGuard, RejectReason> {
        let now = Instant::now();
        let window = Duration::from_secs(60);
        let mut st = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        while let Some(&front) = st.recent_requests.front() {
            if now.duration_since(front) >= window {
                st.recent_requests.pop_front();
            } else {
                break;
            }
        }

        if st.recent_requests.len() >= self.max_per_minute {
            return Err(RejectReason::RateLimited);
        }
        if st.active_inbound >= self.max_pending_inbound {
            return Err(RejectReason::Busy);
        }

        st.recent_requests.push_back(now);
        st.active_inbound += 1;

        Ok(InboundPairingGuard {
            state: Arc::clone(&self.state),
        })
    }
}

/// RAII guard releasing the inbound pairing slot when the ceremony completes or aborts.
pub struct InboundPairingGuard {
    state: Arc<Mutex<PairingGateState>>,
}

impl Drop for InboundPairingGuard {
    fn drop(&mut self) {
        let mut st = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        st.active_inbound = st.active_inbound.saturating_sub(1);
    }
}
