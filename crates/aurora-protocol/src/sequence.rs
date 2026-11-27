use crate::types::ProtocolError;

/// Per-connection strict monotonic sequence tracker providing replay,
/// duplicate, reorder and gap detection in both directions.
#[derive(Debug, Default, Clone)]
pub struct SequenceTracker {
    inbound_expected: u64,
    outbound_next: u64,
}

impl SequenceTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reserves and returns the next outbound sequence number (`0, 1, 2, ...`).
    pub fn next_outbound(&mut self) -> Result<u64, ProtocolError> {
        let current = self.outbound_next;
        self.outbound_next = self
            .outbound_next
            .checked_add(1)
            .ok_or(ProtocolError::SequenceOverflow)?;
        Ok(current)
    }

    /// Validates an inbound sequence number; rejects replays, gaps and regressions.
    pub fn accept_inbound(&mut self, seq: u64) -> Result<(), ProtocolError> {
        if seq != self.inbound_expected {
            return Err(ProtocolError::InvalidSequence {
                expected: self.inbound_expected,
                actual: seq,
            });
        }
        self.inbound_expected = self
            .inbound_expected
            .checked_add(1)
            .ok_or(ProtocolError::SequenceOverflow)?;
        Ok(())
    }

    pub fn inbound_expected(&self) -> u64 {
        self.inbound_expected
    }

    pub fn outbound_next(&self) -> u64 {
        self.outbound_next
    }
}
