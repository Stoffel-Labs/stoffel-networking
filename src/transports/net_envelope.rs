use serde::{Deserialize, Serialize};

/// Network envelope used on QUIC to distinguish control messages (like handshakes)
/// from protocol payloads. If deserialization of this wrapper fails on receive,
/// the consumer must treat the bytes as a raw HoneyBadger WrappedMessage payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetEnvelope {
    /// Binary encoded handshake used for future extensibility. Current QUIC impl
    /// still uses a text-line handshake on the first stream, but we support this
    /// for forward-compatibility.
    Handshake { role: String, id: usize },
    /// Raw HoneyBadger message bytes (bincode of WrappedMessage from mpc crate).
    HoneyBadger(Vec<u8>),
}

impl NetEnvelope {
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).expect("envelope serialization should not fail")
    }

    pub fn try_deserialize(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}
