use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use crate::transports::ice::IceCandidate;

/// Network envelope used on QUIC to distinguish control messages (like handshakes)
/// from protocol payloads. If deserialization of this wrapper fails on receive,
/// the consumer must treat the bytes as a raw HoneyBadger WrappedMessage payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetEnvelope {
    /// Binary encoded handshake for PartyId/ClientId exchange.
    /// Role identification is now done via ALPN protocol negotiation.
    Handshake { id: usize },
    /// Raw HoneyBadger message bytes (bincode of WrappedMessage from mpc crate).
    HoneyBadger(Vec<u8>),

    // =========================================================================
    // ICE NAT Traversal Messages
    // =========================================================================

    /// ICE candidate exchange - sent after handshake to share connectivity candidates
    IceCandidates {
        /// ICE username fragment for authentication
        ufrag: String,
        /// ICE password for authentication
        pwd: String,
        /// List of gathered candidates (host, server reflexive, etc.)
        candidates: Vec<IceCandidate>,
    },

    /// Request peer to participate in coordinated hole punching
    /// Sent by controlling agent to synchronize timing
    PunchRequest {
        /// Unique transaction ID for correlation
        transaction_id: u64,
        /// Target address the peer should punch towards
        target_address: SocketAddr,
        /// Suggested delay in milliseconds before sending probe
        delay_ms: u64,
    },

    /// Acknowledgment of hole punch request with timing information
    PunchAck {
        /// Matching transaction ID from the request
        transaction_id: u64,
        /// Timestamp when ack was sent (for RTT calculation)
        timestamp_ms: u64,
    },

    /// Connectivity check probe sent directly peer-to-peer
    /// Used to verify connectivity and trigger nomination
    ConnectivityCheck {
        /// Transaction ID for matching request/response
        transaction_id: u64,
        /// True if this is a response to a check, false if request
        is_response: bool,
        /// USE-CANDIDATE flag - if true, nominate this pair
        use_candidate: bool,
        /// ICE credentials for verification
        ufrag: String,
    },

    /// Request relay assistance when direct connection fails
    RelayRequest {
        /// Party ID of the target peer we want to reach
        target_party_id: usize,
    },

    /// Relay offer from server providing a relay path
    RelayOffer {
        /// Address of the relay endpoint to use
        relay_address: SocketAddr,
        /// Token for authenticating with the relay
        allocation_token: Vec<u8>,
        /// Party ID this relay is for
        for_party_id: usize,
    },

    /// Relayed data wrapper - encapsulates data being forwarded through relay
    RelayedData {
        /// Target party for the data
        target_party_id: usize,
        /// Source party sending the data
        source_party_id: usize,
        /// The actual payload being relayed
        payload: Vec<u8>,
    },
}

impl NetEnvelope {
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).expect("envelope serialization should not fail")
    }

    pub fn try_deserialize(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}
