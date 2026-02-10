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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use crate::transports::ice::IceCandidate;

    fn test_addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), port)
    }

    // =========================================================================
    // Happy path: round-trip serialize/deserialize for all 9 variants
    // =========================================================================

    #[test]
    fn test_handshake_round_trip() {
        let envelope = NetEnvelope::Handshake { id: 42 };
        let bytes = envelope.serialize();
        let deserialized = NetEnvelope::try_deserialize(&bytes).unwrap();
        if let NetEnvelope::Handshake { id } = deserialized {
            assert_eq!(id, 42);
        } else {
            panic!("expected Handshake variant");
        }
    }

    #[test]
    fn test_honeybadger_round_trip() {
        let payload = vec![1, 2, 3, 4, 5];
        let envelope = NetEnvelope::HoneyBadger(payload.clone());
        let bytes = envelope.serialize();
        let deserialized = NetEnvelope::try_deserialize(&bytes).unwrap();
        if let NetEnvelope::HoneyBadger(data) = deserialized {
            assert_eq!(data, payload);
        } else {
            panic!("expected HoneyBadger variant");
        }
    }

    #[test]
    fn test_ice_candidates_round_trip() {
        let candidate = IceCandidate::host(test_addr(5000), 1);
        let original_foundation = candidate.foundation.clone();
        let original_priority = candidate.priority;
        let envelope = NetEnvelope::IceCandidates {
            ufrag: "abcd".to_string(),
            pwd: "secret_password_long_enough".to_string(),
            candidates: vec![candidate],
        };
        let bytes = envelope.serialize();
        let deserialized = NetEnvelope::try_deserialize(&bytes).unwrap();
        if let NetEnvelope::IceCandidates { ufrag, pwd, candidates } = deserialized {
            assert_eq!(ufrag, "abcd");
            assert_eq!(pwd, "secret_password_long_enough");
            assert_eq!(candidates.len(), 1);
            let c = &candidates[0];
            assert_eq!(c.address, test_addr(5000));
            assert_eq!(c.candidate_type, crate::transports::ice::CandidateType::Host);
            assert_eq!(c.foundation, original_foundation);
            assert_eq!(c.priority, original_priority);
            assert_eq!(c.component, 1);
            assert!(c.related_address.is_none());
        } else {
            panic!("expected IceCandidates variant");
        }
    }

    #[test]
    fn test_punch_request_round_trip() {
        let target = test_addr(9000);
        let envelope = NetEnvelope::PunchRequest {
            transaction_id: 12345,
            target_address: target,
            delay_ms: 50,
        };
        let bytes = envelope.serialize();
        let deserialized = NetEnvelope::try_deserialize(&bytes).unwrap();
        if let NetEnvelope::PunchRequest { transaction_id, target_address, delay_ms } = deserialized {
            assert_eq!(transaction_id, 12345);
            assert_eq!(target_address, target);
            assert_eq!(delay_ms, 50);
        } else {
            panic!("expected PunchRequest variant");
        }
    }

    #[test]
    fn test_punch_ack_round_trip() {
        let envelope = NetEnvelope::PunchAck {
            transaction_id: 99999,
            timestamp_ms: 1700000000000,
        };
        let bytes = envelope.serialize();
        let deserialized = NetEnvelope::try_deserialize(&bytes).unwrap();
        if let NetEnvelope::PunchAck { transaction_id, timestamp_ms } = deserialized {
            assert_eq!(transaction_id, 99999);
            assert_eq!(timestamp_ms, 1700000000000);
        } else {
            panic!("expected PunchAck variant");
        }
    }

    #[test]
    fn test_connectivity_check_round_trip() {
        let envelope = NetEnvelope::ConnectivityCheck {
            transaction_id: 777,
            is_response: true,
            use_candidate: false,
            ufrag: "testufrag".to_string(),
        };
        let bytes = envelope.serialize();
        let deserialized = NetEnvelope::try_deserialize(&bytes).unwrap();
        if let NetEnvelope::ConnectivityCheck { transaction_id, is_response, use_candidate, ufrag } = deserialized {
            assert_eq!(transaction_id, 777);
            assert!(is_response);
            assert!(!use_candidate);
            assert_eq!(ufrag, "testufrag");
        } else {
            panic!("expected ConnectivityCheck variant");
        }
    }

    #[test]
    fn test_relay_request_round_trip() {
        let envelope = NetEnvelope::RelayRequest {
            target_party_id: 3,
        };
        let bytes = envelope.serialize();
        let deserialized = NetEnvelope::try_deserialize(&bytes).unwrap();
        if let NetEnvelope::RelayRequest { target_party_id } = deserialized {
            assert_eq!(target_party_id, 3);
        } else {
            panic!("expected RelayRequest variant");
        }
    }

    #[test]
    fn test_relay_offer_round_trip() {
        let relay_addr = test_addr(8080);
        let token = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let envelope = NetEnvelope::RelayOffer {
            relay_address: relay_addr,
            allocation_token: token.clone(),
            for_party_id: 7,
        };
        let bytes = envelope.serialize();
        let deserialized = NetEnvelope::try_deserialize(&bytes).unwrap();
        if let NetEnvelope::RelayOffer { relay_address, allocation_token, for_party_id } = deserialized {
            assert_eq!(relay_address, relay_addr);
            assert_eq!(allocation_token, token);
            assert_eq!(for_party_id, 7);
        } else {
            panic!("expected RelayOffer variant");
        }
    }

    #[test]
    fn test_relayed_data_round_trip() {
        let payload = vec![10, 20, 30, 40, 50];
        let envelope = NetEnvelope::RelayedData {
            target_party_id: 1,
            source_party_id: 2,
            payload: payload.clone(),
        };
        let bytes = envelope.serialize();
        let deserialized = NetEnvelope::try_deserialize(&bytes).unwrap();
        if let NetEnvelope::RelayedData { target_party_id, source_party_id, payload: p } = deserialized {
            assert_eq!(target_party_id, 1);
            assert_eq!(source_party_id, 2);
            assert_eq!(p, payload);
        } else {
            panic!("expected RelayedData variant");
        }
    }

    // =========================================================================
    // Edge cases
    // =========================================================================

    #[test]
    fn test_honeybadger_empty_payload() {
        let envelope = NetEnvelope::HoneyBadger(vec![]);
        let bytes = envelope.serialize();
        let deserialized = NetEnvelope::try_deserialize(&bytes).unwrap();
        if let NetEnvelope::HoneyBadger(data) = deserialized {
            assert!(data.is_empty());
        } else {
            panic!("expected HoneyBadger variant");
        }
    }

    #[test]
    fn test_ice_candidates_empty_candidate_list() {
        let envelope = NetEnvelope::IceCandidates {
            ufrag: "u".to_string(),
            pwd: "p".to_string(),
            candidates: vec![],
        };
        let bytes = envelope.serialize();
        let deserialized = NetEnvelope::try_deserialize(&bytes).unwrap();
        if let NetEnvelope::IceCandidates { ufrag, pwd, candidates } = deserialized {
            assert_eq!(ufrag, "u");
            assert_eq!(pwd, "p");
            assert!(candidates.is_empty());
        } else {
            panic!("expected IceCandidates variant");
        }
    }

    #[test]
    fn test_handshake_id_zero() {
        let envelope = NetEnvelope::Handshake { id: 0 };
        let bytes = envelope.serialize();
        let deserialized = NetEnvelope::try_deserialize(&bytes).unwrap();
        if let NetEnvelope::Handshake { id } = deserialized {
            assert_eq!(id, 0);
        } else {
            panic!("expected Handshake variant");
        }
    }

    #[test]
    fn test_handshake_id_max() {
        let envelope = NetEnvelope::Handshake { id: usize::MAX };
        let bytes = envelope.serialize();
        let deserialized = NetEnvelope::try_deserialize(&bytes).unwrap();
        if let NetEnvelope::Handshake { id } = deserialized {
            assert_eq!(id, usize::MAX);
        } else {
            panic!("expected Handshake variant");
        }
    }

    #[test]
    fn test_honeybadger_large_payload_64kb() {
        let payload = vec![0xAB; 64 * 1024];
        let envelope = NetEnvelope::HoneyBadger(payload.clone());
        let bytes = envelope.serialize();
        let deserialized = NetEnvelope::try_deserialize(&bytes).unwrap();
        if let NetEnvelope::HoneyBadger(data) = deserialized {
            assert_eq!(data.len(), 64 * 1024);
            assert_eq!(data, payload);
        } else {
            panic!("expected HoneyBadger variant");
        }
    }

    #[test]
    fn test_relayed_data_empty_payload() {
        let envelope = NetEnvelope::RelayedData {
            target_party_id: 5,
            source_party_id: 10,
            payload: vec![],
        };
        let bytes = envelope.serialize();
        let deserialized = NetEnvelope::try_deserialize(&bytes).unwrap();
        if let NetEnvelope::RelayedData { target_party_id, source_party_id, payload } = deserialized {
            assert_eq!(target_party_id, 5);
            assert_eq!(source_party_id, 10);
            assert!(payload.is_empty());
        } else {
            panic!("expected RelayedData variant");
        }
    }

    // =========================================================================
    // Malicious / adversarial inputs
    // =========================================================================

    #[test]
    fn test_try_deserialize_empty_bytes() {
        let result = NetEnvelope::try_deserialize(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_try_deserialize_random_garbage() {
        let garbage = vec![0xFF; 100];
        let result = NetEnvelope::try_deserialize(&garbage);
        assert!(result.is_err());
    }

    #[test]
    fn test_try_deserialize_truncated_data() {
        let envelope = NetEnvelope::PunchRequest {
            transaction_id: 12345,
            target_address: test_addr(9000),
            delay_ms: 50,
        };
        let bytes = envelope.serialize();
        // Take only the first half of the serialized bytes
        let truncated = &bytes[..bytes.len() / 2];
        let result = NetEnvelope::try_deserialize(truncated);
        assert!(result.is_err());
    }

    #[test]
    fn test_serialization_is_deterministic() {
        let envelope = NetEnvelope::ConnectivityCheck {
            transaction_id: 999,
            is_response: false,
            use_candidate: true,
            ufrag: "deterministic".to_string(),
        };
        let bytes1 = envelope.serialize();
        let bytes2 = envelope.serialize();
        assert_eq!(bytes1, bytes2, "serializing the same value twice must produce identical bytes");
    }

    #[test]
    fn test_all_variants_produce_different_output() {
        let addr = test_addr(5000);
        let candidate = IceCandidate::host(addr, 1);

        let variants: Vec<NetEnvelope> = vec![
            NetEnvelope::Handshake { id: 1 },
            NetEnvelope::HoneyBadger(vec![1, 2, 3]),
            NetEnvelope::IceCandidates {
                ufrag: "u".to_string(),
                pwd: "p".to_string(),
                candidates: vec![candidate],
            },
            NetEnvelope::PunchRequest {
                transaction_id: 1,
                target_address: addr,
                delay_ms: 10,
            },
            NetEnvelope::PunchAck {
                transaction_id: 1,
                timestamp_ms: 1000,
            },
            NetEnvelope::ConnectivityCheck {
                transaction_id: 1,
                is_response: false,
                use_candidate: false,
                ufrag: "u".to_string(),
            },
            NetEnvelope::RelayRequest { target_party_id: 1 },
            NetEnvelope::RelayOffer {
                relay_address: addr,
                allocation_token: vec![1],
                for_party_id: 1,
            },
            NetEnvelope::RelayedData {
                target_party_id: 1,
                source_party_id: 2,
                payload: vec![1],
            },
        ];

        let serialized: Vec<Vec<u8>> = variants.iter().map(|v| v.serialize()).collect();

        // Every pair of variants must produce different serialized bytes
        for i in 0..serialized.len() {
            for j in (i + 1)..serialized.len() {
                assert_ne!(
                    serialized[i], serialized[j],
                    "variant {} and variant {} produced identical serialized output",
                    i, j
                );
            }
        }
    }
}
