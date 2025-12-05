//! ICE (Interactive Connectivity Establishment) candidate types and utilities
//!
//! Implements RFC 8445 candidate types, priority calculation, and pair formation
//! for NAT traversal in QUIC connections.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use rand::Rng;

/// ICE candidate types per RFC 8445
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CandidateType {
    /// Local interface address (highest priority)
    Host,
    /// STUN-discovered reflexive address
    ServerReflexive,
    /// Peer reflexive (discovered during connectivity checks)
    PeerReflexive,
    /// TURN relay address (lowest priority, future extension)
    Relay,
}

impl CandidateType {
    /// Returns the type preference value for priority calculation (RFC 8445)
    pub fn type_preference(&self) -> u32 {
        match self {
            CandidateType::Host => 126,
            CandidateType::PeerReflexive => 110,
            CandidateType::ServerReflexive => 100,
            CandidateType::Relay => 0,
        }
    }
}

/// Transport protocol for candidate
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransportProtocol {
    Udp,
}

/// Single ICE candidate representing a potential connection endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceCandidate {
    /// Unique identifier for this candidate (used for pairing)
    pub foundation: String,
    /// Component ID (always 1 for QUIC - single component)
    pub component: u32,
    /// Transport protocol
    pub protocol: TransportProtocol,
    /// Computed priority (higher is better)
    pub priority: u32,
    /// The network address and port
    pub address: SocketAddr,
    /// Type of candidate
    pub candidate_type: CandidateType,
    /// Related address (for srflx/relay, the base/host address)
    pub related_address: Option<SocketAddr>,
    /// STUN server used to discover this candidate (for srflx)
    pub stun_server: Option<SocketAddr>,
}

impl IceCandidate {
    /// RFC 8445 priority calculation:
    /// priority = (2^24) * type_preference + (2^8) * local_preference + (2^0) * (256 - component_id)
    pub fn calculate_priority(
        candidate_type: CandidateType,
        local_preference: u16,
        component_id: u32,
    ) -> u32 {
        let type_preference = candidate_type.type_preference();
        (type_preference << 24)
            + ((local_preference as u32) << 8)
            + (256 - component_id.min(256))
    }

    /// Creates a foundation string based on candidate properties
    /// Foundation is the same for candidates that share the same base and STUN server
    fn generate_foundation(
        candidate_type: CandidateType,
        base_addr: Option<SocketAddr>,
        stun_server: Option<SocketAddr>,
    ) -> String {
        use std::hash::{Hash, Hasher};
        use std::collections::hash_map::DefaultHasher;

        let mut hasher = DefaultHasher::new();
        candidate_type.hash(&mut hasher);
        if let Some(addr) = base_addr {
            addr.hash(&mut hasher);
        }
        if let Some(server) = stun_server {
            server.hash(&mut hasher);
        }
        format!("{:x}", hasher.finish())
    }

    /// Creates a host candidate from a local address
    pub fn host(address: SocketAddr, component: u32) -> Self {
        let local_preference = Self::compute_local_preference(&address);
        let priority = Self::calculate_priority(CandidateType::Host, local_preference, component);
        let foundation = Self::generate_foundation(CandidateType::Host, Some(address), None);

        Self {
            foundation,
            component,
            protocol: TransportProtocol::Udp,
            priority,
            address,
            candidate_type: CandidateType::Host,
            related_address: None,
            stun_server: None,
        }
    }

    /// Creates a server reflexive candidate discovered via STUN
    pub fn server_reflexive(
        reflexive_addr: SocketAddr,
        base_addr: SocketAddr,
        stun_server: SocketAddr,
        component: u32,
    ) -> Self {
        let local_preference = Self::compute_local_preference(&reflexive_addr);
        let priority =
            Self::calculate_priority(CandidateType::ServerReflexive, local_preference, component);
        let foundation =
            Self::generate_foundation(CandidateType::ServerReflexive, Some(base_addr), Some(stun_server));

        Self {
            foundation,
            component,
            protocol: TransportProtocol::Udp,
            priority,
            address: reflexive_addr,
            candidate_type: CandidateType::ServerReflexive,
            related_address: Some(base_addr),
            stun_server: Some(stun_server),
        }
    }

    /// Creates a peer reflexive candidate discovered during connectivity checks
    pub fn peer_reflexive(
        reflexive_addr: SocketAddr,
        base_addr: SocketAddr,
        component: u32,
    ) -> Self {
        let local_preference = Self::compute_local_preference(&reflexive_addr);
        let priority =
            Self::calculate_priority(CandidateType::PeerReflexive, local_preference, component);
        let foundation =
            Self::generate_foundation(CandidateType::PeerReflexive, Some(base_addr), None);

        Self {
            foundation,
            component,
            protocol: TransportProtocol::Udp,
            priority,
            address: reflexive_addr,
            candidate_type: CandidateType::PeerReflexive,
            related_address: Some(base_addr),
            stun_server: None,
        }
    }

    /// Computes local preference based on address properties
    /// Higher values for IPv4 (more commonly traversable), lower for IPv6
    fn compute_local_preference(addr: &SocketAddr) -> u16 {
        match addr {
            SocketAddr::V4(_) => 65535,
            SocketAddr::V6(_) => 65534,
        }
    }
}

/// State of a candidate pair during connectivity checking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidatePairState {
    /// Pair has not been checked yet
    Frozen,
    /// Pair is waiting for its turn to be checked
    Waiting,
    /// Connectivity check is in progress
    InProgress,
    /// Connectivity check succeeded
    Succeeded,
    /// Connectivity check failed
    Failed,
}

/// A candidate pair representing a potential path between local and remote endpoints
#[derive(Debug, Clone)]
pub struct CandidatePair {
    /// Local candidate
    pub local: IceCandidate,
    /// Remote candidate
    pub remote: IceCandidate,
    /// Combined priority for pair ordering
    pub priority: u64,
    /// Current state of connectivity checking
    pub state: CandidatePairState,
    /// Whether this pair has been nominated for use
    pub nominated: bool,
    /// Round-trip time measured during check (if succeeded)
    pub rtt_ms: Option<u64>,
}

impl CandidatePair {
    /// RFC 8445 pair priority calculation:
    /// pair_priority = 2^32 * MIN(G, D) + 2 * MAX(G, D) + (G > D ? 1 : 0)
    /// G = controlling agent's candidate priority
    /// D = controlled agent's candidate priority
    pub fn calculate_pair_priority(controlling_priority: u32, controlled_priority: u32) -> u64 {
        let min = std::cmp::min(controlling_priority, controlled_priority) as u64;
        let max = std::cmp::max(controlling_priority, controlled_priority) as u64;
        let tie_breaker = if controlling_priority > controlled_priority {
            1u64
        } else {
            0u64
        };

        (1u64 << 32) * min + 2 * max + tie_breaker
    }

    /// Creates a new candidate pair
    pub fn new(
        local: IceCandidate,
        remote: IceCandidate,
        is_controlling: bool,
    ) -> Self {
        let (controlling_priority, controlled_priority) = if is_controlling {
            (local.priority, remote.priority)
        } else {
            (remote.priority, local.priority)
        };

        let priority = Self::calculate_pair_priority(controlling_priority, controlled_priority);

        Self {
            local,
            remote,
            priority,
            state: CandidatePairState::Frozen,
            nominated: false,
            rtt_ms: None,
        }
    }

    /// Forms all candidate pairs from local and remote candidate sets
    /// Returns pairs sorted by priority (highest first)
    pub fn form_pairs(
        local_candidates: &[IceCandidate],
        remote_candidates: &[IceCandidate],
        is_controlling: bool,
    ) -> Vec<CandidatePair> {
        let mut pairs = Vec::with_capacity(local_candidates.len() * remote_candidates.len());

        for local in local_candidates {
            for remote in remote_candidates {
                // Only pair candidates with matching components and protocols
                if local.component == remote.component && local.protocol == remote.protocol {
                    // Only pair candidates with compatible address families
                    let compatible = matches!(
                        (&local.address, &remote.address),
                        (SocketAddr::V4(_), SocketAddr::V4(_)) | (SocketAddr::V6(_), SocketAddr::V6(_))
                    );

                    if compatible {
                        pairs.push(CandidatePair::new(
                            local.clone(),
                            remote.clone(),
                            is_controlling,
                        ));
                    }
                }
            }
        }

        // Sort by priority (highest first)
        pairs.sort_by(|a, b| b.priority.cmp(&a.priority));

        // Prune redundant pairs (same foundation pair)
        pairs.dedup_by(|a, b| {
            a.local.foundation == b.local.foundation && a.remote.foundation == b.remote.foundation
        });

        pairs
    }
}

/// Collection of local ICE candidates with credentials
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LocalCandidates {
    /// Gathered candidates
    pub candidates: Vec<IceCandidate>,
    /// ICE username fragment (4+ characters)
    pub ufrag: String,
    /// ICE password (22+ characters)
    pub pwd: String,
}

impl LocalCandidates {
    /// Creates a new empty candidate collection with generated credentials
    pub fn new() -> Self {
        Self {
            candidates: Vec::new(),
            ufrag: Self::generate_credential(4),
            pwd: Self::generate_credential(22),
        }
    }

    /// Generates a random ICE credential of specified minimum length
    fn generate_credential(min_len: usize) -> String {
        const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";
        let mut rng = rand::thread_rng();

        (0..min_len)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }

    /// Adds a host candidate
    pub fn add_host(&mut self, addr: SocketAddr) {
        // Component 1 for QUIC (single component)
        let candidate = IceCandidate::host(addr, 1);
        self.candidates.push(candidate);
    }

    /// Adds a server reflexive candidate
    pub fn add_server_reflexive(
        &mut self,
        reflexive_addr: SocketAddr,
        base_addr: SocketAddr,
        stun_server: SocketAddr,
    ) {
        let candidate = IceCandidate::server_reflexive(reflexive_addr, base_addr, stun_server, 1);
        self.candidates.push(candidate);
    }

    /// Returns true if no candidates have been gathered
    pub fn is_empty(&self) -> bool {
        self.candidates.is_empty()
    }

    /// Returns the number of gathered candidates
    pub fn len(&self) -> usize {
        self.candidates.len()
    }

    /// Returns the highest priority candidate (typically host)
    pub fn best_candidate(&self) -> Option<&IceCandidate> {
        self.candidates.iter().max_by_key(|c| c.priority)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_priority_calculation() {
        // Host candidate should have highest priority
        let host_priority = IceCandidate::calculate_priority(CandidateType::Host, 65535, 1);
        let srflx_priority =
            IceCandidate::calculate_priority(CandidateType::ServerReflexive, 65535, 1);
        let relay_priority = IceCandidate::calculate_priority(CandidateType::Relay, 65535, 1);

        assert!(host_priority > srflx_priority);
        assert!(srflx_priority > relay_priority);
    }

    #[test]
    fn test_host_candidate_creation() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000);
        let candidate = IceCandidate::host(addr, 1);

        assert_eq!(candidate.candidate_type, CandidateType::Host);
        assert_eq!(candidate.address, addr);
        assert_eq!(candidate.component, 1);
        assert!(candidate.related_address.is_none());
    }

    #[test]
    fn test_server_reflexive_candidate() {
        let reflexive = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)), 12345);
        let base = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000);
        let stun = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 3478);

        let candidate = IceCandidate::server_reflexive(reflexive, base, stun, 1);

        assert_eq!(candidate.candidate_type, CandidateType::ServerReflexive);
        assert_eq!(candidate.address, reflexive);
        assert_eq!(candidate.related_address, Some(base));
        assert_eq!(candidate.stun_server, Some(stun));
    }

    #[test]
    fn test_pair_formation() {
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000);
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 200)), 6000);

        let local = vec![IceCandidate::host(local_addr, 1)];
        let remote = vec![IceCandidate::host(remote_addr, 1)];

        let pairs = CandidatePair::form_pairs(&local, &remote, true);

        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].local.address, local_addr);
        assert_eq!(pairs[0].remote.address, remote_addr);
        assert_eq!(pairs[0].state, CandidatePairState::Frozen);
    }

    #[test]
    fn test_pair_priority() {
        // Pair with higher controlling priority should have tie-breaker = 1
        let priority1 = CandidatePair::calculate_pair_priority(100, 50);
        let priority2 = CandidatePair::calculate_pair_priority(50, 100);

        // They should differ only in the tie-breaker bit
        assert_ne!(priority1, priority2);
    }

    #[test]
    fn test_local_candidates_credentials() {
        let candidates = LocalCandidates::new();

        assert!(candidates.ufrag.len() >= 4);
        assert!(candidates.pwd.len() >= 22);
        assert!(candidates.is_empty());
    }
}
