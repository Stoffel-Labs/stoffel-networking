use ark_ff::Field;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use thiserror::Error;

/// Error type for network related issues.
#[derive(Error, Debug, PartialEq)]
pub enum NetworkError {
    #[error("The message was not sent correctly")]
    SendError,
    /// The request reached a time out.
    #[error("timeout reached.")]
    Timeout,
    /// The party is not found in the network.
    #[error("the party with ID {0:?} is not in the network")]
    PartyNotFound(PartyId),
    #[error("the client with ID {0:?} is not connected")]
    ClientNotFound(ClientId),
}

/// Error type for consensus protocol failures.
#[derive(Error, Debug, Clone, PartialEq)]
pub enum ConsensusError {
    #[error("Node list mismatch from node at {node_address}")]
    NodeListMismatch { node_address: SocketAddr },
    #[error("Client list digest mismatch from party {party_id}")]
    ClientListDigestMismatch { party_id: PartyId },
    #[error("Timed out waiting for {expected} clients, only {connected} connected")]
    ClientReadinessTimeout { expected: usize, connected: usize },
    #[error("Timed out waiting for consensus from {missing_count} nodes")]
    ConsensusTimeout { missing_count: usize },
    #[error("Consensus query failed: {0}")]
    QueryFailed(String),
    #[error("Consensus aborted: {0}")]
    Aborted(String),
}

/// Drives the transparent gating of send/broadcast/send_to_client.
#[derive(Clone, Debug, PartialEq)]
pub enum ConsensusGate {
    /// No consensus required (expected_clients/expected_parties not set)
    NotRequired,
    /// Consensus in progress or waiting for connections
    Pending,
    /// Consensus succeeded
    Ready,
    /// Consensus failed
    Failed(String),
}

/// Verified canonical ordering of nodes and clients after consensus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOrdering {
    node_keys: Vec<NodePublicKey>,
    client_keys: Vec<NodePublicKey>,
}

impl VerifiedOrdering {
    pub fn new(node_keys: Vec<NodePublicKey>, client_keys: Vec<NodePublicKey>) -> Self {
        Self {
            node_keys,
            client_keys,
        }
    }

    pub fn node_count(&self) -> usize {
        self.node_keys.len()
    }

    pub fn client_count(&self) -> usize {
        self.client_keys.len()
    }

    pub fn party_id_for_node(&self, pk: &NodePublicKey) -> Option<PartyId> {
        self.node_keys.iter().position(|k| k == pk)
    }

    pub fn client_id_for_client(&self, pk: &NodePublicKey) -> Option<ClientId> {
        self.client_keys.iter().position(|k| k == pk)
    }

    pub fn node_key(&self, party_id: PartyId) -> Option<&NodePublicKey> {
        self.node_keys.get(party_id)
    }

    pub fn client_key(&self, client_id: ClientId) -> Option<&NodePublicKey> {
        self.client_keys.get(client_id)
    }

    pub fn node_keys(&self) -> &[NodePublicKey] {
        &self.node_keys
    }

    pub fn client_keys(&self) -> &[NodePublicKey] {
        &self.client_keys
    }
}

/// Type to identify a party in a protocol.
pub type PartyId = usize;
pub type ClientId = usize;

/// Represents a node's public key (DER-encoded SubjectPublicKeyInfo).
/// Used for deterministic sender_id computation across all participants.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodePublicKey(pub Vec<u8>);

impl NodePublicKey {
    /// Derives a stable ID from this public key.
    /// Uses a simple hash-like computation over the public key bytes.
    /// The result is deterministic and unique for different public keys.
    pub fn derive_id(&self) -> usize {
        // Use a simple FNV-1a-like hash for deterministic ID derivation
        const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
        const FNV_PRIME: u64 = 0x100000001b3;

        let mut hash = FNV_OFFSET_BASIS;
        for byte in &self.0 {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }

        // Convert to usize (truncate on 32-bit systems)
        hash as usize
    }
}

/// Describes how the remote endpoint identifies itself during the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientType {
    Server,
    Client,
}

/// Time that the network needs to wait until the operation returns a timeout.
pub type Timeout = usize;

/// Trait for messages sent in a protocol.
pub trait Message: Serialize + for<'a> Deserialize<'a> + Sized {
    /// Returns the ID of the sender of the message.
    fn sender_id(&self) -> PartyId;
    /// Returns the message as little endiand bytes.
    fn bytes(&self) -> &[u8];
}

/// Trait that represents a network used to communicate messages during the execution of a
/// protocol.
#[async_trait]
pub trait Network {
    /// Type of the node in the network.
    type NodeType: Node;
    /// Configuration of the network.
    type NetworkConfig;
    /// Send a message through the network to the given party. The function returns the number of
    /// bytes sent to the recipient.
    async fn send(&self, recipient: PartyId, message: &[u8]) -> Result<usize, NetworkError>;
    /// Broadcasts a message to all the parties connected to the network. The function returns the
    /// number of bytes broadcasted to the network.
    async fn broadcast(&self, message: &[u8]) -> Result<usize, NetworkError>;
    /// Returns the participants connected to this network.
    fn parties(&self) -> Vec<&Self::NodeType>;
    /// Returns mutable references to the participants connected to this network.
    fn parties_mut(&mut self) -> Vec<&mut Self::NodeType>;
    /// Returns the configuration of the network.
    fn config(&self) -> &Self::NetworkConfig;
    /// Returns the node with the given ID.
    fn node(&self, id: PartyId) -> Option<&Self::NodeType>;
    /// Returns a mutable reference of the node with the given ID.
    fn node_mut(&mut self, id: PartyId) -> Option<&mut Self::NodeType>;
    // --- server-to-client communication ---
    /// Send a message to a client.
    async fn send_to_client(&self, client: ClientId, message: &[u8])
        -> Result<usize, NetworkError>;

    /// Returns the connected clients.
    fn clients(&self) -> Vec<ClientId>;

    /// Checks whether a client is connected.
    fn is_client_connected(&self, client: ClientId) -> bool;

    // --- party identification ---

    /// Returns this node's party ID (0..N-1).
    fn local_party_id(&self) -> PartyId;

    /// Returns the number of parties in the network (including self).
    fn party_count(&self) -> usize;

    /// Returns the verified ordering if consensus has completed.
    fn verified_ordering(&self) -> Option<VerifiedOrdering>;
}

/// Participant of an MPC protocol.
pub trait Node: Send + Sync {
    /// Returns the ID of this node.
    fn id(&self) -> PartyId;
    /// Returns the ID of this node as a field element for protocol specific usage.
    fn scalar_id<F: Field>(&self) -> F;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_public_key_derive_id_consistency() {
        let key = NodePublicKey(vec![1, 2, 3, 4, 5]);
        let id_first = key.derive_id();
        let id_second = key.derive_id();
        assert_eq!(
            id_first, id_second,
            "derive_id must return the same value for the same key bytes"
        );
    }

    #[test]
    fn test_node_public_key_derive_id_different() {
        let key_a = NodePublicKey(vec![1, 2, 3]);
        let key_b = NodePublicKey(vec![4, 5, 6]);
        assert_ne!(
            key_a.derive_id(),
            key_b.derive_id(),
            "derive_id should return different values for different key bytes"
        );
    }

    #[test]
    fn test_network_error_display_non_empty() {
        let variants: Vec<NetworkError> = vec![
            NetworkError::SendError,
            NetworkError::Timeout,
            NetworkError::PartyNotFound(42),
            NetworkError::ClientNotFound(99),
        ];

        for error in &variants {
            let display = format!("{}", error);
            assert!(
                !display.is_empty(),
                "Display output for {:?} must not be empty",
                error
            );
        }
    }

    #[test]
    fn test_client_type_variants_distinct() {
        let server = ClientType::Server;
        let client = ClientType::Client;

        assert!(
            matches!(server, ClientType::Server),
            "server variant should match ClientType::Server"
        );
        assert!(
            !matches!(server, ClientType::Client),
            "server variant should not match ClientType::Client"
        );
        assert!(
            matches!(client, ClientType::Client),
            "client variant should match ClientType::Client"
        );
        assert!(
            !matches!(client, ClientType::Server),
            "client variant should not match ClientType::Server"
        );
    }

    #[test]
    fn test_node_public_key_derive_id_empty() {
        let key = NodePublicKey(vec![]);
        let id_first = key.derive_id();
        let id_second = key.derive_id();
        assert_eq!(
            id_first, id_second,
            "derive_id on empty bytes must be deterministic"
        );
    }

    // =========================================================================
    // ConsensusError tests
    // =========================================================================

    #[test]
    fn test_consensus_error_display() {
        let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let errors = vec![
            ConsensusError::NodeListMismatch { node_address: addr },
            ConsensusError::ClientListDigestMismatch { party_id: 2 },
            ConsensusError::ClientReadinessTimeout {
                expected: 3,
                connected: 1,
            },
            ConsensusError::ConsensusTimeout { missing_count: 2 },
            ConsensusError::QueryFailed("test".into()),
            ConsensusError::Aborted("test".into()),
        ];
        for error in &errors {
            let display = format!("{}", error);
            assert!(!display.is_empty());
        }
    }

    // =========================================================================
    // ConsensusGate tests
    // =========================================================================

    #[test]
    fn test_consensus_gate_variants() {
        assert_eq!(ConsensusGate::NotRequired, ConsensusGate::NotRequired);
        assert_eq!(ConsensusGate::Pending, ConsensusGate::Pending);
        assert_eq!(ConsensusGate::Ready, ConsensusGate::Ready);
        assert_eq!(
            ConsensusGate::Failed("err".into()),
            ConsensusGate::Failed("err".into())
        );
        assert_ne!(ConsensusGate::Pending, ConsensusGate::Ready);
    }

    #[test]
    fn test_consensus_gate_clone() {
        let gate = ConsensusGate::Failed("test error".into());
        let cloned = gate.clone();
        assert_eq!(gate, cloned);
    }

    // =========================================================================
    // VerifiedOrdering tests
    // =========================================================================

    #[test]
    fn test_verified_ordering_new() {
        let node_keys = vec![
            NodePublicKey(vec![1, 2, 3]),
            NodePublicKey(vec![4, 5, 6]),
        ];
        let client_keys = vec![NodePublicKey(vec![7, 8, 9])];
        let ordering = VerifiedOrdering::new(node_keys.clone(), client_keys.clone());

        assert_eq!(ordering.node_count(), 2);
        assert_eq!(ordering.client_count(), 1);
    }

    #[test]
    fn test_verified_ordering_party_id_for_node() {
        let pk_a = NodePublicKey(vec![1, 2, 3]);
        let pk_b = NodePublicKey(vec![4, 5, 6]);
        let ordering = VerifiedOrdering::new(vec![pk_a.clone(), pk_b.clone()], vec![]);

        assert_eq!(ordering.party_id_for_node(&pk_a), Some(0));
        assert_eq!(ordering.party_id_for_node(&pk_b), Some(1));
        assert_eq!(
            ordering.party_id_for_node(&NodePublicKey(vec![9, 9, 9])),
            None
        );
    }

    #[test]
    fn test_verified_ordering_client_id_for_client() {
        let ck_a = NodePublicKey(vec![10, 20]);
        let ck_b = NodePublicKey(vec![30, 40]);
        let ordering = VerifiedOrdering::new(vec![], vec![ck_a.clone(), ck_b.clone()]);

        assert_eq!(ordering.client_id_for_client(&ck_a), Some(0));
        assert_eq!(ordering.client_id_for_client(&ck_b), Some(1));
    }

    #[test]
    fn test_verified_ordering_key_accessors() {
        let pk = NodePublicKey(vec![1, 2]);
        let ck = NodePublicKey(vec![3, 4]);
        let ordering = VerifiedOrdering::new(vec![pk.clone()], vec![ck.clone()]);

        assert_eq!(ordering.node_key(0), Some(&pk));
        assert_eq!(ordering.node_key(1), None);
        assert_eq!(ordering.client_key(0), Some(&ck));
        assert_eq!(ordering.client_key(1), None);
        assert_eq!(ordering.node_keys(), &[pk]);
        assert_eq!(ordering.client_keys(), &[ck]);
    }

    #[test]
    fn test_verified_ordering_empty() {
        let ordering = VerifiedOrdering::new(vec![], vec![]);
        assert_eq!(ordering.node_count(), 0);
        assert_eq!(ordering.client_count(), 0);
        assert_eq!(ordering.node_key(0), None);
        assert_eq!(ordering.client_key(0), None);
    }
}
