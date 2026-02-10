
use ark_ff::Field;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
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
        assert_eq!(id_first, id_second, "derive_id must return the same value for the same key bytes");
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
}
