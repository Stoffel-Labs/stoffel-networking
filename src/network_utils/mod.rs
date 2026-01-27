
use ark_ff::Field;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A unified identifier type for network participants (parties and clients).
///
/// This type consolidates the previously separate `PartyId` and `ClientId` types
/// into a single `SenderId` type, providing cleaner semantics when dealing with
/// connections that can be either MPC parties or external clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub struct SenderId(pub usize);

impl SenderId {
    /// Creates a new SenderId from a raw value.
    pub const fn new(id: usize) -> Self {
        Self(id)
    }

    /// Returns the raw numeric value.
    pub const fn raw(&self) -> usize {
        self.0
    }
}

impl From<usize> for SenderId {
    fn from(id: usize) -> Self {
        Self(id)
    }
}

impl From<SenderId> for usize {
    fn from(id: SenderId) -> Self {
        id.0
    }
}

impl std::fmt::Display for SenderId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Type alias for backwards compatibility - use SenderId directly when possible.
pub type PartyId = SenderId;
/// Type alias for backwards compatibility - use SenderId directly when possible.
pub type ClientId = SenderId;

/// Error type for network related issues.
#[derive(Error, Debug, PartialEq)]
pub enum NetworkError {
    #[error("The message was not sent correctly")]
    SendError,
    /// The request reached a time out.
    #[error("timeout reached.")]
    Timeout,
    /// The party is not found in the network.
    #[error("the party with ID {0} is not in the network")]
    PartyNotFound(SenderId),
    #[error("the client with ID {0} is not connected")]
    ClientNotFound(SenderId),
}

/// Represents a node's public key (DER-encoded SubjectPublicKeyInfo).
/// Used for deterministic sender_id computation across all participants.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodePublicKey(pub Vec<u8>);

impl NodePublicKey {
    /// Derives a stable ID from this public key.
    /// Uses a simple hash-like computation over the public key bytes.
    /// The result is deterministic and unique for different public keys.
    pub fn derive_id(&self) -> SenderId {
        // Use a simple FNV-1a-like hash for deterministic ID derivation
        const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
        const FNV_PRIME: u64 = 0x100000001b3;

        let mut hash = FNV_OFFSET_BASIS;
        for byte in &self.0 {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(FNV_PRIME);
        }

        // Convert to usize (truncate on 32-bit systems)
        SenderId(hash as usize)
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
    fn sender_id(&self) -> SenderId;
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
}

/// Participant of an MPC protocol.
pub trait Node: Send + Sync {
    /// Returns the ID of this node.
    fn id(&self) -> SenderId;
    /// Returns the ID of this node as a field element for protocol specific usage.
    fn scalar_id<F: Field>(&self) -> F;
}
