//! # Peer-to-Peer Networking for StoffelVM (Actor Model Compatible)
//!
//! ## QUIC Stream Model
//!
//! This implementation uses persistent bidirectional streams with improved
//! connection state management and graceful handling of stream/connection closures.

use crate::network_utils::{
    ClientId, ClientType, Message, Network, NetworkError, Node, NodePublicKey, PartyId,
};
use crate::transports::ice::LocalCandidates;
use crate::transports::ice_agent::IceAgent;
use crate::transports::net_envelope::NetEnvelope;
use crate::transports::stun::StunClient;
use ark_ff::Field;
use async_trait::async_trait;
use dashmap::{DashMap, DashSet};
use quinn::{ClientConfig, Connection, Endpoint, IdleTimeout, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, trace, warn};
use uuid::Uuid;
use x509_parser::prelude::*;

// ============================================================================
// ALPN PROTOCOL IDENTIFIERS
// ============================================================================

/// ALPN protocol identifier for CLIENT role connections
const ALPN_CLIENT_PROTOCOL: &[u8] = b"client-protocol";
/// ALPN protocol identifier for SERVER role connections
const ALPN_SERVER_PROTOCOL: &[u8] = b"server-protocol";

// ============================================================================
// CONNECTION STATE
// ============================================================================

/// Represents the current state of a connection.
///
/// The state transitions are: `Connected` → `Closing` → `Closed`,
/// or `Connected` → `Disconnected` (for unexpected disconnections).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConnectionState {
    /// Connection is active and healthy (default state)
    #[default]
    Connected,
    /// Connection is gracefully closing
    Closing,
    /// Connection has been closed
    Closed,
    /// Connection failed/disconnected unexpectedly
    Disconnected,
}

// ============================================================================
// CUSTOM ERROR TYPE
// ============================================================================

/// Error type for connection operations.
///
/// These errors are returned by [`PeerConnection`] methods when operations fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionError {
    /// Stream closed gracefully by peer
    StreamClosed,
    /// Connection lost unexpectedly
    ConnectionLost(String),
    /// Send operation failed
    SendFailed(String),
    /// Receive operation failed
    ReceiveFailed(String),
    /// Message framing error
    FramingError(String),
    /// Connection initialization failed
    InitializationFailed(String),
    /// Connection is in invalid state for operation
    InvalidState(ConnectionState),
}

impl std::fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StreamClosed => write!(f, "Stream closed gracefully by peer"),
            Self::ConnectionLost(msg) => write!(f, "Connection lost: {}", msg),
            Self::SendFailed(msg) => write!(f, "Send failed: {}", msg),
            Self::ReceiveFailed(msg) => write!(f, "Receive failed: {}", msg),
            Self::FramingError(msg) => write!(f, "Framing error: {}", msg),
            Self::InitializationFailed(msg) => write!(f, "Initialization failed: {}", msg),
            Self::InvalidState(state) => write!(f, "Invalid connection state: {:?}", state),
        }
    }
}

impl std::error::Error for ConnectionError {}

// For backward compatibility with String errors
impl From<ConnectionError> for String {
    fn from(err: ConnectionError) -> String {
        err.to_string()
    }
}

// ============================================================================
// PEER CONNECTION TRAIT
// ============================================================================

/// Represents a connection to a peer
///
/// IMPORTANT: Uses interior mutability (Arc<Mutex<...>>) internally,
/// so it can be safely shared via Arc between multiple tasks.
pub trait PeerConnection: Send + Sync {
    /// Sends data to the peer
    fn send<'a>(
        &'a self,
        data: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

    /// Receives data from the peer
    fn receive<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>>;

    /// Returns the address of the remote peer
    fn remote_address(&self) -> SocketAddr;

    /// Closes the connection gracefully
    fn close<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

    /// Returns the current connection state
    fn state<'a>(&'a self) -> Pin<Box<dyn Future<Output = ConnectionState> + Send + 'a>>;

    /// Checks if the connection is still alive
    fn is_connected<'a>(&'a self) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;

    /// Returns how the remote peer identified itself in the handshake
    fn get_connection_role(&self) -> ClientType;

    /// Returns the party ID of the remote peer, if known.
    fn remote_party_id(&self) -> Option<PartyId>;

    /// Sets the party ID for this connection.
    /// Called by the network manager once all peers are connected.
    fn set_remote_party_id(&self, party_id: PartyId);
}

impl Debug for dyn PeerConnection {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PeerConnection {{ remote_address: {} }}",
            self.remote_address()
        )
    }
}

// ============================================================================
// NETWORK MANAGER TRAIT
// ============================================================================

pub trait NetworkManager: Send + Sync {
    fn connect<'a>(
        &'a mut self,
        address: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<dyn PeerConnection>, String>> + Send + 'a>>;

    fn accept<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<dyn PeerConnection>, String>> + Send + 'a>>;

    fn listen<'a>(
        &'a mut self,
        bind_address: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}

// ============================================================================
// MESSAGE FRAMING HELPERS
// ============================================================================

/// Maximum message size: 100MB
const MAX_MESSAGE_SIZE: usize = 100_000_000;

/// Sends a length-prefixed message with connection state checking
async fn send_framed_message(
    send: &mut quinn::SendStream,
    data: &[u8],
) -> Result<(), ConnectionError> {
    if data.len() > MAX_MESSAGE_SIZE {
        return Err(ConnectionError::FramingError(format!(
            "Message size {} exceeds maximum {}",
            data.len(),
            MAX_MESSAGE_SIZE
        )));
    }

    // Write 4-byte length prefix (big-endian)
    let len = data.len() as u32;
    send.write_all(&len.to_be_bytes()).await.map_err(|e| {
        // Check if this is a connection error
        if e.to_string().contains("closed") || e.to_string().contains("reset") {
            ConnectionError::ConnectionLost(format!("Connection lost while writing length: {}", e))
        } else {
            ConnectionError::SendFailed(format!("Failed to write length: {}", e))
        }
    })?;

    // Write message payload
    send.write_all(data).await.map_err(|e| {
        if e.to_string().contains("closed") || e.to_string().contains("reset") {
            ConnectionError::ConnectionLost(format!("Connection lost while writing payload: {}", e))
        } else {
            ConnectionError::SendFailed(format!("Failed to write payload: {}", e))
        }
    })?;

    Ok(())
}

/// Receives a length-prefixed message with better EOF handling
async fn recv_framed_message(recv: &mut quinn::RecvStream) -> Result<Vec<u8>, ConnectionError> {
    // Read 4-byte length prefix
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await.map_err(|e| match e {
        quinn::ReadExactError::FinishedEarly(_) => ConnectionError::StreamClosed,
        quinn::ReadExactError::ReadError(re) => {
            // Check if this is a connection lost scenario
            let err_str = re.to_string();
            if err_str.contains("closed")
                || err_str.contains("reset")
                || err_str.contains("connection lost")
            {
                ConnectionError::ConnectionLost(format!(
                    "Connection lost while reading length: {}",
                    re
                ))
            } else {
                ConnectionError::ReceiveFailed(format!("Failed to read length: {}", re))
            }
        }
    })?;

    let len = u32::from_be_bytes(len_buf) as usize;

    // Validate message size
    if len > MAX_MESSAGE_SIZE {
        return Err(ConnectionError::FramingError(format!(
            "Message size {} exceeds maximum {}",
            len, MAX_MESSAGE_SIZE
        )));
    }

    // Read message payload
    let mut msg = vec![0u8; len];
    recv.read_exact(&mut msg).await.map_err(|e| match e {
        quinn::ReadExactError::FinishedEarly(_) => ConnectionError::StreamClosed,
        quinn::ReadExactError::ReadError(re) => {
            let err_str = re.to_string();
            if err_str.contains("closed")
                || err_str.contains("reset")
                || err_str.contains("connection lost")
            {
                ConnectionError::ConnectionLost(format!(
                    "Connection lost while reading payload: {}",
                    re
                ))
            } else {
                ConnectionError::ReceiveFailed(format!("Failed to read payload: {}", re))
            }
        }
    })?;

    Ok(msg)
}

// ============================================================================
// QUIC PEER CONNECTION
// ============================================================================

/// A QUIC-based peer connection with persistent bidirectional streams.
///
/// This type implements [`PeerConnection`] using QUIC as the underlying transport.
/// It uses interior mutability (`Arc<Mutex<>>`) for safe sharing across async tasks.
///
/// # Drop Behavior
///
/// Dropping a `QuicPeerConnection` will close the underlying QUIC connection
/// immediately without waiting for graceful shutdown. For graceful closure,
/// call [`close()`](PeerConnection::close) and await it before dropping.
#[derive(Clone)]
pub struct QuicPeerConnection {
    connection: Connection,
    remote_addr: SocketAddr,
    /// Persistent send stream - uses interior mutability for sharing
    send_stream: Arc<Mutex<quinn::SendStream>>,
    /// Persistent receive stream - uses interior mutability for sharing
    recv_stream: Arc<Mutex<quinn::RecvStream>>,
    /// Connection state
    state: Arc<Mutex<ConnectionState>>,
    connection_role: ClientType,
    /// Peer's public key extracted from TLS certificate
    peer_public_key: Option<NodePublicKey>,
    /// Remote peer's party ID (set by manager after connection)
    remote_party_id: Arc<std::sync::Mutex<Option<PartyId>>>,
}

impl std::fmt::Debug for QuicPeerConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicPeerConnection")
            .field("remote_addr", &self.remote_addr)
            .field("connection_role", &self.connection_role)
            .field("peer_public_key", &self.peer_public_key.is_some())
            .field("remote_party_id", &self.remote_party_id.lock().ok())
            .finish_non_exhaustive()
    }
}

impl QuicPeerConnection {
    /// Creates a new connection with an already-opened bidirectional stream
    pub fn new(
        connection: Connection,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        connection_role: ClientType,
        peer_public_key: Option<NodePublicKey>,
    ) -> Self {
        let remote_addr = connection.remote_address();
        Self {
            connection,
            remote_addr,
            send_stream: Arc::new(Mutex::new(send)),
            recv_stream: Arc::new(Mutex::new(recv)),
            state: Arc::new(Mutex::new(ConnectionState::Connected)),
            connection_role,
            peer_public_key,
            remote_party_id: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Creates a new connection and immediately opens a bidirectional stream
    pub async fn new_with_connection(
        connection: Connection,
        connection_role: ClientType,
        peer_public_key: Option<NodePublicKey>,
    ) -> Result<Self, ConnectionError> {
        let remote_addr = connection.remote_address();
        let (send, recv) = connection.open_bi().await.map_err(|e| {
            ConnectionError::InitializationFailed(format!("Failed to open stream: {}", e))
        })?;

        Ok(Self {
            connection,
            remote_addr,
            send_stream: Arc::new(Mutex::new(send)),
            recv_stream: Arc::new(Mutex::new(recv)),
            state: Arc::new(Mutex::new(ConnectionState::Connected)),
            connection_role,
            peer_public_key,
            remote_party_id: Arc::new(std::sync::Mutex::new(None)),
        })
    }

    /// Returns the peer's public key if available
    pub fn get_peer_public_key(&self) -> Option<&NodePublicKey> {
        self.peer_public_key.as_ref()
    }

    /// Sets the remote party ID (called by manager once all peers are connected)
    pub fn set_remote_party_id(&self, party_id: PartyId) {
        if let Ok(mut id) = self.remote_party_id.lock() {
            *id = Some(party_id);
        }
    }

    /// Gets the remote party ID if set
    pub fn get_remote_party_id(&self) -> Option<PartyId> {
        self.remote_party_id.lock().ok().and_then(|id| *id)
    }

    /// Updates connection state
    async fn update_state(&self, new_state: ConnectionState) {
        let mut state = self.state.lock().await;
        *state = new_state;
    }

    /// Checks the underlying QUIC connection health
    async fn check_connection_health(&self) -> bool {
        // Check if the connection is closed
        if let Some(_err) = self.connection.close_reason() {
            return false;
        }
        true
    }
}

impl PeerConnection for QuicPeerConnection {
    fn send<'a>(
        &'a self,
        data: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            // Check state before sending
            {
                let state = self.state.lock().await;
                match *state {
                    ConnectionState::Closed | ConnectionState::Disconnected => {
                        return Err(format!("Cannot send: connection is {:?}", *state));
                    }
                    ConnectionState::Closing => {
                        return Err("Cannot send: connection is closing".to_string());
                    }
                    _ => {}
                }
            }

            let mut send_guard = self.send_stream.lock().await;
            match send_framed_message(&mut *send_guard, data).await {
                Ok(()) => Ok(()),
                Err(ConnectionError::ConnectionLost(msg)) => {
                    self.update_state(ConnectionState::Disconnected).await;
                    Err(format!("Connection lost: {}", msg))
                }
                Err(ConnectionError::StreamClosed) => {
                    self.update_state(ConnectionState::Closed).await;
                    Err("Stream closed by peer".to_string())
                }
                Err(e) => Err(e.to_string()),
            }
        })
    }

    fn receive<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
        Box::pin(async move {
            // Check state before receiving
            {
                let state = self.state.lock().await;
                match *state {
                    ConnectionState::Closed | ConnectionState::Disconnected => {
                        return Err(format!("Cannot receive: connection is {:?}", *state));
                    }
                    _ => {}
                }
            }

            let mut recv_guard = self.recv_stream.lock().await;
            match recv_framed_message(&mut *recv_guard).await {
                Ok(data) => Ok(data),
                Err(ConnectionError::ConnectionLost(msg)) => {
                    self.update_state(ConnectionState::Disconnected).await;
                    Err(format!("Connection lost: {}", msg))
                }
                Err(ConnectionError::StreamClosed) => {
                    self.update_state(ConnectionState::Closed).await;
                    Err("Stream closed by peer".to_string())
                }
                Err(e) => Err(e.to_string()),
            }
        })
    }

    fn remote_address(&self) -> SocketAddr {
        self.remote_addr
    }

    fn close<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            self.update_state(ConnectionState::Closing).await;
            self.connection
                .close(0u32.into(), b"Connection closed gracefully");
            self.update_state(ConnectionState::Closed).await;
            Ok(())
        })
    }

    fn state<'a>(&'a self) -> Pin<Box<dyn Future<Output = ConnectionState> + Send + 'a>> {
        Box::pin(async move {
            let state = self.state.lock().await;
            *state
        })
    }

    fn is_connected<'a>(&'a self) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            let state = self.state.lock().await;
            match *state {
                ConnectionState::Connected => self.check_connection_health().await,
                _ => false,
            }
        })
    }

    fn get_connection_role(&self) -> ClientType {
        self.connection_role
    }

    fn remote_party_id(&self) -> Option<PartyId> {
        self.get_remote_party_id()
    }

    fn set_remote_party_id(&self, party_id: PartyId) {
        if let Ok(mut id) = self.remote_party_id.lock() {
            *id = Some(party_id);
        }
    }
}

// ============================================================================
// LOOPBACK PEER CONNECTION (for self-delivery)
// ============================================================================

/// A loopback peer connection for self-delivery.
///
/// This type implements [`PeerConnection`] using in-memory channels,
/// allowing a node to send messages to itself without network I/O.
/// Used for MPC protocols where a party may need to process its own messages.
pub struct LoopbackPeerConnection {
    remote_addr: SocketAddr,
    tx: mpsc::Sender<Vec<u8>>,
    rx: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    state: Arc<Mutex<ConnectionState>>,
    connection_role: ClientType,
    remote_party_id: Arc<std::sync::Mutex<Option<PartyId>>>,
}

impl std::fmt::Debug for LoopbackPeerConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoopbackPeerConnection")
            .field("remote_addr", &self.remote_addr)
            .field("connection_role", &self.connection_role)
            .field("remote_party_id", &self.remote_party_id.lock().ok())
            .finish_non_exhaustive()
    }
}

impl LoopbackPeerConnection {
    pub fn new(remote_addr: SocketAddr, party_id: Option<PartyId>) -> Self {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(1024);
        Self {
            remote_addr,
            tx,
            rx: Arc::new(Mutex::new(rx)),
            state: Arc::new(Mutex::new(ConnectionState::Connected)),
            connection_role: ClientType::Server,
            remote_party_id: Arc::new(std::sync::Mutex::new(party_id)),
        }
    }

    /// Helper to create a framed message (for consistency with QUIC)
    fn frame_message(data: &[u8]) -> Vec<u8> {
        let len = data.len() as u32;
        let mut framed = Vec::with_capacity(4 + data.len());
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(data);
        framed
    }

    /// Helper to unframe a message (for consistency with QUIC)
    fn unframe_message(framed: Vec<u8>) -> Result<Vec<u8>, ConnectionError> {
        if framed.len() < 4 {
            return Err(ConnectionError::FramingError(
                "Message too short".to_string(),
            ));
        }

        let len_bytes: [u8; 4] = framed[0..4].try_into().unwrap();
        let len = u32::from_be_bytes(len_bytes) as usize;

        if framed.len() != 4 + len {
            return Err(ConnectionError::FramingError(format!(
                "Length mismatch: expected {}, got {}",
                len,
                framed.len() - 4
            )));
        }

        Ok(framed[4..].to_vec())
    }

    /// Updates connection state
    async fn update_state(&self, new_state: ConnectionState) {
        let mut state = self.state.lock().await;
        *state = new_state;
    }
}

impl PeerConnection for LoopbackPeerConnection {
    fn send<'a>(
        &'a self,
        data: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            // Check state
            {
                let state = self.state.lock().await;
                if *state != ConnectionState::Connected {
                    return Err(format!("Cannot send: loopback connection is {:?}", *state));
                }
            }

            let framed = Self::frame_message(data);
            self.tx.send(framed).await.map_err(|e| {
                // Channel closed - update state
                tokio::spawn({
                    let state = self.state.clone();
                    async move {
                        let mut s = state.lock().await;
                        *s = ConnectionState::Closed;
                    }
                });
                format!("Loopback send failed: {}", e)
            })
        })
    }

    fn receive<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
        Box::pin(async move {
            // Check state
            {
                let state = self.state.lock().await;
                if *state == ConnectionState::Closed || *state == ConnectionState::Disconnected {
                    return Err(format!(
                        "Cannot receive: loopback connection is {:?}",
                        *state
                    ));
                }
            }

            let mut rx = self.rx.lock().await;
            match rx.recv().await {
                Some(framed) => Self::unframe_message(framed).map_err(|e| e.to_string()),
                None => {
                    self.update_state(ConnectionState::Closed).await;
                    Err("Loopback connection closed".to_string())
                }
            }
        })
    }

    fn remote_address(&self) -> SocketAddr {
        self.remote_addr
    }

    fn close<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            self.update_state(ConnectionState::Closing).await;
            // For loopback, we just update state - channel will close when dropped
            self.update_state(ConnectionState::Closed).await;
            Ok(())
        })
    }

    fn state<'a>(&'a self) -> Pin<Box<dyn Future<Output = ConnectionState> + Send + 'a>> {
        Box::pin(async move {
            let state = self.state.lock().await;
            *state
        })
    }

    fn is_connected<'a>(&'a self) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            let state = self.state.lock().await;
            *state == ConnectionState::Connected
        })
    }

    fn get_connection_role(&self) -> ClientType {
        self.connection_role
    }

    fn remote_party_id(&self) -> Option<PartyId> {
        self.remote_party_id.lock().ok().and_then(|id| *id)
    }

    fn set_remote_party_id(&self, party_id: PartyId) {
        if let Ok(mut id) = self.remote_party_id.lock() {
            *id = Some(party_id);
        }
    }
}

// ============================================================================
// STREAM SYNCHRONIZATION
// ============================================================================

/// Sync byte sent by the initiator to establish the bidirectional stream
const STREAM_SYNC_BYTE: u8 = 0xFF;

/// Sends a sync byte to establish the stream (called by connection initiator)
async fn send_stream_sync(send: &mut quinn::SendStream) -> Result<(), ConnectionError> {
    send.write_all(&[STREAM_SYNC_BYTE])
        .await
        .map_err(|e| ConnectionError::SendFailed(format!("Failed to send sync: {}", e)))
}

/// Receives the sync byte to acknowledge stream establishment (called by connection acceptor)
async fn recv_stream_sync(recv: &mut quinn::RecvStream) -> Result<(), ConnectionError> {
    let mut buf = [0u8; 1];
    recv.read_exact(&mut buf).await.map_err(|e| match e {
        quinn::ReadExactError::FinishedEarly(_) => ConnectionError::StreamClosed,
        quinn::ReadExactError::ReadError(re) => {
            ConnectionError::ReceiveFailed(format!("Failed to receive sync: {}", re))
        }
    })?;

    if buf[0] != STREAM_SYNC_BYTE {
        return Err(ConnectionError::FramingError(format!(
            "Invalid sync byte: expected {:#x}, got {:#x}",
            STREAM_SYNC_BYTE, buf[0]
        )));
    }

    Ok(())
}

// ============================================================================
// ALPN HELPERS
// ============================================================================

/// Extracts the negotiated ALPN protocol from a QUIC connection and returns the ClientType
fn extract_alpn_role(connection: &Connection) -> Result<ClientType, String> {
    let handshake_data = connection
        .handshake_data()
        .ok_or_else(|| "No handshake data available".to_string())?;

    let handshake = handshake_data
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .map_err(|_| "Failed to downcast handshake data to rustls type".to_string())?;

    match handshake.protocol.as_ref().map(|v| v.as_slice()) {
        Some(proto) if proto == ALPN_CLIENT_PROTOCOL => {
            trace!("ALPN negotiated: client-protocol");
            Ok(ClientType::Client)
        }
        Some(proto) if proto == ALPN_SERVER_PROTOCOL => {
            trace!("ALPN negotiated: server-protocol");
            Ok(ClientType::Server)
        }
        Some(proto) => {
            let proto_str = String::from_utf8_lossy(proto);
            warn!("Unknown ALPN protocol: {}", proto_str);
            Err(format!("Unknown ALPN protocol: {}", proto_str))
        }
        None => {
            warn!("No ALPN protocol negotiated");
            Err("No ALPN protocol negotiated".to_string())
        }
    }
}

// ============================================================================
// QUIC NODE
// ============================================================================

/// A network node identified by UUID and socket address.
///
/// `QuicNode` represents a participant in the MPC network. Each node has a
/// unique UUID and a network address where it can be reached.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct QuicNode {
    uuid: Uuid,
    address: SocketAddr,
}

impl QuicNode {
    pub fn new_with_random_id(address: SocketAddr) -> Self {
        Self {
            uuid: Uuid::new_v4(),
            address,
        }
    }

    pub fn new(uuid: Uuid, address: SocketAddr) -> Self {
        Self { uuid, address }
    }

    pub fn from_party_id(id: PartyId, address: SocketAddr) -> Self {
        let uuid = Uuid::from_u128(id as u128);
        Self { uuid, address }
    }

    pub fn address(&self) -> SocketAddr {
        self.address
    }

    pub fn uuid(&self) -> Uuid {
        self.uuid
    }
}

impl Node for QuicNode {
    fn id(&self) -> PartyId {
        self.uuid.as_u128() as PartyId
    }

    fn scalar_id<F: Field>(&self) -> F {
        F::from(self.uuid.as_u128())
    }
}

// ============================================================================
// NETWORK CONFIG AND MESSAGE
// ============================================================================

/// Configuration for the QUIC network manager.
///
/// Controls connection timeouts, TLS settings, and NAT traversal options.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuicNetworkConfig {
    /// Connection timeout in milliseconds
    pub timeout_ms: u64,
    /// Maximum connection retry attempts
    pub max_retries: u32,
    /// Enable TLS encryption (should be true for production)
    pub use_tls: bool,

    // NAT Traversal Configuration
    /// Enable NAT traversal features
    pub enable_nat_traversal: bool,
    /// STUN servers for reflexive address discovery
    pub stun_servers: Vec<SocketAddr>,
    /// Enable hole punching for peer-to-peer connections
    pub enable_hole_punching: bool,
    /// Timeout for hole punching attempts (milliseconds)
    pub hole_punch_timeout_ms: u64,
    /// ICE agent configuration
    pub ice_config: crate::transports::ice_agent::IceAgentConfig,
}

impl Default for QuicNetworkConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 30000,
            max_retries: 3,
            use_tls: true,
            enable_nat_traversal: false,
            // Default to empty - STUN servers require DNS resolution which isn't supported
            // by SocketAddr. Users should configure STUN servers with resolved IP addresses.
            stun_servers: vec![],
            enable_hole_punching: true,
            hole_punch_timeout_ms: 10000,
            ice_config: crate::transports::ice_agent::IceAgentConfig::default(),
        }
    }
}

/// Configuration validation errors for [`QuicNetworkConfig`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuicConfigError {
    /// Timeout must be positive
    InvalidTimeout,
    /// ICE configuration is invalid
    InvalidIceConfig(crate::transports::ice_agent::ConfigError),
}

impl std::fmt::Display for QuicConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTimeout => write!(f, "Timeout must be positive"),
            Self::InvalidIceConfig(err) => write!(f, "Invalid ICE configuration: {}", err),
        }
    }
}

impl std::error::Error for QuicConfigError {}

impl From<crate::transports::ice_agent::ConfigError> for QuicConfigError {
    fn from(err: crate::transports::ice_agent::ConfigError) -> Self {
        QuicConfigError::InvalidIceConfig(err)
    }
}

impl QuicNetworkConfig {
    /// Validates the configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `timeout_ms` is zero
    /// - The embedded `ice_config` fails validation
    ///
    /// # Note
    ///
    /// If `enable_nat_traversal` is true but `stun_servers` is empty, the configuration
    /// is still valid, but NAT traversal will not discover reflexive addresses.
    pub fn validate(&self) -> Result<(), QuicConfigError> {
        if self.timeout_ms == 0 {
            return Err(QuicConfigError::InvalidTimeout);
        }
        self.ice_config.validate()?;
        Ok(())
    }

    /// Creates a config with NAT traversal enabled
    pub fn with_nat_traversal() -> Self {
        Self {
            enable_nat_traversal: true,
            ..Default::default()
        }
    }

    /// Sets custom STUN servers
    pub fn stun_servers(mut self, servers: Vec<SocketAddr>) -> Self {
        self.stun_servers = servers;
        self
    }

    /// Enables or disables NAT traversal
    pub fn nat_traversal(mut self, enabled: bool) -> Self {
        self.enable_nat_traversal = enabled;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicMessage {
    sender_id: PartyId,
    content: Vec<u8>,
}

impl QuicMessage {
    pub fn new(sender_id: PartyId, content: Vec<u8>) -> Self {
        Self { sender_id, content }
    }

    pub fn content(&self) -> &[u8] {
        &self.content
    }
}

impl Message for QuicMessage {
    fn sender_id(&self) -> PartyId {
        self.sender_id
    }

    fn bytes(&self) -> &[u8] {
        &self.content
    }
}

// ============================================================================
// QUIC NETWORK MANAGER (Actor-Compatible)
// ============================================================================

/// QUIC-based network manager for MPC peer-to-peer communication.
///
/// `QuicNetworkManager` is the primary entry point for establishing and managing
/// network connections in stoffelnet. It implements both [`NetworkManager`] and
/// [`Network`] traits, providing both low-level connection management and
/// high-level MPC-oriented messaging.
///
/// # Features
///
/// - Manages both peer-to-peer (server) and client connections
/// - Supports NAT traversal via ICE/STUN when configured
/// - Automatically generates and manages TLS certificates
/// - Thread-safe with `Arc<DashMap<>>` for concurrent access
///
/// # Example
///
/// ```no_run
/// use stoffelnet::transports::quic::{QuicNetworkManager, QuicNetworkConfig};
///
/// // Create with default configuration
/// let manager = QuicNetworkManager::new();
///
/// // Or with custom configuration
/// let config = QuicNetworkConfig {
///     timeout_ms: 5000,
///     max_retries: 5,
///     ..Default::default()
/// };
/// let manager = QuicNetworkManager::with_config(config);
/// ```
#[derive(Clone)]
pub struct QuicNetworkManager {
    endpoint: Option<Endpoint>,
    nodes: Vec<QuicNode>,
    node_id: PartyId,
    network_config: QuicNetworkConfig,
    /// Server-role connections (peer-to-peer MPC party connections)
    server_connections: Arc<DashMap<PartyId, Arc<dyn PeerConnection>>>,
    /// Client-role connections (external clients connected to this server)
    client_connections: Arc<DashMap<ClientId, Arc<dyn PeerConnection>>>,
    /// Replaced Mutex<HashSet> with DashSet for client IDs
    client_ids: Arc<DashSet<ClientId>>,
    /// Persistent certificate for this node (generated once)
    /// Stored as DER-encoded certificate and private key
    local_cert_der: Option<Vec<u8>>,
    local_key_der: Option<Vec<u8>>,
    /// This node's public key (derived from local_certificate)
    local_public_key: Option<NodePublicKey>,
    /// Connected peers' public keys (for sender_id computation)
    peer_public_keys: Arc<DashMap<PartyId, NodePublicKey>>,
    /// STUN client for NAT traversal
    stun_client: Option<Arc<StunClient>>,
    /// Cached local ICE candidates
    local_candidates: Arc<Mutex<Option<LocalCandidates>>>,
    /// Pending ICE agents for hole punching
    pending_ice_agents: Arc<DashMap<PartyId, IceAgent>>,
}

impl std::fmt::Debug for QuicNetworkManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicNetworkManager")
            .field("node_id", &self.node_id)
            .field("endpoint_bound", &self.endpoint.is_some())
            .field("nodes_count", &self.nodes.len())
            .field("server_connections_count", &self.server_connections.len())
            .field("client_connections_count", &self.client_connections.len())
            .field("has_local_cert", &self.local_cert_der.is_some())
            .field(
                "nat_traversal_enabled",
                &self.network_config.enable_nat_traversal,
            )
            .finish_non_exhaustive()
    }
}

impl Default for QuicNetworkManager {
    fn default() -> Self {
        Self::new()
    }
}

impl QuicNetworkManager {
    pub fn new() -> Self {
        let node_id = Uuid::new_v4().as_u128() as PartyId;
        Self {
            endpoint: None,
            nodes: Vec::new(),
            node_id,
            network_config: QuicNetworkConfig::default(),
            server_connections: Arc::new(DashMap::new()),
            client_connections: Arc::new(DashMap::new()),
            client_ids: Arc::new(DashSet::new()),
            local_cert_der: None,
            local_key_der: None,
            local_public_key: None,
            peer_public_keys: Arc::new(DashMap::new()),
            stun_client: None,
            local_candidates: Arc::new(Mutex::new(None)),
            pending_ice_agents: Arc::new(DashMap::new()),
        }
    }

    pub fn with_node_id(node_id: PartyId) -> Self {
        let mut manager = Self::new();
        manager.node_id = node_id;
        manager
    }

    /// Creates a network manager with the given configuration.
    ///
    /// # Panics
    ///
    /// In debug builds, panics if the configuration is invalid (e.g., zero timeout,
    /// NAT traversal enabled without STUN servers). Use [`try_with_config`](Self::try_with_config)
    /// for fallible construction.
    pub fn with_config(config: QuicNetworkConfig) -> Self {
        debug_assert!(
            config.validate().is_ok(),
            "Invalid QuicNetworkConfig: {:?}",
            config.validate().unwrap_err()
        );

        Self::create_from_config(config)
    }

    /// Creates a network manager with the given configuration, validating it first.
    ///
    /// # Errors
    ///
    /// Returns an error if the configuration is invalid. See [`QuicNetworkConfig::validate`]
    /// for details on validation rules.
    pub fn try_with_config(config: QuicNetworkConfig) -> Result<Self, QuicConfigError> {
        config.validate()?;
        Ok(Self::create_from_config(config))
    }

    /// Internal constructor used by both `with_config` and `try_with_config`.
    fn create_from_config(config: QuicNetworkConfig) -> Self {
        let stun_client = if config.enable_nat_traversal {
            let stun_servers = config
                .stun_servers
                .iter()
                .map(|addr| crate::transports::stun::StunServerConfig::new(*addr))
                .collect();
            Some(Arc::new(crate::transports::stun::StunClient::new(
                stun_servers,
            )))
        } else {
            None
        };

        Self {
            endpoint: None,
            nodes: Vec::new(),
            node_id: Uuid::new_v4().as_u128() as PartyId,
            network_config: config,
            server_connections: Arc::new(DashMap::new()),
            client_connections: Arc::new(DashMap::new()),
            client_ids: Arc::new(DashSet::new()),
            local_cert_der: None,
            local_key_der: None,
            local_public_key: None,
            peer_public_keys: Arc::new(DashMap::new()),
            stun_client,
            local_candidates: Arc::new(Mutex::new(None)),
            pending_ice_agents: Arc::new(DashMap::new()),
        }
    }

    /// Creates a manager with NAT traversal enabled
    pub fn with_nat_traversal() -> Self {
        Self::with_config(QuicNetworkConfig::with_nat_traversal())
    }

    pub fn add_node(&mut self, node: QuicNode) {
        self.nodes.push(node);
    }

    pub fn add_node_with_party_id(&mut self, id: PartyId, address: SocketAddr) {
        self.nodes.push(QuicNode::from_party_id(id, address));
    }

    /// Ensures loopback connection exists for self-delivery
    pub async fn ensure_loopback_installed(&self) {
        if !self.server_connections.contains_key(&self.node_id) {
            let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            self.server_connections.insert(
                self.node_id,
                Arc::new(LoopbackPeerConnection::new(
                    addr,
                    Some(self.local_derived_id()),
                )) as Arc<dyn PeerConnection>,
            );
        }
    }

    /// Gets a server connection by party ID
    pub async fn get_connection(&self, party_id: PartyId) -> Option<Arc<dyn PeerConnection>> {
        self.server_connections
            .get(&party_id)
            .map(|entry| Arc::clone(entry.value()))
    }

    /// Gets all server connections (peer-to-peer MPC party connections)
    pub fn get_all_server_connections(&self) -> Vec<(PartyId, Arc<dyn PeerConnection>)> {
        self.server_connections
            .iter()
            .map(|entry| (*entry.key(), Arc::clone(entry.value())))
            .collect()
    }

    /// Gets all client connections (external clients connected to this server)
    pub fn get_all_client_connections(&self) -> Vec<(ClientId, Arc<dyn PeerConnection>)> {
        self.client_connections
            .iter()
            .map(|entry| (*entry.key(), Arc::clone(entry.value())))
            .collect()
    }

    /// Gets a specific client connection by ID
    pub fn get_client_connection(&self, client_id: ClientId) -> Option<Arc<dyn PeerConnection>> {
        self.client_connections
            .get(&client_id)
            .map(|entry| Arc::clone(entry.value()))
    }

    /// Removes dead connections from both server and client connection maps
    pub async fn cleanup_dead_connections(&self) {
        let mut to_remove = Vec::new();

        for entry in self.server_connections.iter() {
            let party_id = *entry.key();
            let conn = entry.value();
            if !conn.is_connected().await {
                to_remove.push(party_id);
            }
        }

        for party_id in to_remove {
            self.server_connections.remove(&party_id);
        }

        let mut clients_to_remove = Vec::new();

        for entry in self.client_connections.iter() {
            let client_id = *entry.key();
            let conn = entry.value();
            if !conn.is_connected().await {
                clients_to_remove.push(client_id);
            }
        }

        for client_id in clients_to_remove {
            self.client_connections.remove(&client_id);
            self.client_ids.remove(&client_id);
        }
    }

    /// Checks connection health for a specific party
    pub async fn is_party_connected(&self, party_id: PartyId) -> bool {
        if let Some(conn_ref) = self.server_connections.get(&party_id) {
            conn_ref.value().is_connected().await
        } else {
            false
        }
    }

    /// Creates insecure client config (for development only)
    /// The role parameter determines which ALPN protocol to advertise:
    /// - ClientType::Client -> ALPN_CLIENT_PROTOCOL
    /// - ClientType::Server -> ALPN_SERVER_PROTOCOL
    ///
    /// If cert_der and key_der are provided, the client will present a certificate
    /// during TLS handshake (mutual TLS).
    fn create_insecure_client_config(
        role: ClientType,
        cert_der: Option<&[u8]>,
        key_der: Option<&[u8]>,
    ) -> Result<ClientConfig, String> {
        let mut crypto = match (cert_der, key_der) {
            (Some(cert), Some(key)) => {
                // Mutual TLS: client presents certificate
                let cert_chain = vec![CertificateDer::from(cert.to_vec())];
                let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.to_vec()));

                rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(SkipServerVerification::new()))
                    .with_client_auth_cert(cert_chain, private_key)
                    .map_err(|e| format!("Failed to configure client certificate: {}", e))?
            }
            _ => {
                // No client certificate
                rustls::ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(SkipServerVerification::new()))
                    .with_no_client_auth()
            }
        };

        // Set ALPN based on role
        crypto.alpn_protocols = match role {
            ClientType::Client => vec![ALPN_CLIENT_PROTOCOL.to_vec()],
            ClientType::Server => vec![ALPN_SERVER_PROTOCOL.to_vec()],
        };

        let mut config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| format!("Failed to create QUIC client config: {}", e))?,
        ));

        config.transport_config(Arc::new({
            let mut transport = quinn::TransportConfig::default();
            transport.max_concurrent_uni_streams(0u32.into());
            transport.keep_alive_interval(Some(Duration::from_secs(5)));
            transport.max_idle_timeout(Some(IdleTimeout::from(quinn::VarInt::from_u32(300_000))));
            transport
        }));

        Ok(config)
    }

    /// Creates self-signed server config using provided DER-encoded certificate and key.
    /// Accepts both ALPN_SERVER_PROTOCOL and ALPN_CLIENT_PROTOCOL for incoming connections.
    /// Requests (but doesn't require) client certificates for mutual TLS.
    fn create_self_signed_server_config(
        cert_der_bytes: &[u8],
        key_der_bytes: &[u8],
    ) -> Result<ServerConfig, String> {
        let cert_der = CertificateDer::from(cert_der_bytes.to_vec());
        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der_bytes.to_vec()));

        // Use custom client cert verifier that accepts all client certificates
        // This enables mutual TLS where clients can optionally present certificates
        let mut server_crypto = rustls::ServerConfig::builder()
            .with_client_cert_verifier(SkipClientVerification::new())
            .with_single_cert(vec![cert_der], key_der)
            .map_err(|e| format!("Failed to create server crypto config: {}", e))?;

        // Accept both ALPN protocols for incoming connections
        server_crypto.alpn_protocols =
            vec![ALPN_SERVER_PROTOCOL.to_vec(), ALPN_CLIENT_PROTOCOL.to_vec()];

        let mut server_config = ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
                .map_err(|e| format!("Failed to create QUIC server config: {}", e))?,
        ));

        let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
        transport_config.max_concurrent_uni_streams(0u32.into());
        transport_config.keep_alive_interval(Some(Duration::from_secs(5)));
        transport_config
            .max_idle_timeout(Some(IdleTimeout::from(quinn::VarInt::from_u32(300_000))));

        Ok(server_config)
    }

    /// Ensures endpoint is initialized with client config for the specified role.
    /// Also ensures a local certificate exists for mutual TLS.
    async fn ensure_client_endpoint(&mut self, role: ClientType) -> Result<(), String> {
        // Ensure we have a local certificate for mTLS
        self.ensure_local_certificate()?;

        if self.endpoint.is_none() {
            let client_config = Self::create_insecure_client_config(
                role,
                self.local_cert_der.as_deref(),
                self.local_key_der.as_deref(),
            )?;
            let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
                .map_err(|e| format!("Failed to create client endpoint: {}", e))?;
            endpoint.set_default_client_config(client_config);
            self.endpoint = Some(endpoint);
        }
        Ok(())
    }

    // ============================================================================
    // CERTIFICATE AND PUBLIC KEY MANAGEMENT
    // ============================================================================

    /// Ensures a local certificate is generated and stored as DER bytes.
    fn ensure_local_certificate(&mut self) -> Result<(), String> {
        if self.local_cert_der.is_none() {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
                .map_err(|e| format!("Failed to generate certificate: {}", e))?;

            // Store DER-encoded certificate and key
            let cert_der = cert.cert.der().to_vec();
            let key_der = cert.signing_key.serialize_der();

            // Extract and store public key
            let public_key = Self::extract_public_key_from_cert(&cert_der)?;
            self.local_public_key = Some(public_key);

            self.local_cert_der = Some(cert_der);
            self.local_key_der = Some(key_der);
            trace!("Generated and stored local certificate");
        }
        Ok(())
    }

    /// Extracts the SubjectPublicKeyInfo (SPKI) from a DER-encoded X.509 certificate
    fn extract_public_key_from_cert(cert_der: &[u8]) -> Result<NodePublicKey, String> {
        let (_, cert) = X509Certificate::from_der(cert_der)
            .map_err(|e| format!("Failed to parse X.509 certificate: {:?}", e))?;

        // Get the SubjectPublicKeyInfo in DER format
        let spki = cert.public_key();
        let spki_der = spki.raw.to_vec();

        Ok(NodePublicKey(spki_der))
    }

    /// Extracts the peer's public key from a QUIC connection's TLS certificate chain
    fn extract_peer_public_key(connection: &Connection) -> Result<NodePublicKey, String> {
        let peer_identity = connection
            .peer_identity()
            .ok_or_else(|| "No peer identity available".to_string())?;

        let certs = peer_identity
            .downcast::<Vec<CertificateDer<'static>>>()
            .map_err(|_| "Failed to downcast peer identity to certificate chain".to_string())?;

        if certs.is_empty() {
            return Err("Peer certificate chain is empty".to_string());
        }

        // Extract public key from the first (end-entity) certificate
        Self::extract_public_key_from_cert(&certs[0])
    }

    // ============================================================================
    // SENDER_ID COMPUTATION
    // ============================================================================

    /// Returns a sorted list of all public keys (local + peers).
    /// The position in this list corresponds to the sender_id (0..N-1).
    pub fn get_sorted_public_keys(&self) -> Vec<NodePublicKey> {
        let mut all_keys: Vec<NodePublicKey> = Vec::new();

        // Add local public key
        if let Some(ref local_pk) = self.local_public_key {
            all_keys.push(local_pk.clone());
        }

        // Add peer public keys
        for entry in self.peer_public_keys.iter() {
            all_keys.push(entry.value().clone());
        }

        // Sort lexicographically by DER bytes
        all_keys.sort_by(|a, b| a.0.cmp(&b.0));
        all_keys
    }

    /// Gets the public key for a given party_id (0..N-1).
    /// Returns None if party_id is out of range.
    pub fn get_public_key_for_party_id(&self, party_id: PartyId) -> Option<NodePublicKey> {
        let sorted_keys = self.get_sorted_public_keys();
        sorted_keys.get(party_id).cloned()
    }

    /// Gets the party_id (0..N-1) for a given public key.
    /// Returns None if the public key is not known.
    pub fn get_party_id_for_public_key(&self, pk: &NodePublicKey) -> Option<PartyId> {
        let sorted_keys = self.get_sorted_public_keys();
        sorted_keys
            .iter()
            .position(|k| k == pk)
            .map(|pos| pos as PartyId)
    }

    /// Gets the connection for a given party_id (0..N-1).
    /// For MPC protocols, use this instead of direct connection lookup.
    pub fn get_connection_by_party_id(&self, party_id: PartyId) -> Option<Arc<dyn PeerConnection>> {
        let pk = self.get_public_key_for_party_id(party_id)?;

        // Check if this is our own public key (loopback)
        if Some(&pk) == self.local_public_key.as_ref() {
            return self
                .server_connections
                .get(&self.node_id)
                .map(|r| r.value().clone());
        }

        // Find the connection for this peer's public key
        let derived_id = pk.derive_id();
        self.server_connections
            .get(&derived_id)
            .map(|r| r.value().clone())
    }

    /// Computes the local party ID by sorting all public keys (local + peers) lexicographically
    /// and returning this node's position in the sorted list.
    /// Returns None if local_public_key is not set.
    pub fn compute_local_party_id(&self) -> Option<PartyId> {
        let local_pk = self.local_public_key.as_ref()?;
        self.get_party_id_for_public_key(local_pk)
    }

    /// Assigns party IDs to all connections based on the sorted public key list.
    /// Call this once all peers are connected to finalize party IDs.
    /// Returns the number of connections that were assigned party IDs.
    pub fn assign_party_ids(&self) -> usize {
        let sorted_keys = self.get_sorted_public_keys();
        let mut assigned = 0;

        // Assign party IDs to server connections (except loopback)
        for entry in self.server_connections.iter() {
            let derived_id = *entry.key();
            let conn = entry.value();

            // Skip loopback - handle separately
            if derived_id == self.node_id {
                continue;
            }

            // Look up public key by derived_id
            if let Some(pk_entry) = self.peer_public_keys.get(&derived_id) {
                let peer_pk = pk_entry.value();
                if let Some(pos) = sorted_keys.iter().position(|k| k == peer_pk) {
                    conn.set_remote_party_id(pos);
                    assigned += 1;
                }
            }
        }

        // Assign party IDs to client connections
        for entry in self.client_connections.iter() {
            let derived_id = *entry.key();
            let conn = entry.value();

            // Look up public key by derived_id
            if let Some(pk_entry) = self.peer_public_keys.get(&derived_id) {
                let peer_pk = pk_entry.value();
                if let Some(pos) = sorted_keys.iter().position(|k| k == peer_pk) {
                    conn.set_remote_party_id(pos);
                    assigned += 1;
                }
            }
        }

        // Assign party ID to loopback connection
        if let Some(local_pk) = &self.local_public_key {
            if let Some(pos) = sorted_keys.iter().position(|k| k == local_pk) {
                if let Some(loopback) = self.server_connections.get(&self.node_id) {
                    loopback.set_remote_party_id(pos);
                    assigned += 1;
                }
            }
        }

        assigned
    }

    /// Checks if we have public keys from all expected parties.
    pub fn is_fully_connected(&self, expected_count: usize) -> bool {
        self.peer_public_keys.len() >= expected_count.saturating_sub(1)
            && self.local_public_key.is_some()
    }

    /// Returns a reference to this node's public key
    pub fn get_public_key(&self) -> Option<&NodePublicKey> {
        self.local_public_key.as_ref()
    }

    /// Returns the node_id (legacy ID, used as fallback)
    pub fn get_node_id(&self) -> PartyId {
        self.node_id
    }

    /// Returns the ID derived from this node's public key.
    /// Falls back to node_id if no certificate has been generated yet.
    pub fn local_derived_id(&self) -> PartyId {
        self.local_public_key
            .as_ref()
            .map(|pk| pk.derive_id())
            .unwrap_or(self.node_id)
    }

    /// Connects as a CLIENT to a server (role identified via ALPN).
    /// The server's ID is derived from its public key.
    /// Returns Arc<dyn PeerConnection> for actor model compatibility.
    pub async fn connect_as_client(
        &mut self,
        address: SocketAddr,
    ) -> Result<Arc<dyn PeerConnection>, String> {
        self.ensure_client_endpoint(ClientType::Client).await?;
        self.ensure_loopback_installed().await;

        let endpoint = self.endpoint.as_ref().unwrap();
        let connection = endpoint
            .connect(address, "localhost")
            .map_err(|e| format!("Failed to initiate connection: {}", e))?
            .await
            .map_err(|e| format!("Failed to establish connection: {}", e))?;

        // Verify ALPN negotiation resulted in client-protocol
        let connection_role = extract_alpn_role(&connection).unwrap_or_else(|e| {
            warn!("ALPN extraction failed: {}, defaulting to Server", e);
            ClientType::Server
        });

        // Extract peer's public key from TLS certificate
        let peer_public_key = Self::extract_peer_public_key(&connection).ok();

        // Open persistent stream and send sync byte to establish it
        let (mut send, recv) = connection
            .open_bi()
            .await
            .map_err(|e| format!("Failed to open stream: {}", e))?;

        send_stream_sync(&mut send)
            .await
            .map_err(|e| format!("Failed to sync stream: {}", e))?;

        // Derive server's ID from its public key
        let server_id = if let Some(ref pk) = peer_public_key {
            pk.derive_id()
        } else {
            warn!(
                "Could not extract server public key from {}, using address-based ID",
                address
            );
            self.fallback_node_lookup(address)
        };

        // Store peer's public key if available
        if let Some(ref pk) = peer_public_key {
            self.peer_public_keys.insert(server_id, pk.clone());
            trace!("Stored public key for server {}", server_id);
        }

        // Ensure node exists
        if !self.nodes.iter().any(|n| n.id() == server_id) {
            self.nodes.push(QuicNode::from_party_id(server_id, address));
        }

        // Create Arc-wrapped connection
        let conn = Arc::new(QuicPeerConnection::new(
            connection.clone(),
            send,
            recv,
            connection_role,
            peer_public_key,
        )) as Arc<dyn PeerConnection>;

        // Store connection with the server's derived ID
        self.server_connections.insert(server_id, Arc::clone(&conn));

        // Log our own derived client ID for debugging
        let client_id = self
            .local_public_key
            .as_ref()
            .map(|pk| pk.derive_id())
            .unwrap_or(self.node_id);
        info!(
            "Client {} connected to server {} at {}",
            client_id, server_id, address
        );

        Ok(conn)
    }

    /// Fallback method to find or create a node ID when handshake fails
    fn fallback_node_lookup(&mut self, address: SocketAddr) -> PartyId {
        self.nodes
            .iter()
            .find(|n| n.address() == address)
            .map(|n| n.id())
            .unwrap_or_else(|| {
                warn!(
                    "Creating random node ID for address {} - this may cause connection issues",
                    address
                );
                let node = QuicNode::new_with_random_id(address);
                let id = node.id();
                self.nodes.push(node);
                id
            })
    }

    /// Connects as a SERVER to another server (role identified via ALPN).
    /// The peer's ID is derived from its public key.
    /// Returns Arc<dyn PeerConnection> for actor model compatibility.
    pub async fn connect_as_server(
        &mut self,
        address: SocketAddr,
    ) -> Result<Arc<dyn PeerConnection>, String> {
        self.ensure_client_endpoint(ClientType::Server).await?;
        self.ensure_loopback_installed().await;

        let endpoint = self.endpoint.as_ref().unwrap();
        let connection = endpoint
            .connect(address, "localhost")
            .map_err(|e| format!("Failed to initiate connection: {}", e))?
            .await
            .map_err(|e| format!("Failed to establish connection: {}", e))?;

        // Verify ALPN negotiation - we expect the peer to see server-protocol
        let connection_role = extract_alpn_role(&connection).unwrap_or_else(|e| {
            warn!("ALPN extraction failed: {}, defaulting to Server", e);
            ClientType::Server
        });

        // Extract peer's public key from TLS certificate
        let peer_public_key = Self::extract_peer_public_key(&connection).ok();

        // Open persistent stream and send sync byte to establish it
        let (mut send, recv) = connection
            .open_bi()
            .await
            .map_err(|e| format!("Failed to open stream: {}", e))?;

        send_stream_sync(&mut send)
            .await
            .map_err(|e| format!("Failed to sync stream: {}", e))?;

        // Derive peer's ID from its public key
        let peer_id = if let Some(ref pk) = peer_public_key {
            pk.derive_id()
        } else {
            warn!(
                "Could not extract peer public key from {}, using address-based ID",
                address
            );
            self.fallback_node_lookup(address)
        };

        // Store peer's public key if available
        if let Some(ref pk) = peer_public_key {
            self.peer_public_keys.insert(peer_id, pk.clone());
            trace!("Stored public key for peer {}", peer_id);
        }

        // Ensure node exists
        if !self.nodes.iter().any(|n| n.id() == peer_id) {
            self.nodes.push(QuicNode::from_party_id(peer_id, address));
        }

        // Create Arc-wrapped connection
        let conn = Arc::new(QuicPeerConnection::new(
            connection.clone(),
            send,
            recv,
            connection_role,
            peer_public_key,
        )) as Arc<dyn PeerConnection>;

        self.server_connections.insert(peer_id, Arc::clone(&conn));

        // Log our own derived ID for debugging
        let our_id = self
            .local_public_key
            .as_ref()
            .map(|pk| pk.derive_id())
            .unwrap_or(self.node_id);
        info!(
            "Server {} connected to peer {} at {}",
            our_id, peer_id, address
        );

        Ok(conn)
    }

    // =========================================================================
    // NAT TRAVERSAL METHODS
    // =========================================================================

    /// Returns whether NAT traversal is enabled
    pub fn is_nat_traversal_enabled(&self) -> bool {
        self.network_config.enable_nat_traversal
    }

    /// Returns the local party ID
    pub fn party_id(&self) -> PartyId {
        self.node_id
    }

    /// Discovers local IP addresses by attempting to connect to external addresses
    ///
    /// This is a common technique to find local IPs that have routes to the internet.
    async fn discover_local_ips(&self) -> Vec<IpAddr> {
        let mut ips = Vec::new();

        // Try to discover the default local IP by "connecting" to a public address
        // (no actual connection is made, just route lookup)
        let targets = [
            "8.8.8.8:53", // Google DNS
            "1.1.1.1:53", // Cloudflare DNS
        ];

        for target in targets {
            if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
                if let Ok(target_addr) = target.parse::<SocketAddr>() {
                    if socket.connect(target_addr).is_ok() {
                        if let Ok(local_addr) = socket.local_addr() {
                            let ip = local_addr.ip();
                            if !ips.contains(&ip) && !ip.is_unspecified() && !ip.is_loopback() {
                                ips.push(ip);
                            }
                        }
                    }
                }
            }
        }

        // Also try to find IPs from local interfaces by binding to specific ports
        // and checking what IPs we can use
        if ips.is_empty() {
            // Try common private network ranges
            let test_addrs = ["10.0.0.1:1", "192.168.1.1:1", "172.16.0.1:1"];

            for target in test_addrs {
                if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
                    if let Ok(target_addr) = target.parse::<SocketAddr>() {
                        if socket.connect(target_addr).is_ok() {
                            if let Ok(local_addr) = socket.local_addr() {
                                let ip = local_addr.ip();
                                if !ips.contains(&ip) && !ip.is_unspecified() && !ip.is_loopback() {
                                    ips.push(ip);
                                }
                            }
                        }
                    }
                }
            }
        }

        debug!("Discovered {} local IP(s): {:?}", ips.len(), ips);
        ips
    }

    /// Gathers ICE candidates for NAT traversal
    ///
    /// Discovers local host addresses and queries STUN servers for
    /// server reflexive (external) addresses.
    pub async fn gather_ice_candidates(
        &self,
    ) -> Result<crate::transports::ice::LocalCandidates, String> {
        use crate::transports::ice::LocalCandidates;

        if !self.network_config.enable_nat_traversal {
            return Err("NAT traversal not enabled".to_string());
        }

        // Check cache first
        {
            let cached = self.local_candidates.lock().await;
            if let Some(ref candidates) = *cached {
                return Ok(candidates.clone());
            }
        }

        let mut candidates = LocalCandidates::new();

        // Get local address from endpoint
        let local_addr = if let Some(endpoint) = &self.endpoint {
            endpoint
                .local_addr()
                .map_err(|e| format!("Failed to get local address: {}", e))?
        } else {
            // Create a temporary socket to determine local address
            let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| format!("Failed to bind socket: {}", e))?;
            socket
                .local_addr()
                .map_err(|e| format!("Failed to get local address: {}", e))?
        };

        let port = local_addr.port();

        // If bound to 0.0.0.0, discover actual local IP addresses
        if local_addr.ip() == IpAddr::V4(Ipv4Addr::UNSPECIFIED) {
            // Try to discover local IP by connecting to a known address
            // This is a common technique to find the "default" local IP
            let discovered_ips = self.discover_local_ips().await;

            if discovered_ips.is_empty() {
                // Fallback: just add the unspecified address
                candidates.add_host(local_addr);
                debug!("Added host candidate (fallback): {}", local_addr);
            } else {
                for ip in discovered_ips {
                    let addr = SocketAddr::new(ip, port);
                    candidates.add_host(addr);
                    debug!("Added host candidate: {}", addr);
                }
            }
        } else {
            // Add host candidate as-is
            candidates.add_host(local_addr);
            debug!("Added host candidate: {}", local_addr);
        }

        // Gather server reflexive candidates via STUN
        if let Some(ref stun_client) = self.stun_client {
            let socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| format!("Failed to bind STUN socket: {}", e))?;

            let results = stun_client.discover_all(&socket).await;

            for result in results {
                if result.reflexive_address != local_addr {
                    candidates.add_server_reflexive(
                        result.reflexive_address,
                        local_addr,
                        result.server_address,
                    );
                    debug!(
                        "Added server reflexive candidate: {} (from {})",
                        result.reflexive_address, result.server_address
                    );
                }
            }
        }

        if candidates.is_empty() {
            return Err("No candidates gathered".to_string());
        }

        info!("Gathered {} ICE candidates", candidates.len());

        // Cache the candidates
        {
            let mut cached = self.local_candidates.lock().await;
            *cached = Some(candidates.clone());
        }

        Ok(candidates)
    }

    /// Creates an ICE candidates message for sending to a peer
    pub async fn create_ice_candidates_message(&self) -> Result<NetEnvelope, String> {
        let candidates = self.gather_ice_candidates().await?;

        Ok(NetEnvelope::IceCandidates {
            ufrag: candidates.ufrag.clone(),
            pwd: candidates.pwd.clone(),
            candidates: candidates.candidates.clone(),
        })
    }

    /// Initiates a peer-to-peer connection with NAT traversal
    ///
    /// This method:
    /// 1. Gathers local ICE candidates
    /// 2. Sends candidates to the peer via the signaling connection
    /// 3. Receives remote candidates
    /// 4. Runs ICE connectivity checks
    /// 5. Returns the established connection
    pub async fn connect_p2p(
        &mut self,
        target_party_id: PartyId,
        signaling_connection: Arc<dyn PeerConnection>,
    ) -> Result<Arc<dyn PeerConnection>, String> {
        use crate::transports::ice_agent::IceAgent;

        if !self.network_config.enable_nat_traversal {
            return Err("NAT traversal not enabled".to_string());
        }

        info!(
            "Starting P2P connection to party {} via NAT traversal",
            target_party_id
        );

        // 1. Gather local candidates
        let local_candidates = self.gather_ice_candidates().await?;

        // 2. Send our candidates to the peer
        let candidates_msg = NetEnvelope::IceCandidates {
            ufrag: local_candidates.ufrag.clone(),
            pwd: local_candidates.pwd.clone(),
            candidates: local_candidates.candidates.clone(),
        };

        signaling_connection
            .send(&candidates_msg.serialize())
            .await
            .map_err(|e| format!("Failed to send ICE candidates: {}", e))?;

        debug!("Sent {} ICE candidates to peer", local_candidates.len());

        // 3. Wait for remote candidates
        let remote_data = signaling_connection
            .receive()
            .await
            .map_err(|e| format!("Failed to receive remote candidates: {}", e))?;

        let remote_envelope = NetEnvelope::try_deserialize(&remote_data)
            .map_err(|e| format!("Failed to deserialize remote candidates: {}", e))?;

        let (remote_ufrag, remote_pwd, remote_candidates) = match remote_envelope {
            NetEnvelope::IceCandidates {
                ufrag,
                pwd,
                candidates,
            } => (ufrag, pwd, candidates),
            _ => {
                return Err("Expected IceCandidates message".to_string());
            }
        };

        debug!("Received {} remote ICE candidates", remote_candidates.len());

        // 4. Create and configure ICE agent
        let mut ice_agent = IceAgent::new(self.network_config.ice_config.clone(), self.node_id)
            .map_err(|e| format!("Failed to create ICE agent: {}", e))?;

        // Gather candidates using our local addresses
        let host_addresses: Vec<_> = local_candidates
            .candidates
            .iter()
            .map(|c| c.address)
            .collect();

        if host_addresses.is_empty() {
            return Err("No local candidates".to_string());
        }

        // Create a temporary socket for STUN queries
        // TODO: Consider reusing the QUIC endpoint's socket for accurate NAT mappings
        let stun_socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| format!("Failed to create STUN socket: {}", e))?;

        ice_agent
            .gather_candidates(&host_addresses, &stun_socket)
            .await
            .map_err(|e| format!("ICE gathering failed: {}", e))?;

        // Set remote candidates
        ice_agent
            .set_remote_candidates(target_party_id, remote_ufrag, remote_pwd, remote_candidates)
            .map_err(|e| format!("Failed to set remote candidates: {}", e))?;

        // 5. Ensure endpoint exists
        self.ensure_client_endpoint(ClientType::Server).await?;
        let endpoint = self.endpoint.as_ref().unwrap();

        // 6. Run connectivity checks
        let nominated_pair = ice_agent
            .run_connectivity_checks(endpoint)
            .await
            .map_err(|e| format!("ICE connectivity checks failed: {}", e))?;

        info!(
            "ICE completed: {} -> {} (RTT: {:?}ms)",
            nominated_pair.local.address, nominated_pair.remote.address, nominated_pair.rtt_ms
        );

        // Store agent for potential later use
        self.pending_ice_agents.insert(target_party_id, ice_agent);

        // 7. Establish QUIC connection on the successful pair
        let connection = endpoint
            .connect(nominated_pair.remote.address, "localhost")
            .map_err(|e| format!("Failed to initiate connection: {}", e))?
            .await
            .map_err(|e| format!("Failed to establish connection: {}", e))?;

        // Get connection role from ALPN negotiation
        let connection_role = extract_alpn_role(&connection).unwrap_or_else(|e| {
            warn!("ALPN extraction failed: {}, defaulting to Server", e);
            ClientType::Server
        });

        // Extract peer's public key from TLS certificate
        let peer_public_key = Self::extract_peer_public_key(&connection).ok();

        // Open stream and sync
        let (mut send, recv) = connection
            .open_bi()
            .await
            .map_err(|e| format!("Failed to open stream: {}", e))?;

        send_stream_sync(&mut send)
            .await
            .map_err(|e| format!("Failed to sync stream: {}", e))?;

        let conn = Arc::new(QuicPeerConnection::new(
            connection,
            send,
            recv,
            connection_role,
            peer_public_key,
        )) as Arc<dyn PeerConnection>;

        // Store connection
        self.server_connections
            .insert(target_party_id, Arc::clone(&conn));

        // Cleanup ICE agent
        self.pending_ice_agents.remove(&target_party_id);

        Ok(conn)
    }

    /// Handles an incoming P2P connection request with NAT traversal
    ///
    /// Called when we receive ICE candidates from a peer wanting to connect.
    pub async fn handle_p2p_request(
        &mut self,
        from_party_id: PartyId,
        remote_ufrag: String,
        remote_pwd: String,
        remote_candidates: Vec<crate::transports::ice::IceCandidate>,
        signaling_connection: Arc<dyn PeerConnection>,
    ) -> Result<Arc<dyn PeerConnection>, String> {
        use crate::transports::ice_agent::IceAgent;

        if !self.network_config.enable_nat_traversal {
            return Err("NAT traversal not enabled".to_string());
        }

        info!(
            "Handling P2P request from party {} with {} candidates",
            from_party_id,
            remote_candidates.len()
        );

        // 1. Gather our candidates
        let local_candidates = self.gather_ice_candidates().await?;

        // 2. Send our candidates back
        let candidates_msg = NetEnvelope::IceCandidates {
            ufrag: local_candidates.ufrag.clone(),
            pwd: local_candidates.pwd.clone(),
            candidates: local_candidates.candidates.clone(),
        };

        signaling_connection
            .send(&candidates_msg.serialize())
            .await
            .map_err(|e| format!("Failed to send ICE candidates: {}", e))?;

        // 3. Create ICE agent
        let mut ice_agent = IceAgent::new(self.network_config.ice_config.clone(), self.node_id)
            .map_err(|e| format!("Failed to create ICE agent: {}", e))?;

        // Gather candidates using our local addresses
        let host_addresses: Vec<_> = local_candidates
            .candidates
            .iter()
            .map(|c| c.address)
            .collect();

        if host_addresses.is_empty() {
            return Err("No local candidates".to_string());
        }

        // Create a temporary socket for STUN queries
        // TODO: Consider reusing the QUIC endpoint's socket for accurate NAT mappings
        let stun_socket = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| format!("Failed to create STUN socket: {}", e))?;

        ice_agent
            .gather_candidates(&host_addresses, &stun_socket)
            .await
            .map_err(|e| format!("ICE gathering failed: {}", e))?;

        ice_agent
            .set_remote_candidates(from_party_id, remote_ufrag, remote_pwd, remote_candidates)
            .map_err(|e| format!("Failed to set remote candidates: {}", e))?;

        // 4. Run connectivity checks
        self.ensure_client_endpoint(ClientType::Server).await?;
        let endpoint = self.endpoint.as_ref().unwrap();

        let nominated_pair = ice_agent
            .run_connectivity_checks(endpoint)
            .await
            .map_err(|e| format!("ICE connectivity checks failed: {}", e))?;

        info!(
            "ICE completed (responder): {} -> {}",
            nominated_pair.local.address, nominated_pair.remote.address
        );

        // 5. The controlling agent will establish the final connection
        // We wait to accept it
        let incoming = endpoint.accept().await.ok_or("No incoming connection")?;

        let connection = incoming
            .await
            .map_err(|e| format!("Failed to accept connection: {}", e))?;

        // Get connection role from ALPN negotiation
        let connection_role = extract_alpn_role(&connection).unwrap_or_else(|e| {
            warn!("ALPN extraction failed: {}, defaulting to Server", e);
            ClientType::Server
        });

        // Extract peer's public key from TLS certificate
        let peer_public_key = Self::extract_peer_public_key(&connection).ok();

        let (send, recv) = connection
            .accept_bi()
            .await
            .map_err(|e| format!("Failed to accept stream: {}", e))?;

        let conn = Arc::new(QuicPeerConnection::new(
            connection,
            send,
            recv,
            connection_role,
            peer_public_key,
        )) as Arc<dyn PeerConnection>;

        self.server_connections
            .insert(from_party_id, Arc::clone(&conn));

        Ok(conn)
    }

    /// Connects with automatic fallback strategies
    ///
    /// Tries connection methods in order:
    /// 1. Direct connection (if address provided)
    /// 2. NAT traversal with hole punching
    /// 3. Relay (future - returns error for now)
    pub async fn connect_with_fallback(
        &mut self,
        target_party_id: PartyId,
        direct_address: Option<SocketAddr>,
        signaling_connection: Option<Arc<dyn PeerConnection>>,
    ) -> Result<Arc<dyn PeerConnection>, String> {
        // Strategy 1: Direct connection
        if let Some(addr) = direct_address {
            debug!("Attempting direct connection to {}", addr);

            let result =
                tokio::time::timeout(Duration::from_secs(3), self.connect_as_server(addr)).await;

            match result {
                Ok(Ok(conn)) => {
                    info!("Direct connection succeeded to {}", addr);
                    return Ok(conn);
                }
                Ok(Err(e)) => {
                    debug!("Direct connection failed: {}", e);
                }
                Err(_) => {
                    debug!("Direct connection timed out");
                }
            }
        }

        // Strategy 2: NAT traversal
        if self.network_config.enable_nat_traversal {
            if let Some(signaling) = signaling_connection {
                debug!("Attempting NAT traversal to party {}", target_party_id);

                match self.connect_p2p(target_party_id, signaling).await {
                    Ok(conn) => {
                        info!("NAT traversal succeeded to party {}", target_party_id);
                        return Ok(conn);
                    }
                    Err(e) => {
                        warn!("NAT traversal failed: {}", e);
                    }
                }
            } else {
                debug!("No signaling connection available for NAT traversal");
            }
        }

        // Strategy 3: Relay (future implementation)
        // For now, return an error indicating relay is not available

        Err(format!(
            "All connection strategies failed for party {}",
            target_party_id
        ))
    }

    /// Processes an incoming signaling message for NAT traversal
    ///
    /// Returns an optional response message to send back.
    pub async fn process_signaling_message(
        &mut self,
        from_party_id: PartyId,
        envelope: NetEnvelope,
        signaling_connection: Arc<dyn PeerConnection>,
    ) -> Result<Option<Arc<dyn PeerConnection>>, String> {
        match envelope {
            NetEnvelope::IceCandidates {
                ufrag,
                pwd,
                candidates,
            } => {
                // Peer is initiating P2P connection
                let conn = self
                    .handle_p2p_request(from_party_id, ufrag, pwd, candidates, signaling_connection)
                    .await?;
                Ok(Some(conn))
            }
            NetEnvelope::RelayRequest { target_party_id } => {
                // Future: Handle relay request
                warn!(
                    "Relay request from {} for {} - not implemented",
                    from_party_id, target_party_id
                );
                Ok(None)
            }
            _ => {
                // Not a NAT traversal message
                Ok(None)
            }
        }
    }
}

impl NetworkManager for QuicNetworkManager {
    fn connect<'a>(
        &'a mut self,
        address: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<dyn PeerConnection>, String>> + Send + 'a>> {
        Box::pin(async move { self.connect_as_server(address).await })
    }

    fn accept<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<dyn PeerConnection>, String>> + Send + 'a>> {
        Box::pin(async move {
            let endpoint = self
                .endpoint
                .as_ref()
                .ok_or_else(|| "Endpoint not initialized. Call listen() first.".to_string())?;

            let incoming = endpoint
                .accept()
                .await
                .ok_or_else(|| "No incoming connections".to_string())?;

            let connection = incoming
                .await
                .map_err(|e| format!("Failed to accept connection: {}", e))?;

            let remote_addr = connection.remote_address();

            // Extract role from ALPN protocol negotiation
            let connection_role = extract_alpn_role(&connection).unwrap_or_else(|e| {
                warn!(
                    "ALPN extraction failed during accept: {}, defaulting to Server",
                    e
                );
                ClientType::Server
            });

            // Extract peer's public key from TLS certificate (mTLS)
            let peer_public_key = Self::extract_peer_public_key(&connection).ok();

            // Accept persistent stream and receive sync byte
            let (send, mut recv) = connection
                .accept_bi()
                .await
                .map_err(|e| format!("Failed to accept stream: {}", e))?;

            recv_stream_sync(&mut recv)
                .await
                .map_err(|e| format!("Failed to sync stream: {}", e))?;

            // Derive peer ID from public key, or fallback to address-based lookup
            let peer_id = if let Some(ref pk) = peer_public_key {
                pk.derive_id()
            } else {
                warn!(
                    "No peer public key available from {}, using address-based ID",
                    remote_addr
                );
                // Fallback: use address-based lookup
                self.nodes
                    .iter()
                    .find(|n| n.address() == remote_addr)
                    .map(|n| n.id())
                    .unwrap_or_else(|| {
                        let node = QuicNode::new_with_random_id(remote_addr);
                        let id = node.id();
                        self.nodes.push(node);
                        id
                    })
            };

            // Create Arc-wrapped connection
            let conn = Arc::new(QuicPeerConnection::new(
                connection.clone(),
                send,
                recv,
                connection_role,
                peer_public_key.clone(),
            )) as Arc<dyn PeerConnection>;

            match connection_role {
                ClientType::Client => {
                    // Client connection identified via ALPN
                    info!(
                        "Accepted client connection from {} with derived ID {}",
                        remote_addr, peer_id
                    );

                    // Store as client connection
                    self.client_connections.insert(peer_id, Arc::clone(&conn));
                    self.client_ids.insert(peer_id);
                }
                ClientType::Server => {
                    // Server-to-server connection identified via ALPN
                    info!(
                        "Accepted server connection from {} with derived ID {}",
                        remote_addr, peer_id
                    );

                    // Store peer's public key if available
                    if let Some(pk) = peer_public_key {
                        self.peer_public_keys.insert(peer_id, pk);
                        trace!("Stored public key for peer {}", peer_id);
                    }

                    // Ensure node exists
                    if !self.nodes.iter().any(|n| n.id() == peer_id) {
                        self.nodes
                            .push(QuicNode::from_party_id(peer_id, remote_addr));
                    }

                    // Store connection
                    self.server_connections.insert(peer_id, Arc::clone(&conn));
                }
            }

            Ok(conn)
        })
    }

    fn listen<'a>(
        &'a mut self,
        bind_address: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            // Ensure we have a local certificate
            self.ensure_local_certificate()?;
            let cert_der = self.local_cert_der.as_ref().unwrap();
            let key_der = self.local_key_der.as_ref().unwrap();

            let server_config = Self::create_self_signed_server_config(cert_der, key_der)?;
            let mut endpoint = Endpoint::server(server_config, bind_address)
                .map_err(|e| format!("Failed to create server endpoint: {}", e))?;

            // Default client config for outgoing connections uses Server role with mTLS
            let client_config = Self::create_insecure_client_config(
                ClientType::Server,
                Some(cert_der),
                Some(key_der),
            )?;
            endpoint.set_default_client_config(client_config);

            self.endpoint = Some(endpoint);
            self.ensure_loopback_installed().await;
            Ok(())
        })
    }
}

// ============================================================================
// NETWORK TRAIT IMPLEMENTATION
// ============================================================================

#[async_trait]
impl Network for QuicNetworkManager {
    type NodeType = QuicNode;
    type NetworkConfig = QuicNetworkConfig;

    async fn send(&self, recipient: PartyId, message: &[u8]) -> Result<usize, NetworkError> {
        // Use party_id-based lookup for MPC protocols (recipient is a party_id 0..N-1)
        let connection = self
            .get_connection_by_party_id(recipient)
            .ok_or(NetworkError::PartyNotFound(recipient))?;

        // Check if connection is still alive
        if !connection.is_connected().await {
            debug!("Connection to recipient {} is dead", recipient);
            self.cleanup_dead_connections().await;
            return Err(NetworkError::PartyNotFound(recipient));
        }

        match connection.send(message).await {
            Ok(_) => {
                debug!("Successfully sent message to recipient {}", recipient);
                Ok(message.len())
            }
            Err(e) => {
                debug!("Failed to send message to recipient {}: {}", recipient, e);
                self.cleanup_dead_connections().await;
                Err(NetworkError::SendError)
            }
        }
    }

    async fn broadcast(&self, message: &[u8]) -> Result<usize, NetworkError> {
        let mut total_bytes = 0usize;
        let party_count = self.party_count();

        // Broadcast to all parties using party_id (0..N-1)
        for party_id in 0..party_count {
            if let Some(connection) = self.get_connection_by_party_id(party_id) {
                // Check connection health before sending
                if !connection.is_connected().await {
                    debug!(
                        "Skipping broadcast to party_id {}: connection is dead",
                        party_id
                    );
                    continue;
                }

                match connection.send(message).await {
                    Ok(_) => {
                        debug!("Successfully broadcasted message to party_id {}", party_id);
                        total_bytes += message.len();
                    }
                    Err(e) => {
                        debug!(
                            "Failed to broadcast message to party_id {}: {}",
                            party_id, e
                        );
                    }
                }
            } else {
                debug!(
                    "Warning: No connection for party_id {}, skipping broadcast",
                    party_id
                );
            }
        }

        // If no parties found, try legacy loopback as fallback
        if party_count == 0 {
            if let Some(connection_ref) = self.server_connections.get(&self.node_id) {
                let connection = connection_ref.value();
                if connection.is_connected().await && connection.send(message).await.is_ok() {
                    debug!("Successfully broadcasted message to self (loopback fallback)");
                    total_bytes += message.len();
                }
            }
        }

        // Cleanup dead connections after broadcast
        self.cleanup_dead_connections().await;

        Ok(total_bytes)
    }

    fn parties(&self) -> Vec<&Self::NodeType> {
        self.nodes.iter().collect()
    }

    fn parties_mut(&mut self) -> Vec<&mut Self::NodeType> {
        self.nodes.iter_mut().collect()
    }

    fn config(&self) -> &Self::NetworkConfig {
        &self.network_config
    }

    fn node(&self, id: PartyId) -> Option<&Self::NodeType> {
        self.nodes.iter().find(|node| node.id() == id)
    }

    fn node_mut(&mut self, id: PartyId) -> Option<&mut Self::NodeType> {
        self.nodes.iter_mut().find(|node| node.id() == id)
    }

    async fn send_to_client(
        &self,
        client: ClientId,
        message: &[u8],
    ) -> Result<usize, NetworkError> {
        if let Some(conn_ref) = self.client_connections.get(&client) {
            let connection = conn_ref.value();

            // Check connection health
            if !connection.is_connected().await {
                debug!("Connection to client {} is dead", client);
                return Err(NetworkError::ClientNotFound(client));
            }

            match connection.send(message).await {
                Ok(_) => Ok(message.len()),
                Err(_) => Err(NetworkError::SendError),
            }
        } else {
            Err(NetworkError::ClientNotFound(client))
        }
    }

    fn clients(&self) -> Vec<ClientId> {
        self.client_ids.iter().map(|entry| *entry.key()).collect()
    }

    fn is_client_connected(&self, client: ClientId) -> bool {
        self.client_ids.contains(&client)
    }

    fn local_party_id(&self) -> PartyId {
        self.compute_local_party_id().unwrap_or(self.node_id)
    }

    fn party_count(&self) -> usize {
        let local_count = if self.local_public_key.is_some() {
            1
        } else {
            0
        };
        local_count + self.peer_public_keys.len()
    }
}

// ============================================================================
// CERTIFICATE VERIFIERS (Development Only)
// ============================================================================

/// Client certificate verifier that accepts all client certificates without verification.
/// DEVELOPMENT ONLY - do not use in production.
#[derive(Debug)]
struct SkipClientVerification;

impl SkipClientVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::server::danger::ClientCertVerifier for SkipClientVerification {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        // Accept all client certificates without verification
        Ok(rustls::server::danger::ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }

    fn client_auth_mandatory(&self) -> bool {
        // Client certificates are optional - clients without certs can still connect
        false
    }
}

/// Server certificate verifier that accepts all server certificates without verification.
/// DEVELOPMENT ONLY - do not use in production.
#[derive(Debug)]
struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Self {
        Self
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transports::net_envelope::NetEnvelope;

    // Helper function to ensure crypto provider is installed
    fn ensure_crypto_provider() {
        // Install the default crypto provider (ring) if not already installed
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    // ========================================================================
    // ALPN Constants Tests
    // ========================================================================

    #[test]
    fn test_alpn_constants_are_distinct() {
        assert_ne!(ALPN_CLIENT_PROTOCOL, ALPN_SERVER_PROTOCOL);
        assert_eq!(ALPN_CLIENT_PROTOCOL, b"client-protocol");
        assert_eq!(ALPN_SERVER_PROTOCOL, b"server-protocol");
    }

    // ========================================================================
    // Certificate and Public Key Tests
    // ========================================================================

    #[test]
    fn test_certificate_generation_and_public_key_extraction() {
        // Generate a self-signed certificate
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("Failed to generate certificate");

        let cert_der = cert.cert.der().to_vec();

        // Extract public key
        let public_key = QuicNetworkManager::extract_public_key_from_cert(&cert_der)
            .expect("Failed to extract public key");

        // Public key should not be empty
        assert!(!public_key.0.is_empty());

        // Public key should be valid DER-encoded SPKI (starts with SEQUENCE tag 0x30)
        assert_eq!(
            public_key.0[0], 0x30,
            "Public key should start with SEQUENCE tag"
        );
    }

    #[test]
    fn test_different_certificates_have_different_public_keys() {
        let cert1 = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("Failed to generate certificate 1");
        let cert2 = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("Failed to generate certificate 2");

        let pk1 = QuicNetworkManager::extract_public_key_from_cert(cert1.cert.der())
            .expect("Failed to extract pk1");
        let pk2 = QuicNetworkManager::extract_public_key_from_cert(cert2.cert.der())
            .expect("Failed to extract pk2");

        // Different certificates should have different public keys
        assert_ne!(pk1, pk2);
    }

    #[test]
    fn test_same_certificate_same_public_key() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("Failed to generate certificate");

        let pk1 = QuicNetworkManager::extract_public_key_from_cert(cert.cert.der())
            .expect("Failed to extract pk1");
        let pk2 = QuicNetworkManager::extract_public_key_from_cert(cert.cert.der())
            .expect("Failed to extract pk2");

        // Same certificate should yield same public key
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn test_ensure_local_certificate() {
        let mut manager = QuicNetworkManager::new();

        // Initially no certificate
        assert!(manager.local_cert_der.is_none());
        assert!(manager.local_key_der.is_none());
        assert!(manager.local_public_key.is_none());

        // Ensure certificate is created
        manager
            .ensure_local_certificate()
            .expect("Failed to ensure certificate");

        // Now should have certificate
        assert!(manager.local_cert_der.is_some());
        assert!(manager.local_key_der.is_some());
        assert!(manager.local_public_key.is_some());

        // Store references for comparison
        let cert_der = manager.local_cert_der.clone();
        let public_key = manager.local_public_key.clone();

        // Calling again should not change the certificate
        manager
            .ensure_local_certificate()
            .expect("Failed on second call");

        assert_eq!(manager.local_cert_der, cert_der);
        assert_eq!(manager.local_public_key, public_key);
    }

    // ========================================================================
    // NodePublicKey Tests
    // ========================================================================

    #[test]
    fn test_node_public_key_ordering() {
        let pk1 = NodePublicKey(vec![0x00, 0x01, 0x02]);
        let pk2 = NodePublicKey(vec![0x00, 0x01, 0x03]);
        let pk3 = NodePublicKey(vec![0x00, 0x02, 0x01]);

        // Test ordering
        assert!(pk1 < pk2);
        assert!(pk2 < pk3);
        assert!(pk1 < pk3);
    }

    #[test]
    fn test_node_public_key_equality() {
        let pk1 = NodePublicKey(vec![0x00, 0x01, 0x02]);
        let pk2 = NodePublicKey(vec![0x00, 0x01, 0x02]);
        let pk3 = NodePublicKey(vec![0x00, 0x01, 0x03]);

        assert_eq!(pk1, pk2);
        assert_ne!(pk1, pk3);
    }

    #[test]
    fn test_node_public_key_clone() {
        let pk1 = NodePublicKey(vec![0x00, 0x01, 0x02]);
        let pk2 = pk1.clone();

        assert_eq!(pk1, pk2);
    }

    // ========================================================================
    // sender_id Computation Tests
    // ========================================================================

    #[test]
    fn test_compute_local_party_id_no_local_key() {
        let manager = QuicNetworkManager::new();

        // Without local public key, compute_local_party_id should return None
        assert!(manager.compute_local_party_id().is_none());
    }

    #[test]
    fn test_compute_local_party_id_single_node() {
        let mut manager = QuicNetworkManager::new();
        manager
            .ensure_local_certificate()
            .expect("Failed to ensure certificate");

        // With only local node, sender_id should be 0
        let sender_id = manager.compute_local_party_id();
        assert_eq!(sender_id, Some(0));
    }

    #[test]
    fn test_compute_local_party_id_multiple_nodes() {
        let mut manager = QuicNetworkManager::new();
        manager
            .ensure_local_certificate()
            .expect("Failed to ensure certificate");

        let local_pk = manager.local_public_key.clone().unwrap();

        // Add peer public keys that are lexicographically before and after local
        let pk_before = NodePublicKey(vec![0x00]); // Likely before any real key
        let pk_after = NodePublicKey(vec![0xFF; 1000]); // Likely after any real key

        manager.peer_public_keys.insert(1, pk_before);
        manager.peer_public_keys.insert(2, pk_after);

        // Compute sender_id
        let sender_id = manager
            .compute_local_party_id()
            .expect("Should compute sender_id");

        // Local key should be in the middle (position 1)
        // Since pk_before < local_pk < pk_after when sorted
        assert_eq!(sender_id, 1);
    }

    #[test]
    fn test_compute_local_party_id_deterministic_ordering() {
        // Create three managers and ensure they compute consistent sender_ids
        let mut manager1 = QuicNetworkManager::new();
        let mut manager2 = QuicNetworkManager::new();
        let mut manager3 = QuicNetworkManager::new();

        manager1.ensure_local_certificate().unwrap();
        manager2.ensure_local_certificate().unwrap();
        manager3.ensure_local_certificate().unwrap();

        let pk1 = manager1.local_public_key.clone().unwrap();
        let pk2 = manager2.local_public_key.clone().unwrap();
        let pk3 = manager3.local_public_key.clone().unwrap();

        // Simulate full connectivity - each manager knows about others
        manager1.peer_public_keys.insert(2, pk2.clone());
        manager1.peer_public_keys.insert(3, pk3.clone());

        manager2.peer_public_keys.insert(1, pk1.clone());
        manager2.peer_public_keys.insert(3, pk3.clone());

        manager3.peer_public_keys.insert(1, pk1.clone());
        manager3.peer_public_keys.insert(2, pk2.clone());

        // Compute sender_ids
        let id1 = manager1.compute_local_party_id().unwrap();
        let id2 = manager2.compute_local_party_id().unwrap();
        let id3 = manager3.compute_local_party_id().unwrap();

        // All sender_ids should be distinct and in range [0, 2]
        let mut ids = vec![id1, id2, id3];
        ids.sort();
        assert_eq!(ids, vec![0, 1, 2]);
    }

    #[test]
    fn test_sender_id_fallback() {
        let manager = QuicNetworkManager::new();

        // Without local certificate, compute_local_party_id() should return None
        assert!(manager.compute_local_party_id().is_none());

        // After getting a certificate, it should return Some
        let mut manager = QuicNetworkManager::new();
        manager.ensure_local_certificate().unwrap();
        assert!(manager.compute_local_party_id().is_some());
    }

    #[test]
    fn test_is_fully_connected() {
        let mut manager = QuicNetworkManager::new();

        // Not fully connected without local key
        assert!(!manager.is_fully_connected(3));

        manager.ensure_local_certificate().unwrap();

        // With local key only, need 0 peers for count=1
        assert!(manager.is_fully_connected(1));

        // For count=3, need 2 peers
        assert!(!manager.is_fully_connected(3));

        manager
            .peer_public_keys
            .insert(1, NodePublicKey(vec![0x01]));
        assert!(!manager.is_fully_connected(3)); // Still need 1 more

        manager
            .peer_public_keys
            .insert(2, NodePublicKey(vec![0x02]));
        assert!(manager.is_fully_connected(3)); // Now fully connected
    }

    // ========================================================================
    // Client Config Tests
    // ========================================================================

    #[test]
    fn test_create_client_config_for_client_role() {
        ensure_crypto_provider();
        let config =
            QuicNetworkManager::create_insecure_client_config(ClientType::Client, None, None);
        assert!(config.is_ok());
    }

    #[test]
    fn test_create_client_config_for_server_role() {
        ensure_crypto_provider();
        let config =
            QuicNetworkManager::create_insecure_client_config(ClientType::Server, None, None);
        assert!(config.is_ok());
    }

    #[test]
    fn test_create_client_config_with_certificate() {
        ensure_crypto_provider();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("Failed to generate certificate");
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.signing_key.serialize_der();

        let config = QuicNetworkManager::create_insecure_client_config(
            ClientType::Client,
            Some(&cert_der),
            Some(&key_der),
        );
        assert!(config.is_ok());
    }

    // ========================================================================
    // Server Config Tests
    // ========================================================================

    #[test]
    fn test_create_server_config() {
        ensure_crypto_provider();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("Failed to generate certificate");

        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.signing_key.serialize_der();

        let config = QuicNetworkManager::create_self_signed_server_config(&cert_der, &key_der);
        assert!(config.is_ok());
    }

    // ========================================================================
    // NetEnvelope Tests
    // ========================================================================

    #[test]
    fn test_net_envelope_handshake_serialization() {
        let envelope = NetEnvelope::Handshake { id: 42 };
        let bytes = envelope.serialize();

        let deserialized = NetEnvelope::try_deserialize(&bytes).expect("Failed to deserialize");

        match deserialized {
            NetEnvelope::Handshake { id } => assert_eq!(id, 42),
            _ => panic!("Expected Handshake variant"),
        }
    }

    #[test]
    fn test_net_envelope_honeybadger_serialization() {
        let data = vec![1, 2, 3, 4, 5];
        let envelope = NetEnvelope::HoneyBadger(data.clone());
        let bytes = envelope.serialize();

        let deserialized = NetEnvelope::try_deserialize(&bytes).expect("Failed to deserialize");

        match deserialized {
            NetEnvelope::HoneyBadger(d) => assert_eq!(d, data),
            _ => panic!("Expected HoneyBadger variant"),
        }
    }

    // ========================================================================
    // QuicNetworkManager Integration Tests
    // ========================================================================

    #[test]
    fn test_manager_initialization() {
        let manager = QuicNetworkManager::new();

        assert!(manager.endpoint.is_none());
        assert!(manager.nodes.is_empty());
        assert!(manager.server_connections.is_empty());
        assert!(manager.client_connections.is_empty());
        assert!(manager.client_ids.is_empty());
        assert!(manager.local_cert_der.is_none());
        assert!(manager.local_key_der.is_none());
        assert!(manager.local_public_key.is_none());
        assert!(manager.peer_public_keys.is_empty());
    }

    #[test]
    fn test_manager_with_node_id() {
        let custom_id = 12345;
        let manager = QuicNetworkManager::with_node_id(custom_id);

        assert_eq!(manager.node_id, custom_id);
        assert_eq!(manager.get_node_id(), custom_id);
    }

    #[test]
    fn test_get_public_key() {
        let mut manager = QuicNetworkManager::new();

        // Initially no public key
        assert!(manager.get_public_key().is_none());

        manager.ensure_local_certificate().unwrap();

        // Now should have public key
        assert!(manager.get_public_key().is_some());
    }

    // ========================================================================
    // Async Integration Tests
    // ========================================================================

    #[tokio::test]
    async fn test_listen_creates_endpoint_and_certificate() {
        ensure_crypto_provider();
        let mut manager = QuicNetworkManager::new();

        // Listen on a random port
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        manager.listen(addr).await.expect("Failed to listen");

        // Should have endpoint now
        assert!(manager.endpoint.is_some());

        // Should have certificate
        assert!(manager.local_cert_der.is_some());
        assert!(manager.local_key_der.is_some());
        assert!(manager.local_public_key.is_some());
    }

    #[tokio::test]
    async fn test_loopback_installed_after_listen() {
        ensure_crypto_provider();
        let mut manager = QuicNetworkManager::new();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        manager.listen(addr).await.expect("Failed to listen");

        // Loopback should be installed
        assert!(manager.server_connections.contains_key(&manager.node_id));
    }

    #[tokio::test]
    async fn test_server_to_server_connection() {
        ensure_crypto_provider();
        // Create two managers
        let mut server1 = QuicNetworkManager::with_node_id(1);
        let mut server2 = QuicNetworkManager::with_node_id(2);

        // Start listening on server1
        let addr1: SocketAddr = "127.0.0.1:0".parse().unwrap();
        server1
            .listen(addr1)
            .await
            .expect("Failed to start server1");

        // Get actual bound address
        let bound_addr = server1.endpoint.as_ref().unwrap().local_addr().unwrap();

        // Server2 connects to server1 as a server (ID is derived from public key)
        let conn_task = tokio::spawn(async move {
            let result = server2.connect_as_server(bound_addr).await;
            (server2, result)
        });

        // Server1 accepts the connection
        let accept_result = server1.accept().await;

        // Wait for connection task
        let (server2, connect_result) = conn_task.await.unwrap();

        // Both should succeed
        assert!(
            accept_result.is_ok(),
            "Accept failed: {:?}",
            accept_result.err()
        );
        assert!(
            connect_result.is_ok(),
            "Connect failed: {:?}",
            connect_result.err()
        );

        // Check that connections were stored with derived IDs
        // Server1 should have a connection to server2 (by server2's derived ID)
        let server2_derived_id = server2.local_derived_id();
        assert!(
            server1.server_connections.contains_key(&server2_derived_id),
            "server1 should have connection to server2 with derived ID {}",
            server2_derived_id
        );
    }

    #[tokio::test]
    async fn test_client_to_server_connection() {
        ensure_crypto_provider();
        // Create server and client managers
        let mut server = QuicNetworkManager::with_node_id(1);
        let mut client = QuicNetworkManager::with_node_id(100);

        // Start listening on server
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        server.listen(addr).await.expect("Failed to start server");

        let bound_addr = server.endpoint.as_ref().unwrap().local_addr().unwrap();

        // Client connects to server (ID is derived from public key)
        let conn_task = tokio::spawn(async move {
            let result = client.connect_as_client(bound_addr).await;
            (client, result)
        });

        // Server accepts the connection
        let accept_result = server.accept().await;

        // Wait for connection task
        let (client, connect_result) = conn_task.await.unwrap();

        // Both should succeed
        assert!(
            accept_result.is_ok(),
            "Accept failed: {:?}",
            accept_result.err()
        );
        assert!(
            connect_result.is_ok(),
            "Connect failed: {:?}",
            connect_result.err()
        );

        // Check that server stored client connection with derived ID
        let client_derived_id = client.local_derived_id();
        assert!(
            server.client_connections.contains_key(&client_derived_id),
            "server should have client connection with derived ID {}",
            client_derived_id
        );
        assert!(server.client_ids.contains(&client_derived_id));
    }

    #[tokio::test]
    async fn test_connection_role_from_alpn() {
        ensure_crypto_provider();
        let mut server = QuicNetworkManager::with_node_id(1);
        let mut client = QuicNetworkManager::with_node_id(100);

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        server.listen(addr).await.expect("Failed to start server");

        let bound_addr = server.endpoint.as_ref().unwrap().local_addr().unwrap();

        let conn_task = tokio::spawn(async move { client.connect_as_client(bound_addr).await });

        let accept_result = server.accept().await.expect("Accept failed");
        let _connect_result = conn_task.await.unwrap().expect("Connect failed");

        // Server should see the connection as coming from a Client
        assert_eq!(accept_result.get_connection_role(), ClientType::Client);
    }

    #[tokio::test]
    async fn test_public_keys_exchanged_on_server_connection() {
        ensure_crypto_provider();
        let mut server1 = QuicNetworkManager::with_node_id(1);
        let mut server2 = QuicNetworkManager::with_node_id(2);

        // Both servers need to have their certificates generated
        let addr1: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:0".parse().unwrap();
        server1
            .listen(addr1)
            .await
            .expect("Failed to start server1");
        server2
            .listen(addr2)
            .await
            .expect("Failed to start server2");

        let bound_addr = server1.endpoint.as_ref().unwrap().local_addr().unwrap();

        let conn_task = tokio::spawn(async move {
            server2
                .connect_as_server(bound_addr)
                .await
                .expect("Connect failed");
            server2
        });

        let _accept_result = server1.accept().await.expect("Accept failed");
        let server2 = conn_task.await.unwrap();

        // Both servers should have their own local public keys
        assert!(server1.local_public_key.is_some());
        assert!(server2.local_public_key.is_some());

        // With mTLS, server1 should have server2's public key stored
        let server2_derived_id = server2.local_derived_id();
        assert!(
            server1.peer_public_keys.contains_key(&server2_derived_id),
            "server1 should have server2's public key stored"
        );
    }

    #[tokio::test]
    async fn test_send_receive_after_connection() {
        ensure_crypto_provider();
        let mut server = QuicNetworkManager::with_node_id(1);
        let mut client = QuicNetworkManager::with_node_id(100);

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        server.listen(addr).await.expect("Failed to start server");

        let bound_addr = server.endpoint.as_ref().unwrap().local_addr().unwrap();

        let conn_task = tokio::spawn(async move {
            let conn = client
                .connect_as_client(bound_addr)
                .await
                .expect("Connect failed");
            (client, conn)
        });

        let server_conn = server.accept().await.expect("Accept failed");
        let (_client, client_conn) = conn_task.await.unwrap();

        // Test sending from client to server
        let test_data = b"Hello, server!";
        client_conn.send(test_data).await.expect("Send failed");

        let received = server_conn.receive().await.expect("Receive failed");
        assert_eq!(received, test_data);

        // Test sending from server to client
        let response_data = b"Hello, client!";
        server_conn
            .send(response_data)
            .await
            .expect("Send response failed");

        let received_response = client_conn
            .receive()
            .await
            .expect("Receive response failed");
        assert_eq!(received_response, response_data);
    }

    #[tokio::test]
    async fn test_local_derived_id() {
        ensure_crypto_provider();
        let mut manager = QuicNetworkManager::new();

        // Before certificate generation, local_derived_id should return node_id
        let initial_id = manager.local_derived_id();
        assert_eq!(initial_id, manager.node_id);

        // After certificate generation
        manager.ensure_local_certificate().unwrap();

        // Now local_derived_id should return derived ID from public key
        let derived_id = manager.local_derived_id();
        let expected_id = manager.local_public_key.as_ref().unwrap().derive_id();
        assert_eq!(derived_id, expected_id);
    }

    #[test]
    fn test_node_public_key_derive_id() {
        let pk1 = NodePublicKey(vec![0x00, 0x01, 0x02]);
        let pk2 = NodePublicKey(vec![0x00, 0x01, 0x02]);
        let pk3 = NodePublicKey(vec![0x00, 0x01, 0x03]);

        // Same public key should derive same ID
        assert_eq!(pk1.derive_id(), pk2.derive_id());

        // Different public keys should derive different IDs
        assert_ne!(pk1.derive_id(), pk3.derive_id());
    }

    #[test]
    fn test_node_public_key_derive_id_deterministic() {
        let pk = NodePublicKey(vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        ]);

        // Multiple calls should return the same ID
        let id1 = pk.derive_id();
        let id2 = pk.derive_id();
        let id3 = pk.derive_id();

        assert_eq!(id1, id2);
        assert_eq!(id2, id3);
    }

    #[test]
    fn test_get_sorted_public_keys() {
        ensure_crypto_provider();
        let mut manager = QuicNetworkManager::new();
        manager.ensure_local_certificate().unwrap();

        // Create some peer public keys (manually sorted in reverse to test sorting)
        let pk_c = NodePublicKey(vec![0x03, 0x01, 0x02]);
        let pk_b = NodePublicKey(vec![0x02, 0x01, 0x02]);
        let pk_a = NodePublicKey(vec![0x01, 0x01, 0x02]);

        manager
            .peer_public_keys
            .insert(pk_c.derive_id(), pk_c.clone());
        manager
            .peer_public_keys
            .insert(pk_b.derive_id(), pk_b.clone());
        manager
            .peer_public_keys
            .insert(pk_a.derive_id(), pk_a.clone());

        let sorted = manager.get_sorted_public_keys();

        // Should have 4 keys (local + 3 peers)
        assert_eq!(sorted.len(), 4);

        // Keys should be sorted lexicographically
        for i in 1..sorted.len() {
            assert!(sorted[i - 1].0 < sorted[i].0, "Keys should be sorted");
        }
    }

    #[test]
    fn test_get_public_key_for_party_id() {
        ensure_crypto_provider();
        let mut manager = QuicNetworkManager::new();
        manager.ensure_local_certificate().unwrap();

        // Add a peer with a known public key
        let peer_pk = NodePublicKey(vec![0xFF, 0xFF, 0xFF]); // Will sort after local key
        manager
            .peer_public_keys
            .insert(peer_pk.derive_id(), peer_pk.clone());

        // Get the sorted keys to determine expected order
        let sorted = manager.get_sorted_public_keys();
        assert_eq!(sorted.len(), 2);

        // sender_id 0 should be the first in sorted order
        let pk0 = manager.get_public_key_for_party_id(0).unwrap();
        assert_eq!(pk0, sorted[0]);

        // sender_id 1 should be the second in sorted order
        let pk1 = manager.get_public_key_for_party_id(1).unwrap();
        assert_eq!(pk1, sorted[1]);

        // sender_id 2 should be None (out of range)
        assert!(manager.get_public_key_for_party_id(2).is_none());
    }

    #[test]
    fn test_get_party_id_for_public_key() {
        ensure_crypto_provider();
        let mut manager = QuicNetworkManager::new();
        manager.ensure_local_certificate().unwrap();

        let local_pk = manager.local_public_key.clone().unwrap();

        // Add peers with known public keys
        let peer_pk1 = NodePublicKey(vec![0x00, 0x00, 0x01]);
        let peer_pk2 = NodePublicKey(vec![0xFF, 0xFF, 0xFF]);
        manager
            .peer_public_keys
            .insert(peer_pk1.derive_id(), peer_pk1.clone());
        manager
            .peer_public_keys
            .insert(peer_pk2.derive_id(), peer_pk2.clone());

        // Get sorted keys
        let sorted = manager.get_sorted_public_keys();
        assert_eq!(sorted.len(), 3);

        // Each key should map to its position in the sorted list
        for (expected_id, pk) in sorted.iter().enumerate() {
            let actual_id = manager.get_party_id_for_public_key(pk).unwrap();
            assert_eq!(
                actual_id, expected_id,
                "sender_id should match position in sorted list"
            );
        }

        // Unknown public key should return None
        let unknown_pk = NodePublicKey(vec![0xAA, 0xBB, 0xCC]);
        assert!(manager.get_party_id_for_public_key(&unknown_pk).is_none());
    }

    #[test]
    fn test_party_count() {
        ensure_crypto_provider();
        let mut manager = QuicNetworkManager::new();

        // Initially no parties (no certificate)
        assert_eq!(manager.party_count(), 0);

        // After generating certificate, we have 1 party (self)
        manager.ensure_local_certificate().unwrap();
        assert_eq!(manager.party_count(), 1);

        // Add peers
        let pk1 = NodePublicKey(vec![0x01]);
        let pk2 = NodePublicKey(vec![0x02]);
        manager.peer_public_keys.insert(pk1.derive_id(), pk1);
        assert_eq!(manager.party_count(), 2);

        manager.peer_public_keys.insert(pk2.derive_id(), pk2);
        assert_eq!(manager.party_count(), 3);
    }

    #[tokio::test]
    async fn test_sender_ids_are_sequential_0_to_n() {
        ensure_crypto_provider();

        // Create two servers
        let mut server1 = QuicNetworkManager::with_node_id(1);
        let mut server2 = QuicNetworkManager::with_node_id(2);

        // Start listening (generates certificates)
        let addr1: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:0".parse().unwrap();
        server1
            .listen(addr1)
            .await
            .expect("Failed to start server1");
        server2
            .listen(addr2)
            .await
            .expect("Failed to start server2");

        let bound_addr = server1.endpoint.as_ref().unwrap().local_addr().unwrap();

        // Connect server2 to server1
        let conn_task = tokio::spawn(async move {
            server2
                .connect_as_server(bound_addr)
                .await
                .expect("Connect failed");
            server2
        });

        let _accept = server1.accept().await.expect("Accept failed");
        let server2 = conn_task.await.unwrap();

        // Both should now have 2 parties
        assert_eq!(server1.party_count(), 2);
        assert_eq!(server2.party_count(), 2);

        // Sender IDs should be 0 and 1
        let server1_sender_id = server1.compute_local_party_id().unwrap();
        let server2_sender_id = server2.compute_local_party_id().unwrap();

        // One should be 0, the other should be 1
        assert!(server1_sender_id == 0 || server1_sender_id == 1);
        assert!(server2_sender_id == 0 || server2_sender_id == 1);
        assert_ne!(
            server1_sender_id, server2_sender_id,
            "Sender IDs should be different"
        );

        // Verify the IDs are consistent across both servers
        // Both servers should agree on who is 0 and who is 1
        let server1_pk = server1.local_public_key.clone().unwrap();
        let server2_pk = server2.local_public_key.clone().unwrap();

        // From server1's perspective
        let s1_id_for_s1 = server1.get_party_id_for_public_key(&server1_pk).unwrap();
        let s1_id_for_s2 = server1.get_party_id_for_public_key(&server2_pk).unwrap();

        // From server2's perspective
        let s2_id_for_s1 = server2.get_party_id_for_public_key(&server1_pk).unwrap();
        let s2_id_for_s2 = server2.get_party_id_for_public_key(&server2_pk).unwrap();

        // Both should agree on sender IDs
        assert_eq!(
            s1_id_for_s1, s2_id_for_s1,
            "Both servers should agree on server1's sender_id"
        );
        assert_eq!(
            s1_id_for_s2, s2_id_for_s2,
            "Both servers should agree on server2's sender_id"
        );
    }

    // ========================================================================
    // Happy Path Tests
    // ========================================================================

    #[tokio::test]
    async fn test_loopback_send_receive() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999);
        let conn = LoopbackPeerConnection::new(addr, None);

        conn.send(b"hello").await.expect("Send failed");
        let received = conn.receive().await.expect("Receive failed");
        assert_eq!(received, b"hello");
    }

    #[tokio::test]
    async fn test_loopback_multiple_messages() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999);
        let conn = LoopbackPeerConnection::new(addr, None);

        conn.send(b"first").await.expect("Send first failed");
        conn.send(b"second").await.expect("Send second failed");
        conn.send(b"third").await.expect("Send third failed");

        let r1 = conn.receive().await.expect("Receive first failed");
        let r2 = conn.receive().await.expect("Receive second failed");
        let r3 = conn.receive().await.expect("Receive third failed");

        assert_eq!(r1, b"first");
        assert_eq!(r2, b"second");
        assert_eq!(r3, b"third");
    }

    #[test]
    fn test_framing_round_trip() {
        let original = b"round trip data";
        let framed = LoopbackPeerConnection::frame_message(original);
        let unframed = LoopbackPeerConnection::unframe_message(framed).expect("Unframe failed");
        assert_eq!(unframed, original);
    }

    #[test]
    fn test_loopback_remote_address() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999);
        let conn = LoopbackPeerConnection::new(addr, None);
        assert_eq!(conn.remote_address(), addr);
    }

    #[test]
    fn test_loopback_connection_role() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999);
        let conn = LoopbackPeerConnection::new(addr, None);
        assert_eq!(conn.get_connection_role(), ClientType::Server);
    }

    #[test]
    fn test_loopback_party_id() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999);
        let conn = LoopbackPeerConnection::new(addr, Some(42));
        assert_eq!(conn.remote_party_id(), Some(42));
    }

    #[test]
    fn test_loopback_set_party_id() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999);
        let conn = LoopbackPeerConnection::new(addr, None);
        assert_eq!(conn.remote_party_id(), None);

        conn.set_remote_party_id(99);
        assert_eq!(conn.remote_party_id(), Some(99));
    }

    // ========================================================================
    // Semi-Honest Tests
    // ========================================================================

    #[tokio::test]
    async fn test_loopback_send_empty_message() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999);
        let conn = LoopbackPeerConnection::new(addr, None);

        conn.send(&[]).await.expect("Send empty failed");
        let received = conn.receive().await.expect("Receive empty failed");
        assert!(received.is_empty());
    }

    #[tokio::test]
    async fn test_loopback_send_after_close() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999);
        let conn = LoopbackPeerConnection::new(addr, None);

        conn.close().await.expect("Close failed");
        let result = conn.send(b"should fail").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_loopback_state_after_close() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999);
        let conn = LoopbackPeerConnection::new(addr, None);

        assert_eq!(conn.state().await, ConnectionState::Connected);
        assert!(conn.is_connected().await);

        conn.close().await.expect("Close failed");
        assert_eq!(conn.state().await, ConnectionState::Closed);
        assert!(!conn.is_connected().await);
    }

    #[tokio::test]
    async fn test_loopback_receive_after_close() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999);
        let conn = LoopbackPeerConnection::new(addr, None);

        conn.close().await.expect("Close failed");
        let result = conn.receive().await;
        assert!(result.is_err(), "receive after close should fail");
    }

    // ========================================================================
    // Malicious / Framing Error Tests
    // ========================================================================

    #[test]
    fn test_unframe_message_too_short() {
        let result = LoopbackPeerConnection::unframe_message(vec![0, 0]);
        assert!(result.is_err());
        match result.unwrap_err() {
            ConnectionError::FramingError(_) => {} // expected
            other => panic!("Expected FramingError, got: {:?}", other),
        }
    }

    #[test]
    fn test_unframe_message_wrong_length() {
        // Header says length is 10, but only 5 bytes of data follow
        let mut data = Vec::new();
        data.extend_from_slice(&10u32.to_be_bytes());
        data.extend_from_slice(&[1, 2, 3, 4, 5]);

        let result = LoopbackPeerConnection::unframe_message(data);
        assert!(result.is_err());
        match result.unwrap_err() {
            ConnectionError::FramingError(_) => {} // expected
            other => panic!("Expected FramingError, got: {:?}", other),
        }
    }

    #[test]
    fn test_unframe_message_empty() {
        let result = LoopbackPeerConnection::unframe_message(vec![]);
        assert!(result.is_err());
        match result.unwrap_err() {
            ConnectionError::FramingError(_) => {} // expected
            other => panic!("Expected FramingError, got: {:?}", other),
        }
    }

    #[test]
    fn test_framing_empty_data() {
        let framed = LoopbackPeerConnection::frame_message(&[]);
        assert_eq!(framed, vec![0, 0, 0, 0]);

        let unframed =
            LoopbackPeerConnection::unframe_message(framed).expect("Unframe empty failed");
        assert!(unframed.is_empty());
    }

    // ========================================================================
    // Concurrency Tests
    // ========================================================================

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_sends() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999);
        let conn = Arc::new(LoopbackPeerConnection::new(addr, None));

        // Spawn senders and a receiver concurrently to exercise actual contention
        let conn_recv = conn.clone();
        let receiver = tokio::spawn(async move {
            let mut received_values = Vec::new();
            for _ in 0..10 {
                let data = conn_recv
                    .receive()
                    .await
                    .expect("Concurrent receive failed");
                assert_eq!(data.len(), 1);
                received_values.push(data[0]);
            }
            received_values
        });

        let mut send_handles = Vec::new();
        for i in 0u8..10 {
            let conn_clone = conn.clone();
            let handle = tokio::spawn(async move {
                conn_clone.send(&[i]).await.expect("Concurrent send failed");
            });
            send_handles.push(handle);
        }

        for handle in send_handles {
            handle.await.expect("Task panicked");
        }

        let mut received_values = receiver.await.expect("Receiver panicked");
        received_values.sort();
        assert_eq!(received_values, (0u8..10).collect::<Vec<_>>());
    }

    // ========================================================================
    // Connection Error Display Tests
    // ========================================================================

    #[test]
    fn test_connection_error_display_contains_inner_message() {
        // Verify Display output includes the inner message for each variant
        let display_lost = format!(
            "{}",
            ConnectionError::ConnectionLost("peer gone".to_string())
        );
        assert!(
            display_lost.contains("peer gone"),
            "ConnectionLost should contain inner msg, got: {}",
            display_lost
        );

        let display_send = format!("{}", ConnectionError::SendFailed("write err".to_string()));
        assert!(
            display_send.contains("write err"),
            "SendFailed should contain inner msg, got: {}",
            display_send
        );

        let display_recv = format!("{}", ConnectionError::ReceiveFailed("read err".to_string()));
        assert!(
            display_recv.contains("read err"),
            "ReceiveFailed should contain inner msg, got: {}",
            display_recv
        );

        let display_frame = format!("{}", ConnectionError::FramingError("bad frame".to_string()));
        assert!(
            display_frame.contains("bad frame"),
            "FramingError should contain inner msg, got: {}",
            display_frame
        );

        let display_init = format!(
            "{}",
            ConnectionError::InitializationFailed("init err".to_string())
        );
        assert!(
            display_init.contains("init err"),
            "InitializationFailed should contain inner msg, got: {}",
            display_init
        );

        let display_state = format!(
            "{}",
            ConnectionError::InvalidState(ConnectionState::Disconnected)
        );
        assert!(
            !display_state.is_empty(),
            "InvalidState should produce non-empty display"
        );

        let display_closed = format!("{}", ConnectionError::StreamClosed);
        assert!(
            !display_closed.is_empty(),
            "StreamClosed should produce non-empty display"
        );
    }

    #[test]
    fn test_connection_error_to_string() {
        let error = ConnectionError::SendFailed("test".to_string());
        let s: String = error.into();
        assert!(
            s.contains("test"),
            "From<ConnectionError> for String should contain inner msg"
        );
    }
}
