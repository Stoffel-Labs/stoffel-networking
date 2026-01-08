//! # Peer-to-Peer Networking for StoffelVM (Actor Model Compatible)
//!
//! ## QUIC Stream Model
//!
//! This implementation uses persistent bidirectional streams with improved
//! connection state management and graceful handling of stream/connection closures.

use quinn::{ClientConfig, Connection, Endpoint, ServerConfig, IdleTimeout};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use dashmap::{DashMap, DashSet};
use crate::network_utils::{ClientId, ClientType, Message, Network, NetworkError, Node, PartyId};
use tokio::sync::{Mutex, mpsc};
use ark_ff::Field;
use async_trait::async_trait;
use uuid::Uuid;
use std::time::Duration;
use crate::transports::net_envelope::NetEnvelope;
use tracing::{debug, info, warn};

// ============================================================================
// CONNECTION STATE
// ============================================================================

/// Represents the current state of a connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Connection is active and healthy
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

/// Error type for connection operations
#[derive(Debug, Clone)]
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
    fn receive<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>>;

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
}

impl Debug for dyn PeerConnection {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "PeerConnection {{ remote_address: {} }}", self.remote_address())
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
        return Err(ConnectionError::FramingError(
            format!("Message size {} exceeds maximum {}", data.len(), MAX_MESSAGE_SIZE)
        ));
    }

    // Write 4-byte length prefix (big-endian)
    let len = data.len() as u32;
    send.write_all(&len.to_be_bytes())
        .await
        .map_err(|e| {
            // Check if this is a connection error
            if e.to_string().contains("closed") || e.to_string().contains("reset") {
                ConnectionError::ConnectionLost(format!("Connection lost while writing length: {}", e))
            } else {
                ConnectionError::SendFailed(format!("Failed to write length: {}", e))
            }
        })?;

    // Write message payload
    send.write_all(data)
        .await
        .map_err(|e| {
            if e.to_string().contains("closed") || e.to_string().contains("reset") {
                ConnectionError::ConnectionLost(format!("Connection lost while writing payload: {}", e))
            } else {
                ConnectionError::SendFailed(format!("Failed to write payload: {}", e))
            }
        })?;

    Ok(())
}

/// Receives a length-prefixed message with better EOF handling
async fn recv_framed_message(
    recv: &mut quinn::RecvStream,
) -> Result<Vec<u8>, ConnectionError> {
    // Read 4-byte length prefix
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| match e {
            quinn::ReadExactError::FinishedEarly(_) => ConnectionError::StreamClosed,
            quinn::ReadExactError::ReadError(re) => {
                // Check if this is a connection lost scenario
                let err_str = re.to_string();
                if err_str.contains("closed") || err_str.contains("reset") || err_str.contains("connection lost") {
                    ConnectionError::ConnectionLost(format!("Connection lost while reading length: {}", re))
                } else {
                    ConnectionError::ReceiveFailed(format!("Failed to read length: {}", re))
                }
            }
        })?;

    let len = u32::from_be_bytes(len_buf) as usize;

    // Validate message size
    if len > MAX_MESSAGE_SIZE {
        return Err(ConnectionError::FramingError(
            format!("Message size {} exceeds maximum {}", len, MAX_MESSAGE_SIZE)
        ));
    }

    // Read message payload
    let mut msg = vec![0u8; len];
    recv.read_exact(&mut msg)
        .await
        .map_err(|e| match e {
            quinn::ReadExactError::FinishedEarly(_) => ConnectionError::StreamClosed,
            quinn::ReadExactError::ReadError(re) => {
                let err_str = re.to_string();
                if err_str.contains("closed") || err_str.contains("reset") || err_str.contains("connection lost") {
                    ConnectionError::ConnectionLost(format!("Connection lost while reading payload: {}", re))
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
}

impl QuicPeerConnection {
    /// Creates a new connection with an already-opened bidirectional stream
    pub fn new(
        connection: Connection,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
        connection_role: ClientType,
    ) -> Self {
        let remote_addr = connection.remote_address();
        Self {
            connection,
            remote_addr,
            send_stream: Arc::new(Mutex::new(send)),
            recv_stream: Arc::new(Mutex::new(recv)),
            state: Arc::new(Mutex::new(ConnectionState::Connected)),
            connection_role,
        }
    }

    /// Creates a new connection and immediately opens a bidirectional stream
    pub async fn new_with_connection(
        connection: Connection,
        connection_role: ClientType,
    ) -> Result<Self, ConnectionError> {
        let remote_addr = connection.remote_address();
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|e| ConnectionError::InitializationFailed(
                format!("Failed to open stream: {}", e)
            ))?;

        Ok(Self {
            connection,
            remote_addr,
            send_stream: Arc::new(Mutex::new(send)),
            recv_stream: Arc::new(Mutex::new(recv)),
            state: Arc::new(Mutex::new(ConnectionState::Connected)),
            connection_role,
        })
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

    fn receive<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
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
            self.connection.close(0u32.into(), b"Connection closed gracefully");
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
}

// ============================================================================
// LOOPBACK PEER CONNECTION (for self-delivery)
// ============================================================================

pub struct LoopbackPeerConnection {
    remote_addr: SocketAddr,
    tx: mpsc::Sender<Vec<u8>>,
    rx: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    state: Arc<Mutex<ConnectionState>>,
    connection_role: ClientType,
}

impl LoopbackPeerConnection {
    pub fn new(remote_addr: SocketAddr) -> Self {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(1024);
        Self {
            remote_addr,
            tx,
            rx: Arc::new(Mutex::new(rx)),
            state: Arc::new(Mutex::new(ConnectionState::Connected)),
            connection_role: ClientType::Server,
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
            return Err(ConnectionError::FramingError("Message too short".to_string()));
        }

        let len_bytes: [u8; 4] = framed[0..4].try_into().unwrap();
        let len = u32::from_be_bytes(len_bytes) as usize;

        if framed.len() != 4 + len {
            return Err(ConnectionError::FramingError(
                format!("Length mismatch: expected {}, got {}", len, framed.len() - 4)
            ));
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
            self.tx
                .send(framed)
                .await
                .map_err(|e| {
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

    fn receive<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
        Box::pin(async move {
            // Check state
            {
                let state = self.state.lock().await;
                if *state == ConnectionState::Closed || *state == ConnectionState::Disconnected {
                    return Err(format!("Cannot receive: loopback connection is {:?}", *state));
                }
            }

            let mut rx = self.rx.lock().await;
            match rx.recv().await {
                Some(framed) => {
                    Self::unframe_message(framed).map_err(|e| e.to_string())
                }
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
}

// ============================================================================
// HANDSHAKE HELPERS
// ============================================================================

/// Sends a handshake envelope over a stream
async fn send_handshake(
    send: &mut quinn::SendStream,
    role: &str,
    id: usize,
) -> Result<(), ConnectionError> {
    let envelope = NetEnvelope::Handshake {
        role: role.to_string(),
        id,
    };
    let bytes = envelope.serialize();
    send_framed_message(send, &bytes).await
}

/// Receives a handshake envelope from a stream
async fn recv_handshake(
    recv: &mut quinn::RecvStream,
) -> Result<Option<(String, usize)>, ConnectionError> {
    let bytes = recv_framed_message(recv).await?;

    match NetEnvelope::try_deserialize(&bytes) {
        Ok(NetEnvelope::Handshake { role, id }) => Ok(Some((role, id))),
        Ok(_) => Ok(None), // Not a handshake envelope
        Err(_) => Ok(None), // Not an envelope, legacy path
    }
}

fn client_type_from_role(role: &str) -> ClientType {
    if role.eq_ignore_ascii_case("CLIENT") {
        ClientType::Client
    } else {
        ClientType::Server
    }
}

// ============================================================================
// QUIC NODE
// ============================================================================

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
pub struct QuicNetworkConfig {
    pub timeout_ms: u64,
    pub max_retries: u32,
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

impl QuicNetworkConfig {
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

#[derive(Clone)]
pub struct QuicNetworkManager {
    endpoint: Option<Endpoint>,
    nodes: Vec<QuicNode>,
    node_id: PartyId,
    network_config: QuicNetworkConfig,
    /// Replaced Mutex<HashMap> with DashMap for better concurrent access
    connections: Arc<DashMap<PartyId, Arc<dyn PeerConnection>>>,
    /// Replaced Mutex<HashMap> with DashMap for client connections
    client_connections: Arc<DashMap<ClientId, Arc<dyn PeerConnection>>>,
    /// Replaced Mutex<HashSet> with DashSet for client IDs
    client_ids: Arc<DashSet<ClientId>>,

    // NAT Traversal State
    /// STUN client for reflexive address discovery
    stun_client: Option<Arc<crate::transports::stun::StunClient>>,
    /// Cached local ICE candidates
    local_candidates: Arc<Mutex<Option<crate::transports::ice::LocalCandidates>>>,
    /// Active ICE agents for pending P2P negotiations
    pending_ice_agents: Arc<DashMap<PartyId, Arc<Mutex<crate::transports::ice_agent::IceAgent>>>>,
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
            connections: Arc::new(DashMap::new()),
            client_connections: Arc::new(DashMap::new()),
            client_ids: Arc::new(DashSet::new()),
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

    pub fn with_config(config: QuicNetworkConfig) -> Self {
        let stun_client = if config.enable_nat_traversal {
            let stun_servers = config
                .stun_servers
                .iter()
                .map(|addr| crate::transports::stun::StunServerConfig::new(*addr))
                .collect();
            Some(Arc::new(crate::transports::stun::StunClient::new(stun_servers)))
        } else {
            None
        };

        Self {
            endpoint: None,
            nodes: Vec::new(),
            node_id: Uuid::new_v4().as_u128() as PartyId,
            network_config: config,
            connections: Arc::new(DashMap::new()),
            client_connections: Arc::new(DashMap::new()),
            client_ids: Arc::new(DashSet::new()),
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
        if !self.connections.contains_key(&self.node_id) {
            let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            self.connections.insert(
                self.node_id,
                Arc::new(LoopbackPeerConnection::new(addr)) as Arc<dyn PeerConnection>
            );
        }
    }

    /// Gets a connection by party ID (for actor model usage)
    pub async fn get_connection(&self, party_id: PartyId) -> Option<Arc<dyn PeerConnection>> {
        self.connections.get(&party_id).map(|entry| Arc::clone(entry.value()))
    }

    /// Gets all party connections (for actor model usage)
    pub async fn get_all_connections(&self) -> Vec<(PartyId, Arc<dyn PeerConnection>)> {
        self.connections
            .iter()
            .map(|entry| (*entry.key(), Arc::clone(entry.value())))
            .collect()
    }

    /// Removes dead connections from the connection map
    pub async fn cleanup_dead_connections(&self) {
        let mut to_remove = Vec::new();

        for entry in self.connections.iter() {
            let party_id = *entry.key();
            let conn = entry.value();
            if !conn.is_connected().await {
                to_remove.push(party_id);
            }
        }

        for party_id in to_remove {
            self.connections.remove(&party_id);
        }
    }

    /// Checks connection health for a specific party
    pub async fn is_party_connected(&self, party_id: PartyId) -> bool {
        if let Some(conn_ref) = self.connections.get(&party_id) {
            conn_ref.value().is_connected().await
        } else {
            false
        }
    }

    /// Creates insecure client config (for development only)
    fn create_insecure_client_config() -> Result<ClientConfig, String> {
        let mut crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification::new()))
            .with_no_client_auth();

        crypto.alpn_protocols = vec![b"quic-example".to_vec()];

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

    /// Creates self-signed server config (for development only)
    fn create_self_signed_server_config() -> Result<ServerConfig, String> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .map_err(|e| format!("Failed to generate certificate: {}", e))?;

        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(
            PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())
        );

        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .map_err(|e| format!("Failed to create server crypto config: {}", e))?;

        server_crypto.alpn_protocols = vec![b"quic-example".to_vec()];

        let mut server_config = ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
                .map_err(|e| format!("Failed to create QUIC server config: {}", e))?,
        ));

        let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
        transport_config.max_concurrent_uni_streams(0u32.into());
        transport_config.keep_alive_interval(Some(Duration::from_secs(5)));
        transport_config.max_idle_timeout(Some(IdleTimeout::from(quinn::VarInt::from_u32(300_000))));

        Ok(server_config)
    }

    /// Ensures endpoint is initialized with client config
    async fn ensure_client_endpoint(&mut self) -> Result<(), String> {
        if self.endpoint.is_none() {
            let client_config = Self::create_insecure_client_config()?;
            let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
                .map_err(|e| format!("Failed to create client endpoint: {}", e))?;
            endpoint.set_default_client_config(client_config);
            self.endpoint = Some(endpoint);
        }
        Ok(())
    }

    /// Connects and sends a CLIENT handshake
    /// Returns Arc<dyn PeerConnection> for actor model compatibility
    /// Connects and sends a CLIENT handshake
    /// Returns Arc<dyn PeerConnection> for actor model compatibility
    pub async fn connect_as_client(
        &mut self,
        address: SocketAddr,
        client_id: ClientId,
    ) -> Result<Arc<dyn PeerConnection>, String> {
        self.ensure_client_endpoint().await?;
        self.ensure_loopback_installed().await;

        let endpoint = self.endpoint.as_ref().unwrap();
        let connection = endpoint
            .connect(address, "localhost")
            .map_err(|e| format!("Failed to initiate connection: {}", e))?
            .await
            .map_err(|e| format!("Failed to establish connection: {}", e))?;

        // Open persistent stream and send handshake
        let (mut send, mut recv) = connection.open_bi().await
            .map_err(|e| format!("Failed to open stream: {}", e))?;

        send_handshake(&mut send, "CLIENT", client_id).await
            .map_err(|e| format!("Failed to send handshake: {}", e))?;

        // Receive server's handshake response to get its PartyId
        let server_handshake = recv_handshake(&mut recv).await
            .map_err(|e| format!("Failed to receive server handshake: {}", e))?;

        let mut connection_role = ClientType::Server;
        // Determine the correct party_id to use
        let party_id = if let Some((role, id)) = server_handshake {
            connection_role = client_type_from_role(&role);
            if role.eq_ignore_ascii_case("SERVER") {
                // Server told us its PartyId - use it!
                info!("Client {} connected to server with PartyId {}", client_id, id);

                // Ensure node exists with this party_id
                // if !self.nodes.iter().any(|n| n.id() == id) {
                let node = QuicNode::from_party_id(id, address);
                self.nodes.push(node);
                // }

                id
            } else {
                // Unexpected role, fallback to address-based lookup
                warn!("Unexpected handshake role from server: {}", role);
                self.fallback_node_lookup(address)
            }
        } else {
            // No handshake received, fallback to address-based lookup
            warn!("No handshake received from server at {}", address);
            self.fallback_node_lookup(address)
        };

        // Create Arc-wrapped connection
        let conn = Arc::new(QuicPeerConnection::new(
            connection.clone(),
            send,
            recv,
            connection_role,
        )) as Arc<dyn PeerConnection>;

        // Store connection with the correct party_id
        self.connections.insert(party_id, Arc::clone(&conn));
        info!("Client {} stored connection to server PartyId {} at {}", client_id, party_id, address);

        Ok(conn)
    }

    /// Fallback method to find or create a node ID when handshake fails
    fn fallback_node_lookup(&mut self, address: SocketAddr) -> PartyId {
        self.nodes.iter()
            .find(|n| n.address() == address)
            .map(|n| n.id())
            .unwrap_or_else(|| {
                warn!("Creating random node ID for address {} - this may cause connection issues", address);
                let node = QuicNode::new_with_random_id(address);
                let id = node.id();
                self.nodes.push(node);
                id
            })
    }

    /// Connects and sends a SERVER handshake
    /// Returns Arc<dyn PeerConnection> for actor model compatibility
    pub async fn connect_as_server(
        &mut self,
        address: SocketAddr,
        party_id: PartyId,
    ) -> Result<Arc<dyn PeerConnection>, String> {
        self.ensure_client_endpoint().await?;
        self.ensure_loopback_installed().await;

        let endpoint = self.endpoint.as_ref().unwrap();
        let connection = endpoint
            .connect(address, "localhost")
            .map_err(|e| format!("Failed to initiate connection: {}", e))?
            .await
            .map_err(|e| format!("Failed to establish connection: {}", e))?;

        // Open persistent stream and send handshake
        let (mut send, mut recv) = connection.open_bi().await
            .map_err(|e| format!("Failed to open stream: {}", e))?;

        send_handshake(&mut send, "SERVER", party_id).await
            .map_err(|e| format!("Failed to send handshake: {}", e))?;

        let server_handshake = recv_handshake(&mut recv).await
            .map_err(|e| format!("Failed to receive server handshake response: {}", e))?;

        let mut connection_role = ClientType::Server;
        // Find or create node and store connection
        let node_id = if let Some((role, id)) = server_handshake {
            connection_role = client_type_from_role(&role);
            if role.eq_ignore_ascii_case("SERVER") {
                if !self.nodes.iter().any(|n| n.id() == id) {
                    self.nodes.push(QuicNode::from_party_id(id, address));
                }
                id
            } else {
                warn!("Unexpected handshake role '{}' from server at {}", role, address);
                self.fallback_node_lookup(address)
            }
        } else {
            warn!("No handshake received from server at {}", address);
            self.fallback_node_lookup(address)
        };

        // Create Arc-wrapped connection
        let conn = Arc::new(QuicPeerConnection::new(
            connection.clone(),
            send,
            recv,
            connection_role,
        )) as Arc<dyn PeerConnection>;

        self.connections.insert(node_id, Arc::clone(&conn));

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
            "8.8.8.8:53",     // Google DNS
            "1.1.1.1:53",     // Cloudflare DNS
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
            let test_addrs = [
                "10.0.0.1:1",
                "192.168.1.1:1",
                "172.16.0.1:1",
            ];

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
    pub async fn create_ice_candidates_message(
        &self,
    ) -> Result<NetEnvelope, String> {
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

        debug!(
            "Received {} remote ICE candidates",
            remote_candidates.len()
        );

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

        // Store agent for potential later use
        self.pending_ice_agents.insert(
            target_party_id,
            Arc::new(Mutex::new(ice_agent)),
        );

        // 5. Ensure endpoint exists
        self.ensure_client_endpoint().await?;
        let endpoint = self.endpoint.as_ref().unwrap();

        // 6. Get the agent back and run connectivity checks
        let agent_arc = self
            .pending_ice_agents
            .get(&target_party_id)
            .map(|e| Arc::clone(e.value()))
            .ok_or("ICE agent not found")?;

        let nominated_pair = {
            let mut agent = agent_arc.lock().await;
            agent
                .run_connectivity_checks(endpoint)
                .await
                .map_err(|e| format!("ICE connectivity checks failed: {}", e))?
        };

        info!(
            "ICE completed: {} -> {} (RTT: {:?}ms)",
            nominated_pair.local.address,
            nominated_pair.remote.address,
            nominated_pair.rtt_ms
        );

        // 7. Establish QUIC connection on the successful pair
        let connection = endpoint
            .connect(nominated_pair.remote.address, "localhost")
            .map_err(|e| format!("Failed to initiate connection: {}", e))?
            .await
            .map_err(|e| format!("Failed to establish connection: {}", e))?;

        // Open stream and perform handshake
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|e| format!("Failed to open stream: {}", e))?;

        send_handshake(&mut send, "SERVER", self.node_id)
            .await
            .map_err(|e| format!("Failed to send handshake: {}", e))?;

        let handshake = recv_handshake(&mut recv)
            .await
            .map_err(|e| format!("Failed to receive handshake: {}", e))?;

        let connection_role = if let Some((role, _)) = handshake {
            client_type_from_role(&role)
        } else {
            ClientType::Server
        };

        let conn = Arc::new(QuicPeerConnection::new(
            connection,
            send,
            recv,
            connection_role,
        )) as Arc<dyn PeerConnection>;

        // Store connection
        self.connections.insert(target_party_id, Arc::clone(&conn));

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
        self.ensure_client_endpoint().await?;
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
        let incoming = endpoint
            .accept()
            .await
            .ok_or("No incoming connection")?;

        let connection = incoming
            .await
            .map_err(|e| format!("Failed to accept connection: {}", e))?;

        let (mut send, mut recv) = connection
            .accept_bi()
            .await
            .map_err(|e| format!("Failed to accept stream: {}", e))?;

        // Read and respond to handshake
        let _handshake = recv_handshake(&mut recv)
            .await
            .map_err(|e| format!("Failed to read handshake: {}", e))?;

        send_handshake(&mut send, "SERVER", self.node_id)
            .await
            .map_err(|e| format!("Failed to send handshake: {}", e))?;

        let conn = Arc::new(QuicPeerConnection::new(
            connection,
            send,
            recv,
            ClientType::Server,
        )) as Arc<dyn PeerConnection>;

        self.connections.insert(from_party_id, Arc::clone(&conn));

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

            let result = tokio::time::timeout(
                Duration::from_secs(3),
                self.connect_as_server(addr, self.node_id),
            )
            .await;

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
                    .handle_p2p_request(
                        from_party_id,
                        ufrag,
                        pwd,
                        candidates,
                        signaling_connection,
                    )
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
        Box::pin(async move {
            self.connect_as_server(address, self.node_id).await
        })
    }

    fn accept<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Arc<dyn PeerConnection>, String>> + Send + 'a>> {
        Box::pin(async move {
            let endpoint = self.endpoint.as_ref()
                .ok_or_else(|| "Endpoint not initialized. Call listen() first.".to_string())?;

            let incoming = endpoint.accept().await
                .ok_or_else(|| "No incoming connections".to_string())?;

            let connection = incoming.await
                .map_err(|e| format!("Failed to accept connection: {}", e))?;

            let remote_addr = connection.remote_address();

            // Accept persistent stream and read handshake
            let (mut send, mut recv) = connection.accept_bi().await
                .map_err(|e| format!("Failed to accept stream: {}", e))?;

            let parsed_role = recv_handshake(&mut recv).await
                .map_err(|e| format!("Failed to read handshake: {}", e))?;

            match parsed_role {
                Some((role, id)) if role.eq_ignore_ascii_case("CLIENT") => {
                    // Send our party_id back to the client so it knows who we are
                    send_handshake(&mut send, "SERVER", self.node_id).await
                        .map_err(|e| format!("Failed to send handshake response: {}", e))?;

                    // Create Arc-wrapped connection AFTER sending handshake
                    let conn = Arc::new(QuicPeerConnection::new(
                        connection.clone(),
                        send,
                        recv,
                        ClientType::Client,
                    )) as Arc<dyn PeerConnection>;

                    // Store as client connection
                    self.client_connections.insert(id, Arc::clone(&conn));
                    self.client_ids.insert(id);

                    Ok(conn)
                }
                Some((role, id)) if role.eq_ignore_ascii_case("SERVER") => {
                    // Server-to-server connection: send handshake response
                    send_handshake(&mut send, "SERVER", self.node_id).await
                        .map_err(|e| format!("Failed to send handshake response: {}", e))?;

                    // Create Arc-wrapped connection
                    let conn = Arc::new(QuicPeerConnection::new(
                        connection.clone(),
                        send,
                        recv,
                        ClientType::Server,
                    )) as Arc<dyn PeerConnection>;

                    // Ensure node exists
                    if !self.nodes.iter().any(|n| n.id() == id) {
                        self.nodes.push(QuicNode::from_party_id(id, remote_addr));
                    }

                    // Store connection
                    self.connections.insert(id, Arc::clone(&conn));

                    Ok(conn)
                }
                _ => {
                    // Fallback: address-based mapping
                    // Create Arc-wrapped connection
                    let conn = Arc::new(QuicPeerConnection::new(
                        connection.clone(),
                        send,
                        recv,
                        ClientType::Server,
                    )) as Arc<dyn PeerConnection>;

                    let node_id = self.nodes.iter()
                        .find(|n| n.address() == remote_addr)
                        .map(|n| n.id())
                        .unwrap_or_else(|| {
                            let node = QuicNode::new_with_random_id(remote_addr);
                            let id = node.id();
                            self.nodes.push(node);
                            id
                        });

                    self.connections.insert(node_id, Arc::clone(&conn));

                    Ok(conn)
                }
            }
        })
    }

    fn listen<'a>(
        &'a mut self,
        bind_address: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let server_config = Self::create_self_signed_server_config()?;
            let mut endpoint = Endpoint::server(server_config, bind_address)
                .map_err(|e| format!("Failed to create server endpoint: {}", e))?;

            let client_config = Self::create_insecure_client_config()?;
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
        if let Some(connection_ref) = self.connections.get(&recipient) {
            let connection = connection_ref.value();

            // Check if connection is still alive
            if !connection.is_connected().await {
                debug!("Connection to recipient {} is dead, removing from map", recipient);
                drop(connection_ref);
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
                    // Connection might be dead, mark for cleanup
                    drop(connection_ref);
                    self.cleanup_dead_connections().await;
                    Err(NetworkError::SendError)
                }
            }
        } else {
            Err(NetworkError::PartyNotFound(recipient))
        }
    }

    async fn broadcast(&self, message: &[u8]) -> Result<usize, NetworkError> {
        let mut total_bytes = 0usize;
        let mut included_self = false;

        for node in &self.nodes {
            if let Some(connection_ref) = self.connections.get(&node.id()) {
                let connection = connection_ref.value();

                // Check connection health before sending
                if !connection.is_connected().await {
                    debug!("Skipping broadcast to node {}: connection is dead", node.id());
                    continue;
                }

                match connection.send(message).await {
                    Ok(_) => {
                        debug!("Successfully broadcasted message to node {}", node.id());
                        total_bytes += message.len();
                        if node.id() == self.node_id {
                            included_self = true;
                        }
                    }
                    Err(e) => {
                        debug!("Failed to broadcast message to node {}: {}", node.id(), e);
                    }
                }
            } else {
                debug!("Warning: No connection to node {}, skipping broadcast", node.id());
            }
        }

        // Ensure self-delivery via loopback
        if !included_self {
            if let Some(connection_ref) = self.connections.get(&self.node_id) {
                let connection = connection_ref.value();
                if connection.is_connected().await && connection.send(message).await.is_ok() {
                    debug!("Successfully broadcasted message to self (loopback)");
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

    async fn send_to_client(&self, client: ClientId, message: &[u8]) -> Result<usize, NetworkError> {
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
}

// ============================================================================
// CERTIFICATE VERIFIER (Development Only)
// ============================================================================

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
