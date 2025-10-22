//! # Peer-to-Peer Networking for StoffelVM (Actor Model Compatible)
//!
//! ## QUIC Stream Model
//!
//! This implementation uses persistent bidirectional streams with improved
//! connection state management and graceful handling of stream/connection closures.

use quinn::{ClientConfig, Connection, Endpoint, ServerConfig, IdleTimeout};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use dashmap::{DashMap, DashSet};
use crate::network_utils::{ClientId, Message, Network, NetworkError, Node, PartyId};
use tokio::sync::{Mutex, mpsc};
use ark_ff::Field;
use async_trait::async_trait;
use uuid::Uuid;
use std::time::Duration;
use crate::transports::net_envelope::NetEnvelope;
use tracing::{debug, error, info, trace, warn};

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

pub struct QuicPeerConnection {
    connection: Connection,
    remote_addr: SocketAddr,
    /// Persistent send stream - uses interior mutability for sharing
    send_stream: Arc<Mutex<quinn::SendStream>>,
    /// Persistent receive stream - uses interior mutability for sharing
    recv_stream: Arc<Mutex<quinn::RecvStream>>,
    /// Connection state
    state: Arc<Mutex<ConnectionState>>,
}

impl QuicPeerConnection {
    /// Creates a new connection with an already-opened bidirectional stream
    pub fn new(
        connection: Connection,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    ) -> Self {
        let remote_addr = connection.remote_address();
        Self {
            connection,
            remote_addr,
            send_stream: Arc::new(Mutex::new(send)),
            recv_stream: Arc::new(Mutex::new(recv)),
            state: Arc::new(Mutex::new(ConnectionState::Connected)),
        }
    }

    /// Creates a new connection and immediately opens a bidirectional stream
    pub async fn new_with_connection(connection: Connection) -> Result<Self, ConnectionError> {
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
        if let Some(err) = self.connection.close_reason() {
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
}

// ============================================================================
// LOOPBACK PEER CONNECTION (for self-delivery)
// ============================================================================

pub struct LoopbackPeerConnection {
    remote_addr: SocketAddr,
    tx: mpsc::Sender<Vec<u8>>,
    rx: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    state: Arc<Mutex<ConnectionState>>,
}

impl LoopbackPeerConnection {
    pub fn new(remote_addr: SocketAddr) -> Self {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(1024);
        Self {
            remote_addr,
            tx,
            rx: Arc::new(Mutex::new(rx)),
            state: Arc::new(Mutex::new(ConnectionState::Connected)),
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
        Ok(NetEnvelope::HoneyBadger(_)) => Ok(None), // Legacy, no handshake
        Err(_) => Ok(None), // Not an envelope, legacy path
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
}

impl Default for QuicNetworkConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 30000,
            max_retries: 3,
            use_tls: true,
        }
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
        }
    }

    pub fn with_node_id(node_id: PartyId) -> Self {
        let mut manager = Self::new();
        manager.node_id = node_id;
        manager
    }

    pub fn with_config(config: QuicNetworkConfig) -> Self {
        let mut manager = Self::new();
        manager.network_config = config;
        manager
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

        // Create Arc-wrapped connection
        let conn = Arc::new(QuicPeerConnection::new(
            connection.clone(),
            send,
            recv,
        )) as Arc<dyn PeerConnection>;

        // Determine the correct party_id to use
        let party_id = if let Some((role, id)) = server_handshake {
            if role.eq_ignore_ascii_case("SERVER") {
                // Server told us its PartyId - use it!
                info!("Client {} connected to server with PartyId {}", client_id, id);

                // Ensure node exists with this party_id
                if !self.nodes.iter().any(|n| n.id() == id) {
                    self.nodes.push(QuicNode::from_party_id(id, address));
                }

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
        let (mut send, recv) = connection.open_bi().await
            .map_err(|e| format!("Failed to open stream: {}", e))?;

        send_handshake(&mut send, "SERVER", party_id).await
            .map_err(|e| format!("Failed to send handshake: {}", e))?;

        // Create Arc-wrapped connection
        let conn = Arc::new(QuicPeerConnection::new(
            connection.clone(),
            send,
            recv,
        )) as Arc<dyn PeerConnection>;

        // Find or create node and store connection
        let node_id = self.nodes.iter()
            .find(|n| n.address() == address)
            .map(|n| n.id())
            .unwrap_or_else(|| {
                let node = QuicNode::new_with_random_id(address);
                let id = node.id();
                self.nodes.push(node);
                id
            });

        self.connections.insert(node_id, Arc::clone(&conn));

        Ok(conn)
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