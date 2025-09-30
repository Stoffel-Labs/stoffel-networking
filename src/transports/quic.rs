// src/net/p2p.rs
//! # Peer-to-Peer Networking for StoffelVM
//!
//! This module provides the networking capabilities for StoffelVM, enabling
//! secure communication between distributed parties for multiparty computation.
//!
//! The networking layer is built on the QUIC protocol, which offers:
//! - Encrypted connections using TLS 1.3
//! - Low latency with 0-RTT connection establishment
//! - Stream multiplexing for concurrent data transfers
//! - Connection migration for network changes
//!
//! The module defines two primary abstractions:
//! - `PeerConnection`: Represents a connection to a single peer
//! - `NetworkManager`: Manages multiple peer connections
//!
//! The current implementation uses the Quinn library for QUIC support.

use quinn::{ClientConfig, Connection, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Formatter};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use crate::network_utils::{ClientId, Message, Network, NetworkError, Node, PartyId};
use tokio::sync::{Mutex, mpsc};
use ark_ff::Field;
use async_trait::async_trait;
use uuid::Uuid;

/// Represents a connection to a peer
///
/// This trait defines the interface for communicating with a remote peer.
/// It provides methods for sending and receiving data, managing streams,
/// and controlling the connection lifecycle.
///
/// The interface is transport-agnostic, allowing different implementations
/// to use different underlying protocols (e.g., QUIC, WebRTC, etc.).
pub trait PeerConnection: Send + Sync {
    /// Sends data to the peer on the default stream
    ///
    /// This is a convenience method that sends data on stream ID 0.
    /// For more control, use `send_on_stream`.
    ///
    /// # Arguments
    /// * `data` - The data to send
    ///
    /// # Returns
    /// * `Ok(())` - If the data was sent successfully
    /// * `Err(String)` - If there was an error sending the data
    fn send<'a>(
        &'a mut self,
        data: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

    /// Receives data from the peer on the default stream
    ///
    /// This is a convenience method that receives data from stream ID 0.
    /// For more control, use `receive_from_stream`.
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - The received data
    /// * `Err(String)` - If there was an error receiving data
    fn receive<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>>;

    /// Sends data on a specific stream
    ///
    /// This method allows sending data on a specific stream ID, enabling
    /// multiplexed communication with the peer.
    ///
    /// # Arguments
    /// * `stream_id` - The ID of the stream to send on
    /// * `data` - The data to send
    ///
    /// # Returns
    /// * `Ok(())` - If the data was sent successfully
    /// * `Err(String)` - If there was an error sending the data
    fn send_on_stream<'a>(
        &'a mut self,
        stream_id: u64,
        data: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

    /// Receives data from a specific stream
    ///
    /// This method allows receiving data from a specific stream ID, enabling
    /// multiplexed communication with the peer.
    ///
    /// # Arguments
    /// * `stream_id` - The ID of the stream to receive from
    ///
    /// # Returns
    /// * `Ok(Vec<u8>)` - The received data
    /// * `Err(String)` - If there was an error receiving data
    fn receive_from_stream<'a>(
        &'a mut self,
        stream_id: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>>;

    /// Returns the address of the remote peer
    ///
    /// This method provides the network address of the connected peer,
    /// which can be useful for logging, debugging, or identity verification.
    fn remote_address(&self) -> SocketAddr;

    /// Closes the connection
    ///
    /// This method gracefully terminates the connection with the peer.
    /// After calling this method, no more data can be sent or received.
    ///
    /// # Returns
    /// * `Ok(())` - If the connection was closed successfully
    /// * `Err(String)` - If there was an error closing the connection
    fn close<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}

impl Debug for dyn PeerConnection {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "PeerConnection {{ remote_address: {} }}", self.remote_address())
    }
}

/// Manages network connections for the VM
///
/// This trait defines the interface for managing network connections in the VM.
/// It provides methods for establishing connections to peers, accepting incoming
/// connections, and listening for connection requests.
///
/// The NetworkManager is responsible for:
/// - Creating and configuring network endpoints
/// - Establishing outgoing connections
/// - Accepting incoming connections
/// - Managing connection lifecycle
///
/// Like the PeerConnection trait, this interface is transport-agnostic,
/// allowing different implementations to use different underlying protocols.
pub trait NetworkManager: Send + Sync {
    /// Establishes a connection to a new peer
    ///
    /// This method initiates an outgoing connection to a peer at the specified address.
    /// It handles the connection establishment process, including any necessary
    /// handshaking, encryption setup, and protocol negotiation.
    ///
    /// # Arguments
    /// * `address` - The network address of the peer to connect to
    ///
    /// # Returns
    /// * `Ok(Box<dyn PeerConnection>)` - A connection to the peer
    /// * `Err(String)` - If the connection could not be established
    fn connect<'a>(
        &'a mut self,
        address: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Result<Box<dyn PeerConnection>, String>> + Send + 'a>>;

    /// Accepts an incoming connection
    ///
    /// This method accepts a pending incoming connection from a peer.
    /// It should be called after `listen()` has been called to set up
    /// the listening endpoint.
    ///
    /// This method will block until a connection is available or an error occurs.
    ///
    /// # Returns
    /// * `Ok(Box<dyn PeerConnection>)` - A connection to the peer
    /// * `Err(String)` - If no connection could be accepted
    fn accept<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Box<dyn PeerConnection>, String>> + Send + 'a>>;

    /// Listens for incoming connections
    ///
    /// This method sets up a network endpoint to listen for incoming connections
    /// at the specified address. After calling this method, `accept()` can be
    /// called to accept incoming connections.
    ///
    /// # Arguments
    /// * `bind_address` - The local address to bind to for listening
    ///
    /// # Returns
    /// * `Ok(())` - If the listening endpoint was set up successfully
    /// * `Err(String)` - If the listening endpoint could not be set up
    fn listen<'a>(
        &'a mut self,
        bind_address: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}

/// QUIC-based implementation of PeerConnection
///
/// This struct implements the PeerConnection trait using the QUIC protocol
/// via the Quinn library. It manages a QUIC connection to a remote peer and
/// provides methods for sending and receiving data over that connection.
///
/// QUIC provides several benefits for secure multiparty computation:
/// - Built-in encryption and authentication
/// - Reliable, ordered delivery of data
/// - Stream multiplexing for concurrent operations
/// - Connection migration for network changes
pub struct QuicPeerConnection {
    /// The underlying QUIC connection
    connection: Connection,
    /// The remote peer's address
    remote_addr: SocketAddr,
    /// Map of stream IDs to send/receive stream pairs
    streams: Arc<Mutex<HashMap<u64, (quinn::SendStream, quinn::RecvStream)>>>,
    /// Whether this connection is on the server side
    is_server: bool,
}

impl QuicPeerConnection {
    /// Creates a new QUIC peer connection
    ///
    /// # Arguments
    /// * `connection` - The underlying QUIC connection
    /// * `is_server` - Whether this connection is on the server side
    ///
    /// The `is_server` parameter determines the behavior when creating new streams:
    /// - Server connections accept incoming streams
    /// - Client connections open new streams
    pub fn new(connection: Connection, is_server: bool) -> Self {
        let remote_addr = connection.remote_address();
        Self {
            connection,
            remote_addr,
            streams: Arc::new(Mutex::new(HashMap::new())),
            is_server,
        }
    }

    /// Gets or creates a bidirectional stream with the given ID
    ///
    /// This method manages the lifecycle of QUIC streams:
    /// 1. If a stream with the given ID already exists, it is reused
    /// 2. Otherwise, a new stream is created:
    ///    - For server connections, by accepting an incoming stream
    ///    - For client connections, by opening a new stream
    ///
    /// # Arguments
    /// * `stream_id` - The ID of the stream to get or create
    ///
    /// # Returns
    /// * `Ok((SendStream, RecvStream))` - The send and receive halves of the stream
    /// * `Err(String)` - If the stream could not be created
    async fn open_stream_for_send(&mut self, stream_id: u64) -> Result<(quinn::SendStream, quinn::RecvStream), String> {
        // Reuse cached stream if present
        if let Some((send, recv)) = self.streams.lock().await.remove(&stream_id) {
            return Ok((send, recv));
        }
        // Actively open a stream when sending
        let (send, recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|e| format!("Failed to open bidirectional stream: {}", e))?;
        Ok((send, recv))
    }

    async fn accept_stream_for_recv(&mut self, stream_id: u64) -> Result<(quinn::SendStream, quinn::RecvStream), String> {
        // Reuse cached stream if present
        if let Some((send, recv)) = self.streams.lock().await.remove(&stream_id) {
            return Ok((send, recv));
        }
        // Passively accept when receiving
        let (send, recv) = self
            .connection
            .accept_bi()
            .await
            .map_err(|e| format!("Failed to accept bidirectional stream: {}", e))?;
        Ok((send, recv))
    }
}

impl PeerConnection for QuicPeerConnection {
    fn send<'a>(
        &'a mut self,
        data: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move { self.send_on_stream(0, data).await })
    }

    fn receive<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
        Box::pin(async move { self.receive_from_stream(0).await })
    }

    fn send_on_stream<'a>(
        &'a mut self,
        stream_id: u64,
        data: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let (mut send, recv) = self.open_stream_for_send(stream_id).await?;

            send.write_all(data)
                .await
                .map_err(|e| format!("Failed to send data: {}", e))?;

            // Store the stream back for reuse
            let mut streams = self.streams.lock().await;
            streams.insert(stream_id, (send, recv));

            Ok(())
        })
    }

    fn receive_from_stream<'a>(
        &'a mut self,
        stream_id: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
        Box::pin(async move {
            let (send, mut recv) = self.accept_stream_for_recv(stream_id).await?;

            // Read a chunk of data (up to 65536 bytes)
            let mut buf = vec![0u8; 65536];
            match recv.read(&mut buf).await {
                Ok(Some(n)) => {
                    buf.truncate(n);

                    // Store the stream back for reuse
                    let mut streams = self.streams.lock().await;
                    streams.insert(stream_id, (send, recv));

                    Ok(buf)
                }
                Ok(None) => Err("Connection closed by peer".to_string()),
                Err(e) => Err(format!("Failed to receive data: {}", e)),
            }
        })
    }

    fn remote_address(&self) -> SocketAddr {
        self.remote_addr
    }

    fn close<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            self.connection.close(0u32.into(), b"Connection closed");
            Ok(())
        })
    }
}

/// In-memory loopback implementation of PeerConnection for self-delivery
pub struct LoopbackPeerConnection {
    remote_addr: SocketAddr,
    streams: Arc<Mutex<HashMap<u64, (mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>)>>> ,
}

impl LoopbackPeerConnection {
    pub fn new(remote_addr: SocketAddr) -> Self {
        Self {
            remote_addr,
            streams: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn ensure_stream(&self, stream_id: u64) -> (mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>) {
        let mut guard = self.streams.lock().await;
        if let Some((tx, rx)) = guard.remove(&stream_id) {
            (tx, rx)
        } else {
            let (tx, rx) = mpsc::channel::<Vec<u8>>(1024);
            (tx, rx)
        }
    }
}

impl PeerConnection for LoopbackPeerConnection {
    fn send<'a>(
        &'a mut self,
        data: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        self.send_on_stream(0, data)
    }

    fn receive<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
        self.receive_from_stream(0)
    }

    fn send_on_stream<'a>(
        &'a mut self,
        stream_id: u64,
        data: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let (tx, rx) = self.ensure_stream(stream_id).await;
            // put back for reuse
            {
                let mut guard = self.streams.lock().await;
                guard.insert(stream_id, (tx.clone(), rx));
            }
            tx.send(data.to_vec())
                .await
                .map_err(|e| format!("loopback send failed: {}", e))
                .map(|_| ())
        })
    }

    fn receive_from_stream<'a>(
        &'a mut self,
        stream_id: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
        Box::pin(async move {
            // ensure stream exists and reinsert for reuse
            let (tx, mut rx) = self.ensure_stream(stream_id).await;
            {
                let mut guard = self.streams.lock().await;
                guard.insert(stream_id, (tx, rx));
            }
            // now take receiver to await on
            let mut guard = self.streams.lock().await;
            if let Some((_tx, rx)) = guard.get_mut(&stream_id) {
                match rx.recv().await {
                    Some(msg) => Ok(msg),
                    None => Err("loopback connection closed".into()),
                }
            } else {
                Err("loopback stream missing".into())
            }
        })
    }

    fn remote_address(&self) -> SocketAddr { self.remote_addr }

    fn close<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move { Ok(()) })
    }
}

/// A node in the QUIC network
///
/// This struct represents a participant in the secure multiparty computation
/// network. It implements the Node trait from stoffelmpc-network.
#[derive(Debug, Clone)]
pub struct QuicNode {
    /// The UUID of this node
    uuid: Uuid,
    /// The network address of this node
    address: SocketAddr,
}

impl QuicNode {
    /// Creates a new node with a random UUID
    ///
    /// # Arguments
    /// * `address` - The network address of the node
    pub fn new_with_random_id(address: SocketAddr) -> Self {
        Self {
            uuid: Uuid::new_v4(),
            address,
        }
    }

    /// Creates a new node with a specific UUID
    ///
    /// # Arguments
    /// * `uuid` - The UUID of the node
    /// * `address` - The network address of the node
    pub fn new(uuid: Uuid, address: SocketAddr) -> Self {
        Self { uuid, address }
    }

    /// Creates a new node with a specific ID
    ///
    /// # Arguments
    /// * `id` - The ID of the node (will be converted to UUID)
    /// * `address` - The network address of the node
    pub fn from_party_id(id: PartyId, address: SocketAddr) -> Self {
        // Convert PartyId to u128 and then to UUID
        let uuid = Uuid::from_u128(id as u128);
        Self { uuid, address }
    }

    /// Returns the network address of this node
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// Returns the UUID of this node
    pub fn uuid(&self) -> Uuid {
        self.uuid
    }
}

impl Node for QuicNode {
    fn id(&self) -> PartyId {
        // Convert UUID to u128 and then to PartyId
        // This might lose precision if PartyId is smaller than u128
        self.uuid.as_u128() as PartyId
    }

    fn scalar_id<F: Field>(&self) -> F {
        // Convert UUID to u128 for use with Field
        F::from(self.uuid.as_u128())
    }
}

/// Configuration for the QUIC network
///
/// This struct contains configuration parameters for the QUIC network,
/// such as timeout values, retry settings, and other network-specific options.
#[derive(Debug, Clone)]
pub struct QuicNetworkConfig {
    /// Timeout for network operations in milliseconds
    pub timeout_ms: u64,
    /// Maximum number of retry attempts for network operations
    pub max_retries: u32,
    /// Whether to use secure connections (TLS)
    pub use_tls: bool,
}

impl Default for QuicNetworkConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 30000, // 30 seconds
            max_retries: 3,
            use_tls: true,
        }
    }
}

/// A message type for QUIC-based communication
///
/// This struct implements the Message trait from stoffelmpc-network,
/// providing a standard way to serialize and deserialize messages
/// for secure multiparty computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicMessage {
    /// The ID of the sender of this message
    sender_id: PartyId,
    /// The actual message content
    content: Vec<u8>,
}

impl QuicMessage {
    /// Creates a new message
    ///
    /// # Arguments
    /// * `sender_id` - The ID of the sender
    /// * `content` - The content of the message
    pub fn new(sender_id: PartyId, content: Vec<u8>) -> Self {
        Self { sender_id, content }
    }

    /// Returns the content of the message
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

/// QUIC-based implementation of NetworkManager
///
/// This struct implements the NetworkManager trait using the QUIC protocol
/// via the Quinn library. It manages QUIC endpoints for both client and server
/// roles, and provides methods for establishing connections and accepting
/// incoming connections.
///
/// The implementation uses self-signed certificates for TLS, which is suitable
/// for development but should be replaced with proper certificate management
/// in production.
#[derive(Debug, Clone)]
pub struct QuicNetworkManager {
    /// The QUIC endpoint for sending and receiving connections
    endpoint: Option<Endpoint>,
    /// Configuration for the server role
    server_config: Option<ServerConfig>,
    /// Configuration for the client role
    client_config: Option<ClientConfig>,
    /// The nodes in the network
    nodes: Vec<QuicNode>,
    /// The ID of this node in the network
    node_id: PartyId,
    /// Network configuration
    network_config: QuicNetworkConfig,
    /// Active connections to other server nodes (party connections)
    /// Using Arc<tokio::sync::Mutex<>> for interior mutability to allow modifying connections
    /// while keeping self immutable in Network trait methods
    connections: Arc<Mutex<HashMap<PartyId, Box<dyn PeerConnection>>>>,
    /// Active connections to clients (for async sending)
    client_connections_async: Arc<Mutex<HashMap<ClientId, Box<dyn PeerConnection>>>>,
    /// Set of connected client IDs (for sync queries)
    client_ids: Arc<StdMutex<HashSet<ClientId>>>,
}

impl Default for QuicNetworkManager {
    fn default() -> Self {
        Self::new()
    }
}

impl QuicNetworkManager {
    /// Creates a new QUIC network manager
    ///
    /// This initializes a network manager with no active endpoints or configurations.
    /// Before using the manager, you must call either `connect()` or `listen()`
    /// to set up the appropriate endpoint.
    pub fn new() -> Self {
        // Generate a random UUID for this node
        let node_id = Uuid::new_v4().as_u128() as PartyId;

        Self {
            endpoint: None,
            server_config: None,
            client_config: None,
            nodes: Vec::new(),
            node_id,
            network_config: QuicNetworkConfig::default(),
            connections: Arc::new(Mutex::new(HashMap::new())),
            client_connections_async: Arc::new(Mutex::new(HashMap::new())),
            client_ids: Arc::new(StdMutex::new(HashSet::new())),
        }
    }

    /// Creates a new QUIC network manager with the specified node ID
    ///
    /// # Arguments
    /// * `node_id` - The ID of this node in the network
    pub fn with_node_id(node_id: PartyId) -> Self {
        let mut manager = Self::new();
        manager.node_id = node_id;
        manager
    }

    /// Creates a new QUIC network manager with a random UUID-based node ID
    pub fn with_random_id() -> Self {
        Self::new() // new() already generates a random UUID-based ID
    }

    /// Creates a new QUIC network manager with the specified configuration
    ///
    /// # Arguments
    /// * `config` - The network configuration
    pub fn with_config(config: QuicNetworkConfig) -> Self {
        let mut manager = Self::new();
        manager.network_config = config;
        manager
    }

    /// Adds a node to the network
    ///
    /// # Arguments
    /// * `node` - The node to add
    pub fn add_node(&mut self, node: QuicNode) {
        self.nodes.push(node);
    }

    /// Adds a node with a random UUID to the network
    ///
    /// # Arguments
    /// * `address` - The network address of the node
    pub fn add_node_with_random_id(&mut self, address: SocketAddr) {
        let node = QuicNode::new_with_random_id(address);
        self.nodes.push(node);
    }

    /// Adds a node with a specific UUID to the network
    ///
    /// # Arguments
    /// * `uuid` - The UUID of the node
    /// * `address` - The network address of the node
    pub fn add_node_with_uuid(&mut self, uuid: Uuid, address: SocketAddr) {
        let node = QuicNode::new(uuid, address);
        self.nodes.push(node);
    }

    /// Adds a node with a specific party ID to the network
    ///
    /// # Arguments
    /// * `id` - The ID of the node
    /// * `address` - The network address of the node
    pub fn add_node_with_party_id(&mut self, id: PartyId, address: SocketAddr) {
        let node = QuicNode::from_party_id(id, address);
        self.nodes.push(node);
    }

    /// Creates an insecure client configuration for QUIC
    ///
    /// This method creates a client configuration that:
    /// 1. Skips server certificate verification (insecure, but useful for development)
    /// 2. Sets up ALPN protocols for protocol negotiation
    /// 3. Configures transport parameters
    ///
    /// # Warning
    /// This configuration is insecure and should only be used for development.
    /// In production, proper certificate verification should be implemented.
    ///
    /// # Returns
    /// * `Ok(ClientConfig)` - The client configuration
    /// * `Err(String)` - If the configuration could not be created
    fn create_insecure_client_config() -> Result<ClientConfig, String> {
        // Create a client crypto configuration that skips certificate verification
        let mut crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification::new()))
            .with_no_client_auth();

        // Set ALPN protocol to match the server
        crypto.alpn_protocols = vec![b"quic-example".to_vec()];

        // Create a QUIC client configuration with the crypto configuration
        let mut config = ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
                .map_err(|e| format!("Failed to create QUIC client config: {}", e))?,
        ));

        // Set transport config
        config.transport_config(Arc::new({
            let mut transport = quinn::TransportConfig::default();
            transport.max_concurrent_uni_streams(0u32.into());
            transport
        }));

        Ok(config)
    }

    /// Creates a self-signed server configuration for QUIC
    ///
    /// This method creates a server configuration that:
    /// 1. Generates a self-signed certificate for TLS
    /// 2. Sets up ALPN protocols for protocol negotiation
    /// 3. Configures transport parameters
    ///
    /// # Warning
    /// This configuration uses a self-signed certificate, which is suitable for
    /// development but not for production. In production, proper certificates
    /// should be used.
    ///
    /// # Returns
    /// * `Ok(ServerConfig)` - The server configuration
    /// * `Err(String)` - If the configuration could not be created
    fn create_self_signed_server_config() -> Result<ServerConfig, String> {
        // Generate self-signed certificate
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .map_err(|e| format!("Failed to generate certificate: {}", e))?;

        // Convert the certificate and key to DER format
        let cert_der = CertificateDer::from(cert.cert.der().to_vec());
        let key_der = PrivateKeyDer::Pkcs8(
            PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())
        );

        // Create a server crypto configuration with the certificate
        let mut server_crypto = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .map_err(|e| format!("Failed to create server crypto config: {}", e))?;

        // Set ALPN protocol
        server_crypto.alpn_protocols = vec![b"quic-example".to_vec()];

        // Create a QUIC server configuration with the crypto configuration
        let mut server_config = ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
                .map_err(|e| format!("Failed to create QUIC server config: {}", e))?,
        ));

        // Configure transport parameters
        let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
        transport_config.max_concurrent_uni_streams(0u32.into());

        Ok(server_config)
    }
    /// Ensure a loopback connection is present for self-delivery
    pub async fn ensure_loopback_installed(&self) {
        let mut conns = self.connections.lock().await;
        if !conns.contains_key(&self.node_id) {
            let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
            conns.insert(self.node_id, Box::new(LoopbackPeerConnection::new(addr)));
        }
    }
}

impl NetworkManager for QuicNetworkManager {
    fn connect<'a>(
        &'a mut self,
        address: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Result<Box<dyn PeerConnection>, String>> + Send + 'a>> {
        Box::pin(async move {
            if self.endpoint.is_none() {
                // Create client endpoint
                let client_config = Self::create_insecure_client_config()?;
                let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())
                    .map_err(|e| format!("Failed to create client endpoint: {}", e))?;
                endpoint.set_default_client_config(client_config);
                self.endpoint = Some(endpoint);
            } else {
                // Ensure an existing endpoint (possibly created by listen()) has a default client config
                let client_config = Self::create_insecure_client_config()?;
                if let Some(endpoint) = self.endpoint.as_mut() {
                    endpoint.set_default_client_config(client_config);
                }
            }

            // Ensure loopback connection exists for self-delivery
            self.ensure_loopback_installed().await;

            let endpoint = self.endpoint.as_ref().unwrap();
            let connection = endpoint
                .connect(address, "localhost")
                .map_err(|e| format!("Failed to initiate connection: {}", e))?
                .await
                .map_err(|e| format!("Failed to establish connection: {}", e))?;

            // Send identification handshake as SERVER with our node_id
            if let Ok((mut send, _recv)) = connection.open_bi().await {
                let handshake = format!("ROLE:SERVER:{}\n", self.node_id);
                let _ = send.write_all(handshake.as_bytes()).await;
            }

            // Find the node ID for this address or generate a new one
            let node_id = self.nodes.iter()
                .find(|node| node.address() == address)
                .map(|node| node.id())
                .unwrap_or_else(|| {
                    // If we don't have a node for this address, create one
                    let node = QuicNode::new_with_random_id(address);
                    let id = node.id();
                    self.nodes.push(node);
                    id
                });

            // Store a clone of the connection in the connections hashmap
            let mut connections = self.connections.lock().await;
            connections.insert(node_id, Box::new(QuicPeerConnection::new(connection.clone(), false)));

            // Return the original connection
            Ok(Box::new(QuicPeerConnection::new(connection, false)) as Box<dyn PeerConnection>)
        })
    }

    fn accept<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Box<dyn PeerConnection>, String>> + Send + 'a>> {
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

            // Get the remote address of the connection
            let remote_addr = connection.remote_address();

            // Try to read a role identification handshake from the first bi-directional stream
            let mut parsed_role: Option<(String, usize)> = None;
            if let Ok((mut _send, mut recv)) = connection.accept_bi().await {
                let mut buf = vec![0u8; 256];
                if let Ok(Some(n)) = recv.read(&mut buf).await {
                    let line = String::from_utf8_lossy(&buf[..n]).lines().next().unwrap_or("").to_string();
                    if let Some(rest) = line.strip_prefix("ROLE:") {
                        let mut parts = rest.split(':');
                        if let (Some(role), Some(id_str)) = (parts.next(), parts.next()) {
                            if let Ok(id) = id_str.trim().parse::<usize>() {
                                parsed_role = Some((role.to_string(), id));
                            }
                        }
                    }
                }
            }

            match parsed_role {
                Some((role, id)) if role.eq_ignore_ascii_case("CLIENT") => {
                    // Store as client connection
                    {
                        let mut cc = self.client_connections_async.lock().await;
                        cc.insert(id, Box::new(QuicPeerConnection::new(connection.clone(), true)));
                    }
                    if let Ok(mut set) = self.client_ids.lock() { set.insert(id); }

                    // Return the original connection
                    Ok(Box::new(QuicPeerConnection::new(connection, true)) as Box<dyn PeerConnection>)
                }
                Some((role, id)) if role.eq_ignore_ascii_case("SERVER") => {
                    // Ensure the nodes list includes this server party
                    if !self.nodes.iter().any(|n| n.id() == id) {
                        self.nodes.push(QuicNode::from_party_id(id, remote_addr));
                    }

                    // Store connection in server connections map
                    let mut connections = self.connections.lock().await;
                    connections.insert(id, Box::new(QuicPeerConnection::new(connection.clone(), true)));

                    // Return the original connection
                    Ok(Box::new(QuicPeerConnection::new(connection, true)) as Box<dyn PeerConnection>)
                }
                _ => {
                    // Fallback: use address-based mapping as before
                    let node_id = self.nodes.iter()
                        .find(|node| node.address() == remote_addr)
                        .map(|node| node.id())
                        .unwrap_or_else(|| {
                            let node = QuicNode::new_with_random_id(remote_addr);
                            let id = node.id();
                            self.nodes.push(node);
                            id
                        });

                    let mut connections = self.connections.lock().await;
                    connections.insert(node_id, Box::new(QuicPeerConnection::new(connection.clone(), true)));

                    Ok(Box::new(QuicPeerConnection::new(connection, true)) as Box<dyn PeerConnection>)
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

            // Also configure default client config so this endpoint can initiate outbound connections
            let client_config = Self::create_insecure_client_config()?;
            endpoint.set_default_client_config(client_config);

            self.endpoint = Some(endpoint);

            // Ensure loopback connection exists for self-delivery
            self.ensure_loopback_installed().await;
            Ok(())
        })
    }
}

/// Implementation of the Network trait for QuicNetworkManager
///
/// This implementation uses the QUIC protocol for communication between nodes.
#[async_trait]
impl Network for QuicNetworkManager {
    type NodeType = QuicNode;
    type NetworkConfig = QuicNetworkConfig;

    async fn send(&self, recipient: PartyId, message: &[u8]) -> Result<usize, NetworkError> {
        // Acquire the lock on the connections hashmap
        let mut connections = self.connections.lock().await;

        // Check if the connection exists
        if !connections.contains_key(&recipient) {
            return Err(NetworkError::PartyNotFound(recipient));
        }

        // Get a mutable reference to the connection
        let connection = connections.get_mut(&recipient).unwrap();

        // Send the message
        match connection.send(message).await {
            Ok(_) => {
                println!("Successfully sent message to recipient {}", recipient);
                Ok(message.len())
            },
            Err(e) => {
                println!("Failed to send message to recipient {}: {}", recipient, e);
                Err(NetworkError::SendError)
            }
        }
    }


    async fn broadcast(&self, message: &[u8]) -> Result<usize, NetworkError> {
        // Acquire the lock on the connections hashmap
        let mut connections = self.connections.lock().await;
        let mut total_bytes = 0usize;
        let mut included_self = false;

        // Send the message to all known nodes (including self if present)
        for node in &self.nodes {
            if let Some(connection) = connections.get_mut(&node.id()) {
                match connection.send(message).await {
                    Ok(_) => {
                        println!("Successfully broadcasted message to node {}", node.id());
                        total_bytes += message.len();
                        if node.id() == self.node_id { included_self = true; }
                    },
                    Err(e) => {
                        println!("Failed to broadcast message to node {}: {}", node.id(), e);
                        // Continue with other nodes even if one fails
                    }
                }
            } else {
                // Log a warning that we couldn't send the message to this node
                println!("Warning: No connection to node {}, skipping broadcast", node.id());
            }
        }

        // Ensure self-delivery via loopback even if self is not listed in nodes
        if !included_self {
            if let Some(connection) = connections.get_mut(&self.node_id) {
                if let Ok(_) = connection.send(message).await {
                    println!("Successfully broadcasted message to self (loopback)");
                    total_bytes += message.len();
                }
            }
        }

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
        // Acquire the lock on client connections
        let mut connections = self.client_connections_async.lock().await;
        if let Some(conn) = connections.get_mut(&client) {
            match conn.send(message).await {
                Ok(_) => Ok(message.len()),
                Err(_) => Err(NetworkError::SendError),
            }
        } else {
            Err(NetworkError::ClientNotFound(client))
        }
    }

    fn clients(&self) -> Vec<ClientId> {
        match self.client_ids.lock() {
            Ok(guard) => guard.iter().cloned().collect(),
            Err(_) => Vec::new(),
        }
    }

    fn is_client_connected(&self, client: ClientId) -> bool {
        match self.client_ids.lock() {
            Ok(guard) => guard.contains(&client),
            Err(_) => false,
        }
    }
}

/// Certificate verifier that accepts any server certificate
///
/// This is a dummy implementation of the ServerCertVerifier trait that
/// accepts any server certificate without verification. It is used for
/// development and testing purposes only.
///
/// # Security Warning
///
/// This implementation is **extremely insecure** and vulnerable to
/// man-in-the-middle attacks. It should never be used in production.
/// In a production environment, proper certificate verification should
/// be implemented, typically using a trusted certificate authority.
#[derive(Debug)]
struct SkipServerVerification;

impl SkipServerVerification {
    /// Creates a new SkipServerVerification instance
    ///
    /// This is a simple constructor that returns a new instance of
    /// the SkipServerVerification struct.
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
