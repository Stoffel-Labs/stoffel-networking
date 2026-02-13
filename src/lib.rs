//! # stoffelnet - QUIC-Based P2P Networking for MPC
//!
//! `stoffelnet` is a peer-to-peer networking library designed for secure Multi-Party
//! Computation (MPC) applications. It provides a transport-agnostic abstraction layer
//! with a concrete QUIC implementation, NAT traversal capabilities via ICE/STUN, and
//! actor model compatibility for safe concurrent access.
//!
//! ## Features
//!
//! - **QUIC Transport**: High-performance, encrypted connections using the QUIC protocol
//! - **NAT Traversal**: ICE (RFC 8445) and STUN (RFC 5389) support for peer-to-peer
//!   connectivity through NATs
//! - **Actor Model Compatible**: All connection types use interior mutability (`Arc<Mutex<>>`)
//!   for safe sharing across async tasks
//! - **Transport Agnostic**: Core traits ([`PeerConnection`], [`NetworkManager`]) allow
//!   alternative transport implementations
//! - **FFI Bindings**: C-compatible API for Python, Go, and other language integrations
//!
//! ## Quick Start
//!
//! ```no_run
//! use stoffelnet::transports::quic::{QuicNetworkManager, QuicNetworkConfig, NetworkManager};
//! use std::net::SocketAddr;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create a network manager with default configuration
//!     let mut manager = QuicNetworkManager::new();
//!
//!     // Start listening for incoming connections
//!     let bind_addr: SocketAddr = "127.0.0.1:5000".parse()?;
//!     manager.listen(bind_addr).await?;
//!
//!     // Connect to a peer
//!     let peer_addr: SocketAddr = "127.0.0.1:5001".parse()?;
//!     let connection = manager.connect(peer_addr).await?;
//!
//!     // Send and receive data
//!     connection.send(b"Hello, peer!").await?;
//!     let response = connection.receive().await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Module Structure
//!
//! - [`transports`]: Transport implementations and utilities
//!   - [`transports::quic`]: QUIC-based networking ([`QuicNetworkManager`], [`QuicPeerConnection`])
//!   - [`transports::ice`]: ICE candidate types and pair formation
//!   - [`transports::ice_agent`]: ICE state machine for NAT traversal
//!   - [`transports::stun`]: STUN client for reflexive address discovery
//!   - [`transports::net_envelope`]: Wire protocol message format
//! - [`network_utils`]: Core types and traits ([`Network`], [`Node`], [`PartyId`])
//! - [`ffi`]: C Foreign Function Interface for cross-language bindings
//!
//! ## NAT Traversal
//!
//! For peer-to-peer connectivity through NAT, enable NAT traversal features:
//!
//! ```no_run
//! use stoffelnet::transports::quic::{QuicNetworkManager, QuicNetworkConfig};
//! use std::net::SocketAddr;
//!
//! // Configure with STUN servers (use resolved IP addresses)
//! let stun_server: SocketAddr = "74.125.250.129:19302".parse().unwrap();
//! let config = QuicNetworkConfig {
//!     enable_nat_traversal: true,
//!     stun_servers: vec![stun_server],
//!     ..Default::default()
//! };
//!
//! let manager = QuicNetworkManager::with_config(config);
//! ```
//!
//! ## Key Types
//!
//! - [`PeerConnection`]: Trait for point-to-point peer communication
//! - [`NetworkManager`]: Trait for connection lifecycle management
//! - [`network_utils::Network`]: High-level network abstraction for MPC protocols
//! - [`transports::quic::QuicNetworkManager`]: QUIC implementation of network management
//! - [`transports::ice_agent::IceAgent`]: ICE state machine for NAT traversal
//!
//! [`transports::quic::QuicNetworkManager`]: transports::quic::QuicNetworkManager
//! [`transports::quic::QuicPeerConnection`]: transports::quic::QuicPeerConnection
//! [`network_utils::Network`]: network_utils::Network
//! [`network_utils::PartyId`]: network_utils::PartyId
//! [`transports::ice_agent::IceAgent`]: transports::ice_agent::IceAgent

pub mod ffi;
pub mod network_utils;
pub mod transports;

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

/// Represents a connection to a peer.
///
/// This trait defines the interface for communicating with a remote peer.
/// It provides methods for sending and receiving data, managing streams,
/// and controlling the connection lifecycle.
///
/// The interface is transport-agnostic, allowing different implementations
/// to use different underlying protocols (e.g., QUIC, WebRTC, etc.).
///
/// # Implementation Notes
///
/// Implementations should use interior mutability (e.g., `Arc<Mutex<>>`) to allow
/// safe sharing across async tasks. The QUIC implementation
/// ([`transports::quic::QuicPeerConnection`]) follows this pattern.
///
/// [`transports::quic::QuicPeerConnection`]: transports::quic::QuicPeerConnection
pub trait PeerConnection: Send + Sync {
    /// Sends data to the peer on the default stream.
    ///
    /// This is a convenience method that sends data on stream ID 0.
    /// For more control, use `send_on_stream`.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to send
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The connection is closed, closing, or disconnected
    /// - The message exceeds the maximum size (100MB for QUIC)
    /// - A network error occurs during transmission
    /// - The peer resets the stream
    fn send<'a>(
        &'a mut self,
        data: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

    /// Receives data from the peer on the default stream.
    ///
    /// This is a convenience method that receives data from stream ID 0.
    /// For more control, use `receive_from_stream`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The connection is closed or disconnected
    /// - The stream is closed by the peer
    /// - A network error occurs during reception
    /// - The received message exceeds the maximum size
    fn receive<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>>;

    /// Sends data on a specific stream.
    ///
    /// This method allows sending data on a specific stream ID, enabling
    /// multiplexed communication with the peer.
    ///
    /// # Arguments
    ///
    /// * `stream_id` - The ID of the stream to send on
    /// * `data` - The data to send
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The connection is closed, closing, or disconnected
    /// - The specified stream does not exist or is closed
    /// - The message exceeds the maximum size
    /// - A network error occurs during transmission
    fn send_on_stream<'a>(
        &'a mut self,
        stream_id: u64,
        data: &'a [u8],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

    /// Receives data from a specific stream.
    ///
    /// This method allows receiving data from a specific stream ID, enabling
    /// multiplexed communication with the peer.
    ///
    /// # Arguments
    ///
    /// * `stream_id` - The ID of the stream to receive from
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The connection is closed or disconnected
    /// - The specified stream does not exist or is closed
    /// - A network error occurs during reception
    fn receive_from_stream<'a>(
        &'a mut self,
        stream_id: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>>;

    /// Returns the address of the remote peer.
    ///
    /// This method provides the network address of the connected peer,
    /// which can be useful for logging, debugging, or identity verification.
    fn remote_address(&self) -> SocketAddr;

    /// Returns the party ID of the remote peer.
    ///
    /// The party ID identifies which party (0..N-1) this connection leads to.
    /// Returns `None` if the party ID has not been assigned yet.
    fn remote_party_id(&self) -> Option<usize>;

    /// Closes the connection gracefully.
    ///
    /// This method terminates the connection with the peer. After calling this
    /// method, no more data can be sent or received.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection could not be closed cleanly.
    /// Note that even if an error is returned, the connection should be
    /// considered unusable.
    fn close<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}

/// Manages network connections.
///
/// This trait defines the interface for managing network connections.
/// It provides methods for establishing connections to peers, accepting incoming
/// connections, and listening for connection requests.
///
/// The NetworkManager is responsible for:
/// - Creating and configuring network endpoints
/// - Establishing outgoing connections
/// - Accepting incoming connections
/// - Managing connection lifecycle
///
/// Like the [`PeerConnection`] trait, this interface is transport-agnostic,
/// allowing different implementations to use different underlying protocols.
///
/// # Implementation
///
/// The primary implementation is [`transports::quic::QuicNetworkManager`], which
/// uses QUIC over TLS for secure, multiplexed connections.
///
/// [`transports::quic::QuicNetworkManager`]: transports::quic::QuicNetworkManager
pub trait NetworkManager: Send + Sync {
    /// Establishes a connection to a new peer.
    ///
    /// This method initiates an outgoing connection to a peer at the specified address.
    /// It handles the connection establishment process, including any necessary
    /// handshaking, encryption setup, and protocol negotiation.
    ///
    /// # Arguments
    ///
    /// * `address` - The network address of the peer to connect to
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The endpoint has not been initialized (call [`listen`](Self::listen) first)
    /// - The peer is unreachable or refuses the connection
    /// - TLS handshake fails (certificate validation, protocol mismatch)
    /// - Connection timeout is exceeded
    /// - Stream initialization fails
    fn connect<'a>(
        &'a mut self,
        address: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Result<Box<dyn PeerConnection>, String>> + Send + 'a>>;

    /// Accepts an incoming connection.
    ///
    /// This method accepts a pending incoming connection from a peer.
    /// It should be called after [`listen`](Self::listen) has been called to set up
    /// the listening endpoint.
    ///
    /// This method will block (await) until a connection is available or an error occurs.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The endpoint is not listening (call [`listen`](Self::listen) first)
    /// - The endpoint is closed
    /// - TLS handshake with the connecting peer fails
    /// - Stream initialization fails
    fn accept<'a>(
        &'a mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Box<dyn PeerConnection>, String>> + Send + 'a>>;

    /// Listens for incoming connections.
    ///
    /// This method sets up a network endpoint to listen for incoming connections
    /// at the specified address. After calling this method, [`accept`](Self::accept)
    /// can be called to accept incoming connections.
    ///
    /// # Arguments
    ///
    /// * `bind_address` - The local address to bind to for listening
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The address is already in use
    /// - The address cannot be bound (permission denied, invalid interface)
    /// - TLS certificate generation fails
    /// - The endpoint could not be created
    fn listen<'a>(
        &'a mut self,
        bind_address: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}
