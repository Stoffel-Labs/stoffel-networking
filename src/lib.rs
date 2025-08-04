pub mod transports;
pub mod network_utils;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

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
