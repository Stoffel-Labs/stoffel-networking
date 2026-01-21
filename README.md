# stoffel-networking

A peer-to-peer networking library for the Stoffel MPC framework, built on QUIC with TLS support.

## Overview

`stoffel-networking` (crate name: `stoffelnet`) provides transport-agnostic networking abstractions and a concrete QUIC-based implementation for secure communication between MPC participants. The library is designed for actor-model compatibility and supports both party-to-party (server-to-server) and client-to-server communication patterns.

## Features

- **QUIC Transport**: Built on the `quinn` library with persistent bidirectional streams
- **TLS Security**: Self-signed certificates for development, configurable for production
- **Actor Model Compatible**: Uses `Arc<Mutex<>>` for safe sharing across async tasks
- **Transport Agnostic**: Trait-based design allows alternative transport implementations
- **Role-Based Handshaking**: Distinguishes between CLIENT and SERVER roles
- **Self-Delivery**: Efficient loopback connections for messages to self
- **Concurrent Design**: Lock-free connection storage using `DashMap`
- **Length-Prefixed Framing**: 4-byte big-endian message framing (max 100MB)

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
stoffelnet = { git = "https://github.com/Stoffel-Labs/stoffel-networking.git" }
```

## Usage

### Basic Network Manager Setup

```rust
use stoffelnet::transports::quic::{QuicNetworkManager, QuicNetworkConfig, QuicNode};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Define network nodes
    let nodes = vec![
        QuicNode::new(0, "127.0.0.1:9000".parse()?),
        QuicNode::new(1, "127.0.0.1:9001".parse()?),
        QuicNode::new(2, "127.0.0.1:9002".parse()?),
    ];

    // Configure the network
    let config = QuicNetworkConfig {
        timeout_ms: 30000,
        max_retries: 3,
        use_tls: true,
    };

    // Create network manager for party 0
    let my_party_id = 0;
    let manager = QuicNetworkManager::new(my_party_id, nodes.clone(), config).await?;

    // Start listening for connections
    manager.start_listening().await?;

    Ok(())
}
```

### Sending Messages Between Parties

```rust
use stoffelnet::network_utils::Network;

// Send to a specific party
let message = b"Hello, party 1!";
manager.send(1, message).await?;

// Broadcast to all parties
manager.broadcast(message).await?;

// Receive a message
let (sender_id, data) = manager.receive().await?;
println!("Received from party {}: {:?}", sender_id, data);
```

### Client-Server Communication

```rust
use stoffelnet::network_utils::ClientType;

// Server: accept client connections
let (client_id, initial_message) = manager.receive_from_client().await?;

// Server: send to specific client
manager.send_to_client(client_id, b"Welcome!").await?;

// Client: connect to server
manager.connect_as_client(server_address, ClientType::Client).await?;
```

### Low-Level Peer Connection

```rust
use stoffelnet::PeerConnection;

// Get a connection to a specific party
let connection = manager.get_connection(party_id)?;

// Send raw data
connection.send(b"raw bytes").await?;

// Receive raw data
let data = connection.receive().await?;

// Use specific streams
connection.send_on_stream(stream_id, b"data").await?;
let data = connection.receive_from_stream(stream_id).await?;

// Check connection health
let addr = connection.remote_address().await?;
```

## Architecture

### Core Traits

| Trait | Purpose |
|-------|---------|
| `PeerConnection` | Interface for communicating with a single peer |
| `NetworkManager` | Interface for managing multiple connections |
| `Network` | High-level party-to-party and client-to-server communication |
| `Message` | Serializable protocol message with sender identification |
| `Node` | Represents a network participant |

### Key Types

| Type | Description |
|------|-------------|
| `QuicNetworkManager` | Full QUIC implementation of `NetworkManager` + `Network` |
| `QuicPeerConnection` | QUIC connection wrapper with persistent streams |
| `LoopbackPeerConnection` | In-memory self-delivery using channels |
| `QuicNode` | Network participant with UUID and address |
| `QuicNetworkConfig` | Configuration for timeouts, retries, and TLS |
| `NetEnvelope` | Message wrapper for handshakes and protocol data |

### Connection State Machine

```
Connected ─────► Closing ─────► Closed
    │
    └──────────► Disconnected (unexpected)
```

### Module Structure

```
stoffelnet
├── lib.rs              # Transport-agnostic traits (PeerConnection, NetworkManager)
├── network_utils/      # Core types and Network trait
│   └── mod.rs          # PartyId, ClientId, Message, Network, Node
└── transports/
    ├── mod.rs          # Module re-exports
    ├── net_envelope.rs # Wire format for messages
    └── quic.rs         # QUIC implementation
```

## Configuration

### QuicNetworkConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `timeout_ms` | `u64` | `30000` | Operation timeout in milliseconds |
| `max_retries` | `u32` | `3` | Number of retry attempts |
| `use_tls` | `bool` | `true` | Enable TLS encryption |

## Error Handling

### NetworkError

```rust
pub enum NetworkError {
    SendError,
    Timeout,
    PartyNotFound(PartyId),
    ClientNotFound(ClientId),
}
```

### ConnectionError

```rust
pub enum ConnectionError {
    StreamClosed,
    ConnectionLost(String),
    SendFailed(String),
    ReceiveFailed(String),
    FramingError(String),
    InitializationFailed(String),
    InvalidState(ConnectionState),
}
```

## Wire Protocol

### Message Framing

All messages use length-prefixed framing:

```
┌──────────────────┬─────────────────────────┐
│ Length (4 bytes) │ Payload (N bytes)       │
│ Big-endian u32   │ Serialized NetEnvelope  │
└──────────────────┴─────────────────────────┘
```

### NetEnvelope Format

```rust
pub enum NetEnvelope {
    Handshake { role: String, id: usize },  // Connection negotiation
    HoneyBadger(Vec<u8>),                   // Protocol messages
}
```

## Integration with Stoffel

This library is used by the `mpc-protocols` crate to provide networking for MPC execution:

```
Stoffel CLI
    │
    ▼
mpc-protocols ──────► stoffel-networking
    │                       │
    ▼                       ▼
StoffelVM              QUIC/TLS
```

## Dependencies

Key dependencies:
- `quinn` - QUIC protocol implementation
- `rustls` - TLS cryptography
- `tokio` - Async runtime
- `dashmap` - Concurrent hash maps
- `serde` / `bincode` - Serialization

## License

See the repository license file for details.
