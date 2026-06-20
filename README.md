# stoffel-networking

`stoffel-networking` (crate name: `stoffelnet`) is a QUIC-based peer-to-peer networking library for Stoffel MPC applications. It provides transport-agnostic traits and a concrete QUIC/TLS transport for MPC party-to-party networking, external client connections, and optional ICE/STUN NAT traversal.

## Features

- QUIC transport built on `quinn`, with persistent bidirectional streams.
- TLS-enabled peer connections with generated or caller-supplied certificate material.
- Transport-agnostic traits: `PeerConnection`, `NetworkManager`, `Network`, `Message`, and `Node`.
- Role-aware connection setup for MPC parties and external clients.
- Loopback self-delivery for messages addressed to the local party.
- Concurrent connection maps backed by `DashMap`.
- Length-prefixed framing with a 4-byte big-endian length prefix and a 1 GiB maximum frame size.
- Incremental receive buffering: payload memory grows as bytes arrive instead of pre-allocating the declared frame length.
- Optional ICE (RFC 8445), STUN (RFC 5389), and coordinated UDP hole punching helpers for NAT traversal.
- C-compatible FFI bindings for Python, Go, C, and other language integrations.

## Installation

For the 0.1.0 release:

```toml
[dependencies]
stoffelnet = "0.1.0"
```

To depend on this repository directly:

```toml
[dependencies]
stoffelnet = { git = "https://github.com/Stoffel-Labs/stoffel-networking.git" }
```

## Quick start: low-level peer connections

`NetworkManager` is the low-level connection lifecycle trait. A manager must listen before it can accept incoming connections, and a peer must be listening before another manager can connect to it.

```rust,no_run
use std::net::SocketAddr;
use stoffelnet::{NetworkManager, PeerConnection};
use stoffelnet::transports::quic::QuicNetworkManager;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut manager = QuicNetworkManager::new();

    let bind_addr: SocketAddr = "127.0.0.1:9000".parse()?;
    manager.listen(bind_addr).await?;

    // In a real deployment this address belongs to another listening party.
    let peer_addr: SocketAddr = "127.0.0.1:9001".parse()?;
    let mut connection = manager.connect(peer_addr).await?;

    connection.send(b"hello from stoffelnet").await?;
    let response = connection.receive().await?;
    println!("received {} bytes", response.len());

    Ok(())
}
```

## High-level MPC network API

`QuicNetworkManager` also implements `stoffelnet::network_utils::Network`, the high-level API used by MPC protocols for party sends, broadcasts, and client delivery.

```rust,no_run
use stoffelnet::network_utils::Network;
use stoffelnet::transports::quic::{QuicNetworkConfig, QuicNetworkManager};

async fn send_messages(manager: &QuicNetworkManager) -> Result<(), Box<dyn std::error::Error>> {
    let direct_bytes = manager.send(1, b"message for party 1").await?;
    let broadcast_bytes = manager.broadcast(b"message for all connected parties").await?;

    println!("sent {direct_bytes} bytes directly and {broadcast_bytes} bytes via broadcast");
    Ok(())
}

fn configure_expected_network() -> QuicNetworkManager {
    let config = QuicNetworkConfig {
        expected_parties: Some(3),
        expected_clients: Some(1),
        ..Default::default()
    };

    QuicNetworkManager::with_config(config)
}
```

When `expected_parties` or `expected_clients` is configured, send paths are transparently gated until the configured connection/readiness consensus completes.

## Configuration

`QuicNetworkConfig` controls connection timeouts, TLS behavior, NAT traversal, and optional readiness consensus.

| Field | Default | Description |
| --- | --- | --- |
| `timeout_ms` | `30000` | Connection and stream setup timeout in milliseconds |
| `idle_timeout_ms` | `300000` | QUIC idle timeout in milliseconds |
| `max_retries` | `3` | Maximum connection retry attempts |
| `use_tls` | `true` | Enable TLS and peer certificate handling |
| `enable_nat_traversal` | `false` | Enable ICE/STUN NAT traversal helpers |
| `stun_servers` | `[]` | STUN server socket addresses for reflexive address discovery |
| `enable_hole_punching` | `true` | Enable coordinated UDP hole punching when NAT traversal is used |
| `hole_punch_timeout_ms` | `10000` | Hole-punching timeout in milliseconds |
| `ice_config` | `IceAgentConfig::default()` | ICE connectivity-check settings |
| `expected_parties` | `None` | Optional number of MPC parties required before send/broadcast proceeds |
| `expected_clients` | `None` | Optional number of clients required before send-to-client proceeds |
| `consensus_timeout_ms` | `60000` | Readiness/ordering consensus timeout in milliseconds |

### NAT traversal

STUN servers must be supplied as resolved `SocketAddr` values; DNS hostnames are not accepted by the config type.

```rust,no_run
use std::net::SocketAddr;
use stoffelnet::transports::quic::{QuicNetworkConfig, QuicNetworkManager};

let stun_server: SocketAddr = "74.125.250.129:19302".parse().unwrap();
let config = QuicNetworkConfig::with_nat_traversal().stun_servers(vec![stun_server]);
let manager = QuicNetworkManager::with_config(config);
```

### Stable transport identity

By default, a manager generates ephemeral self-signed certificate material on first use. Runtimes that need stable authenticated transport identities can install certificate/key DER before `listen` or `connect` with `set_local_certificate_der`.

Certificate public-key allowlisting is available through `set_allowed_certificate_public_keys`, `add_allowed_certificate_public_key`, and `clear_allowed_certificate_public_keys`.

## Architecture

### Core traits

| Trait | Purpose |
| --- | --- |
| `PeerConnection` | Point-to-point peer communication: send, receive, stream-specific send/receive, remote address, remote party ID, and close |
| `NetworkManager` | Connection lifecycle: connect, accept, and listen |
| `Network` | High-level party/client messaging for MPC protocols |
| `Message` | Serializable protocol message with sender identification |
| `Node` | Network participant identifier abstraction |

### Main implementation types

| Type | Module | Purpose |
| --- | --- | --- |
| `QuicNetworkManager` | `stoffelnet::transports::quic` | Main QUIC coordinator implementing `NetworkManager` and `Network` |
| `QuicPeerConnection` | `stoffelnet::transports::quic` | QUIC connection wrapper with persistent streams |
| `LoopbackPeerConnection` | `stoffelnet::transports::quic` | In-memory self-delivery connection |
| `QuicNode` | `stoffelnet::transports::quic` | MPC party node with UUID-derived or explicit party ID |
| `NetEnvelope` | `stoffelnet::transports::net_envelope` | Wire message wrapper for handshakes, MPC messages, consensus messages, and NAT traversal signaling |
| `IceCandidate` | `stoffelnet::transports::ice` | ICE candidate representation and priority metadata |
| `IceAgent` | `stoffelnet::transports::ice_agent` | ICE state machine for candidate gathering, exchange, and checks |
| `StunClient` | `stoffelnet::transports::stun` | STUN binding client for reflexive address discovery |

### Module structure

```text
stoffelnet
├── ffi                 # C FFI bindings
├── network_utils       # PartyId, ClientId, Network, Message, Node, consensus types
└── transports
    ├── quic           # QUIC transport implementation
    ├── net_envelope   # Wire protocol message wrapper
    ├── ice            # ICE candidates and candidate pairs
    ├── ice_agent      # ICE agent and hole punching coordinator
    └── stun           # STUN client
```

## Wire protocol

Messages are length-prefixed:

```text
┌──────────────────┬─────────────────────────┐
│ Length (4 bytes) │ Payload (N bytes)       │
│ Big-endian u32   │ bincode NetEnvelope     │
└──────────────────┴─────────────────────────┘
```

The receiver validates declared lengths against the 1 GiB frame limit and reads payloads in 64 KiB chunks, so a malicious length prefix cannot force a large up-front allocation.

`NetEnvelope` carries:

- connection handshakes
- MPC payloads (`HoneyBadger(Vec<u8>)`)
- node/client list consensus messages
- ICE candidate exchange messages
- UDP hole-punch coordination messages
- connectivity checks
- relay request/offer/data messages
- heartbeats

## FFI

The crate builds both Rust and C-compatible artifacts:

```toml
[lib]
crate-type = ["rlib", "cdylib"]
```

The public C header is maintained at `include/stoffelnet.h`. The FFI exposes runtime management, node management, network-manager lifecycle, connection send/receive, async callbacks, expected party/client configuration, certificate public-key allowlisting, verified ordering accessors, and thread-local error reporting.

## Development

Common validation commands:

```bash
cargo fmt --check
cargo check
cargo test --doc
cargo clippy --all-targets -- -D warnings
cargo test
cargo package --allow-dirty
```

Manual NAT simulation helpers live under `tests/nat_simulation/`.

## License

Apache-2.0. See `LICENSE` for details.
