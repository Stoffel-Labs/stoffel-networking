# CLAUDE.md

This file provides guidance to Claude Code when working with the stoffel-networking repository.

## Repository Overview

`stoffel-networking` is a QUIC-based peer-to-peer networking library for the Stoffel MPC framework. It provides transport-agnostic abstractions and concrete implementations for secure communication between MPC participants.

**Crate name:** `stoffelnet`
**Lines of code:** ~1,800
**Primary consumer:** `mpc-protocols` crate

## Development Commands

```bash
# Build
cargo build
cargo build --release

# Check for errors without building
cargo check

# Run tests (none currently exist)
cargo test

# Format and lint
cargo fmt
cargo clippy

# Generate documentation
cargo doc --open
```

## Repository Structure

```
stoffel-networking/
├── Cargo.toml
├── README.md
├── CLAUDE.md
└── src/
    ├── lib.rs                    # Transport-agnostic traits
    ├── network_utils/
    │   └── mod.rs                # Core types: PartyId, Network trait, etc.
    └── transports/
        ├── mod.rs                # Module re-exports
        ├── net_envelope.rs       # Wire protocol message wrapper
        └── quic.rs               # QUIC implementation (~1,335 lines)
```

## Architecture

### Trait Hierarchy

```
PeerConnection (lib.rs)
└── Methods: send, receive, send_on_stream, receive_from_stream, remote_address, close

NetworkManager (lib.rs)
└── Methods: connect, accept, listen

Network (network_utils/mod.rs)
└── Methods: send, receive, broadcast, send_to_client, receive_from_client

Message (network_utils/mod.rs)
└── Methods: sender_id, data

Node (network_utils/mod.rs)
└── Methods: id, address
```

### Implementation Types

| Type | File | Purpose |
|------|------|---------|
| `QuicNetworkManager` | `transports/quic.rs` | Main entry point, implements `NetworkManager` + `Network` |
| `QuicPeerConnection` | `transports/quic.rs` | Single QUIC connection with persistent streams |
| `LoopbackPeerConnection` | `transports/quic.rs` | Self-delivery via channels |
| `QuicNode` | `transports/quic.rs` | Party identifier with UUID and address |
| `NetEnvelope` | `transports/net_envelope.rs` | Wire format for handshakes and messages |

### Key Design Patterns

1. **Actor Model Compatibility**
   - All connection types use `Arc<Mutex<>>` for interior mutability
   - Methods return `Arc<dyn PeerConnection>` for cloning across tasks
   - Safe to share connections between async tasks

2. **Length-Prefixed Framing**
   - 4-byte big-endian length prefix
   - Maximum message size: 100MB
   - Consistent across QUIC and loopback

3. **Connection State Machine**
   ```
   Connected → Closing → Closed
       ↓
   Disconnected (unexpected)
   ```

4. **Handshake Protocol**
   - Uses `NetEnvelope::Handshake { role, id }`
   - Roles: "CLIENT" or "SERVER"
   - Fallback to address-based lookup if handshake fails

5. **Concurrent Data Structures**
   - `DashMap<PartyId, Arc<dyn PeerConnection>>` for party connections
   - `DashMap<ClientId, Arc<dyn PeerConnection>>` for client connections
   - Lock-free concurrent access

## Key Files

### `src/lib.rs` (160 lines)
Transport-agnostic trait definitions:
- `PeerConnection` trait - single peer communication
- `NetworkManager` trait - connection lifecycle
- Re-exports all public types

### `src/network_utils/mod.rs` (86 lines)
Core types and network abstraction:
- Type aliases: `PartyId`, `ClientId`, `Timeout`
- `ClientType` enum (Client, Server)
- `NetworkError` enum
- `Message`, `Network`, `Node` traits

### `src/transports/quic.rs` (1,335 lines)
Complete QUIC implementation:
- `QuicNetworkManager` - main network coordinator
- `QuicPeerConnection` - QUIC connection wrapper
- `LoopbackPeerConnection` - self-delivery
- `ConnectionError` enum
- `ConnectionState` enum
- TLS certificate generation
- Handshake logic

### `src/transports/net_envelope.rs` (24 lines)
Wire protocol format:
```rust
pub enum NetEnvelope {
    Handshake { role: String, id: usize },
    HoneyBadger(Vec<u8>),
}
```

## API Contracts

### With mpc-protocols

The `mpc-protocols` crate depends on this library for:
- Establishing connections between MPC nodes
- Point-to-point message delivery
- Broadcast to all parties
- Client input/output communication

Key interface:
```rust
// Create network manager
let manager = QuicNetworkManager::new(party_id, nodes, config).await?;

// Start listening
manager.start_listening().await?;

// Connect to peers
manager.connect_to_party(other_party_id).await?;

// Use Network trait methods
manager.send(party_id, &data).await?;
manager.broadcast(&data).await?;
let (sender, msg) = manager.receive().await?;
```

### Configuration Defaults

| Parameter | Default | Constraint |
|-----------|---------|------------|
| `timeout_ms` | 30000 | > 0 |
| `max_retries` | 3 | >= 0 |
| `use_tls` | true | - |

## Common Tasks

### Adding a New Transport

1. Create new file in `src/transports/`
2. Implement `PeerConnection` trait for connection type
3. Implement `NetworkManager` trait for manager type
4. Optionally implement `Network` trait for high-level API
5. Re-export in `src/transports/mod.rs`
6. Add feature flag in `Cargo.toml` if optional

### Modifying Wire Protocol

1. Update `NetEnvelope` enum in `src/transports/net_envelope.rs`
2. Ensure backward compatibility or version negotiation
3. Update serialization if message format changes
4. Update `FRAME_HEADER_SIZE` or `MAX_MESSAGE_SIZE` if needed

### Adding Connection Metrics

1. Add fields to `QuicPeerConnection` or `QuicNetworkManager`
2. Update in `send`/`receive` methods
3. Expose via new methods or integrate with tracing

## Error Handling

### NetworkError (network_utils)
- `SendError` - message failed to send
- `Timeout` - operation timed out
- `PartyNotFound(PartyId)` - unknown party
- `ClientNotFound(ClientId)` - unknown client

### ConnectionError (transports/quic)
- `StreamClosed` - peer closed stream
- `ConnectionLost(String)` - connection dropped
- `SendFailed(String)` - send operation failed
- `ReceiveFailed(String)` - receive operation failed
- `FramingError(String)` - invalid message framing
- `InitializationFailed(String)` - setup failed
- `InvalidState(ConnectionState)` - wrong connection state

## Testing Notes

No tests currently exist. When adding tests:

1. Use `tokio::test` for async tests
2. Create test nodes on localhost with different ports
3. Test connection establishment, messaging, and disconnection
4. Test error cases: timeouts, invalid parties, closed connections
5. Consider using `LoopbackPeerConnection` for unit tests

## Dependencies

Critical dependencies to understand:

| Crate | Purpose |
|-------|---------|
| `quinn` | QUIC protocol implementation |
| `rustls` | TLS cryptography |
| `tokio` | Async runtime (features: full) |
| `dashmap` | Concurrent hash maps |
| `serde` + `bincode` | Serialization |
| `tracing` | Logging/observability |
| `async-trait` | Async trait support |

## Sync with Other Repos

### When Network Protocol Changes
- [ ] Update `mpc-protocols` if message format changes
- [ ] Update `Stoffel-Dev/CLAUDE.md` API contracts section
- [ ] Ensure backward compatibility or coordinate version bump

### When Adding New Traits
- [ ] Document in README.md
- [ ] Update architecture section in this file
- [ ] Check if `mpc-protocols` needs to implement new traits
