# CLAUDE.md

This file provides guidance to Claude Code when working with the stoffel-networking repository.

## Repository Overview

`stoffel-networking` is a QUIC-based peer-to-peer networking library for the Stoffel MPC framework. It provides transport-agnostic abstractions and concrete implementations for secure communication between MPC participants, including NAT traversal capabilities via ICE/STUN.

**Crate name:** `stoffelnet`
**Lines of code:** ~8,200
**Primary consumer:** `mpc-protocols` crate
**Crate types:** `rlib` (Rust library), `cdylib` (C dynamic library for FFI)

## Development Commands

```bash
# Build
cargo build
cargo build --release

# Check for errors without building
cargo check

# Run tests
cargo test

# Run specific test module
cargo test ice_agent::integration_tests

# Format and lint
cargo fmt
cargo clippy

# Generate documentation
cargo doc --open

# Build NAT simulation test binaries
cargo build --bin nat_signaling_server
cargo build --bin nat_test_peer
cargo build --bin nat_stun_server
```

## Repository Structure

```
stoffel-networking/
├── Cargo.toml
├── README.md
├── CLAUDE.md
├── src/
│   ├── lib.rs                    # Transport-agnostic traits + module exports
│   ├── ffi.rs                    # C FFI bindings (~1,374 lines)
│   ├── network_utils/
│   │   └── mod.rs                # Core types: PartyId, Network trait, etc.
│   └── transports/
│       ├── mod.rs                # Module re-exports
│       ├── net_envelope.rs       # Wire protocol message wrapper (~98 lines)
│       ├── quic.rs               # QUIC implementation (~1,995 lines)
│       ├── stun.rs               # STUN client for NAT discovery (~537 lines)
│       ├── ice.rs                # ICE candidate types & utilities (~433 lines)
│       └── ice_agent.rs          # ICE agent state machine (~1,984 lines)
└── tests/
    └── nat_simulation/
        └── src/
            ├── signaling_server.rs   # WebSocket signaling for NAT tests
            ├── nat_test_peer.rs      # Test peer for NAT traversal
            └── stun_server.rs        # Simple STUN server for testing
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
| `StunClient` | `transports/stun.rs` | STUN binding requests for reflexive address discovery |
| `IceCandidate` | `transports/ice.rs` | ICE candidate (host, server-reflexive, peer-reflexive) |
| `IceAgent` | `transports/ice_agent.rs` | ICE state machine for NAT traversal |
| `HolePunchCoordinator` | `transports/ice_agent.rs` | Coordinated UDP hole punching |

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

6. **ICE NAT Traversal (RFC 8445)**
   - Candidate gathering (host + server-reflexive via STUN)
   - Candidate exchange via signaling
   - Connectivity checks with priority-ordered pairs
   - Aggressive nomination for fast connection establishment

## Key Files

### `src/lib.rs` (160 lines)
Transport-agnostic trait definitions:
- `PeerConnection` trait - single peer communication
- `NetworkManager` trait - connection lifecycle
- Re-exports all public types including `ffi` module

### `src/ffi.rs` (1,374 lines)
C Foreign Function Interface for Python/C/Go interop:
- `stoffelnet_runtime_new/destroy` - Tokio runtime management
- `stoffelnet_manager_new/destroy` - Network manager lifecycle
- `stoffelnet_node_new` - Create nodes with party IDs
- `stoffelnet_connection_send/receive` - Blocking I/O
- `stoffelnet_connection_send_async/receive_async` - Callback-based async I/O
- Thread-local error storage with `stoffelnet_last_error`
- Error codes: `STOFFELNET_OK`, `STOFFELNET_ERR_*`

### `src/network_utils/mod.rs` (86 lines)
Core types and network abstraction:
- Type aliases: `PartyId`, `ClientId`, `Timeout`
- `ClientType` enum (Client, Server)
- `NetworkError` enum
- `Message`, `Network`, `Node` traits

### `src/transports/quic.rs` (~1,995 lines)
Complete QUIC implementation:
- `QuicNetworkManager` - main network coordinator
- `QuicPeerConnection` - QUIC connection wrapper
- `LoopbackPeerConnection` - self-delivery
- `QuicNetworkConfig` - configuration including NAT traversal settings
- `ConnectionError` enum
- `ConnectionState` enum
- TLS certificate generation
- Handshake logic
- ICE candidate gathering integration

### `src/transports/stun.rs` (537 lines)
STUN client implementation (RFC 5389/8489):
- `StunClient` - query STUN servers for reflexive addresses
- `StunServerConfig` - server configuration with timeout/retries
- `StunBindingResult` - discovered reflexive address + RTT
- `StunError` - network, timeout, invalid response errors
- `detect_symmetric_nat` - helper to detect symmetric NAT

### `src/transports/ice.rs` (433 lines)
ICE candidate types and utilities (RFC 8445):
- `CandidateType` - Host, ServerReflexive, PeerReflexive, Relay
- `IceCandidate` - full candidate with priority, foundation, etc.
- `CandidatePair` - local+remote pair with combined priority
- `CandidatePairState` - Frozen, Waiting, InProgress, Succeeded, Failed
- `LocalCandidates` - collection with ICE credentials (ufrag/pwd)
- Priority calculation per RFC 8445

### `src/transports/ice_agent.rs` (~1,984 lines)
ICE agent state machine:
- `IceAgent` - manages full ICE process for one peer
- `IceRole` - Controlling or Controlled (determined by party ID)
- `IceState` - New, Gathering, GatheringComplete, Exchanging, Checking, Connected, Completed, Failed, Closed
- `IceAgentConfig` - builder pattern configuration
- `HolePunchCoordinator` - coordinated NAT hole punching
- `HolePunchConfig` - timing parameters for hole punch attempts
- Extensive integration tests

### `src/transports/net_envelope.rs` (98 lines)
Wire protocol format:
```rust
pub enum NetEnvelope {
    Handshake { role: String, id: usize },
    HoneyBadger(Vec<u8>),
    // ICE NAT Traversal Messages
    IceCandidates { ufrag: String, pwd: String, candidates: Vec<IceCandidate> },
    PunchRequest { transaction_id: u64, target_address: SocketAddr, delay_ms: u64 },
    PunchAck { transaction_id: u64, timestamp_ms: u64 },
    ConnectivityCheck { transaction_id: u64, is_response: bool, use_candidate: bool, ufrag: String },
    RelayRequest { target_party_id: usize },
    RelayOffer { relay_address: SocketAddr, allocation_token: Vec<u8>, for_party_id: usize },
    RelayedData { target_party_id: usize, source_party_id: usize, payload: Vec<u8> },
}
```

## API Contracts

### With mpc-protocols

The `mpc-protocols` crate depends on this library for:
- Establishing connections between MPC nodes
- Point-to-point message delivery
- Broadcast to all parties
- Client input/output communication
- NAT traversal for peer-to-peer connectivity

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

// NAT traversal (if enabled)
let candidates = manager.gather_ice_candidates().await?;
let ice_message = manager.create_ice_candidates_message().await?;
```

### FFI API (for Python SDK)

```c
// Runtime management
StoffelRuntimeHandle stoffelnet_runtime_new();
void stoffelnet_runtime_destroy(StoffelRuntimeHandle runtime);

// Network manager
StoffelNetworkManagerHandle stoffelnet_manager_new(
    StoffelRuntimeHandle runtime,
    const char* bind_address,
    uint64_t party_id
);
int stoffelnet_manager_connect_to_party(StoffelNetworkManagerHandle manager, uint64_t party_id);

// Connections
int stoffelnet_connection_send(StoffelPeerConnectionHandle conn, StoffelRuntimeHandle rt, const uint8_t* data, size_t len);
int stoffelnet_connection_receive(StoffelPeerConnectionHandle conn, StoffelRuntimeHandle rt, uint8_t** out_data, size_t* out_len);

// Error handling
const char* stoffelnet_last_error();
void stoffelnet_free_bytes(uint8_t* data, size_t len);
```

### Configuration Defaults

| Parameter | Default | Constraint |
|-----------|---------|------------|
| `timeout_ms` | 30000 | > 0 |
| `max_retries` | 3 | >= 0 |
| `use_tls` | true | - |
| `enable_nat_traversal` | false | - |
| `stun_servers` | [] | list of SocketAddr |

### ICE Configuration Defaults

| Parameter | Default | Constraint |
|-----------|---------|------------|
| `check_timeout` | 500ms | > 0 |
| `check_retries` | 3 | >= 1 |
| `check_pace` | 50ms | > 0 |
| `aggressive_nomination` | true | - |
| `overall_timeout` | 30s | > check_timeout |
| `probe_count` | 5 | >= 1 |
| `probe_interval` | 20ms | > 0 |

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

### Adding STUN Servers

STUN servers require resolved IP addresses (DNS not supported by `SocketAddr`):
```rust
let stun_servers = vec![
    "74.125.250.129:19302".parse().unwrap(), // stun.l.google.com resolved
];
let config = QuicNetworkConfig {
    enable_nat_traversal: true,
    stun_servers,
    ..Default::default()
};
```

### Extending FFI

1. Add function in `src/ffi.rs` with `#[unsafe(no_mangle)]` and `extern "C"`
2. Use opaque handle types (`*mut c_void`) for Rust structs
3. Set errors via `set_last_error()` and return error codes
4. Document safety requirements in doc comments
5. Add tests in the `#[cfg(test)] mod tests` block

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

### StunError (transports/stun)
- `NetworkError(String)` - network I/O error
- `Timeout` - request timed out
- `InvalidResponse(String)` - malformed STUN response
- `NoServersAvailable` - no STUN servers configured
- `AllRetriesFailed` - all retry attempts exhausted

### IceError (transports/ice_agent)
- `GatheringFailed(String)` - candidate gathering failed
- `NoCandidates` - no candidates available
- `AllChecksFailed` - all connectivity checks failed
- `Timeout` - overall ICE timeout exceeded
- `InvalidState(IceState)` - operation invalid in current state
- `SignalingError(String)` - signaling channel error
- `NetworkError(String)` - network error
- `HolePunchFailed(String)` - hole punching failed
- `ConfigError(ConfigError)` - invalid configuration

### FFI Error Codes
- `STOFFELNET_OK (0)` - success
- `STOFFELNET_ERR_NULL_POINTER (-1)` - null pointer passed
- `STOFFELNET_ERR_INVALID_ADDRESS (-2)` - invalid address format
- `STOFFELNET_ERR_CONNECTION (-3)` - connection failed
- `STOFFELNET_ERR_SEND (-4)` - send failed
- `STOFFELNET_ERR_RECEIVE (-5)` - receive failed
- `STOFFELNET_ERR_TIMEOUT (-6)` - operation timed out
- `STOFFELNET_ERR_PARTY_NOT_FOUND (-7)` - party not found
- `STOFFELNET_ERR_RUNTIME (-8)` - runtime error
- `STOFFELNET_ERR_INVALID_UTF8 (-9)` - invalid UTF-8 string
- `STOFFELNET_ERR_CANCELLED (-10)` - operation cancelled

## Testing

The repository includes extensive tests, primarily in `ice_agent.rs`:

```bash
# Run all tests
cargo test

# Run ICE integration tests specifically
cargo test ice_agent::integration_tests

# Run with logging output
RUST_LOG=debug cargo test -- --nocapture
```

### Test Categories

1. **Unit tests** in each module (`#[cfg(test)] mod tests`)
2. **Integration tests** in `ice_agent.rs::integration_tests`
   - ICE agent lifecycle
   - Candidate gathering and exchange
   - Role determination
   - Pair formation and priority
   - Connectivity checks (simulated)
   - NetEnvelope serialization

### NAT Simulation Tests

The `tests/nat_simulation/` directory contains binaries for manual NAT traversal testing:

```bash
# Start signaling server
cargo run --bin nat_signaling_server

# Start STUN server (for testing)
cargo run --bin nat_stun_server

# Run test peers
cargo run --bin nat_test_peer -- --party-id 1 --bind 127.0.0.1:5001
cargo run --bin nat_test_peer -- --party-id 2 --bind 127.0.0.1:5002
```

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
| `byteorder` | Big-endian framing for STUN |
| `rand` | Random transaction IDs and credentials |
| `uuid` | Node identification |

## Sync with Other Repos

### When Network Protocol Changes
- [ ] Update `mpc-protocols` if message format changes
- [ ] Update `Stoffel-Dev/CLAUDE.md` API contracts section
- [ ] Ensure backward compatibility or coordinate version bump

### When Adding New Traits
- [ ] Document in README.md
- [ ] Update architecture section in this file
- [ ] Check if `mpc-protocols` needs to implement new traits

### When FFI Changes
- [ ] Update Python SDK bindings (`SDKs/stoffel-python-sdk`)
- [ ] Regenerate header files if using cbindgen
- [ ] Update FFI documentation in this file

### When ICE/NAT Traversal Changes
- [ ] Update `mpc-protocols` if API changes
- [ ] Update this file's ICE Configuration section
- [ ] Update README.md NAT traversal documentation
