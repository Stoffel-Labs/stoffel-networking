# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-08-24

### Added

- Collision-resistant certificate identities and immutable server certificate rosters for authenticated peer admission.
- Exact server public-key verification when establishing authenticated server connections.
- Bounded per-peer outbound queues, an outbound send statistics hook, and exclusive receive ownership for concurrent execution scanners.

### Changed

- Logical clients may retain multiple concurrent physical connections authenticated by the same certificate; client sends fan out across those connections.
- Legacy compact transport IDs now use domain-separated BLAKE3 derivation and remain non-authoritative for authorization decisions.
- Release automation now validates the crate from version-matched `vX.Y.Z` tags, publishes to crates.io, signs the packaged crate with Cosign, and attaches the crate, SHA-256 checksum, and signature bundle to the GitHub release.

### Fixed

- Outbound party sends and broadcasts fail fast on queue saturation instead of blocking receive paths or retaining messages without a bound.

## [0.1.0] - 2026-06-19

### Added

- Initial release of stoffelnet
- QUIC-based peer-to-peer networking with `QuicNetworkManager` and `QuicPeerConnection`
- Transport-agnostic traits: `PeerConnection` and `NetworkManager`
- High-level `Network` trait for MPC protocol communication
- ICE (RFC 8445) support for NAT traversal via `IceAgent`
- STUN (RFC 5389) client for reflexive address discovery via `StunClient`
- Coordinated UDP hole punching via `HolePunchCoordinator`
- Wire protocol with `NetEnvelope` for handshakes, ICE candidates, and MPC messages
- FFI bindings for C/Python/Go interop:
  - Runtime management (`stoffelnet_runtime_new`, `stoffelnet_runtime_destroy`)
  - Network manager lifecycle (`stoffelnet_manager_new`, etc.)
  - Blocking and async send/receive operations
  - Thread-local error handling (`stoffelnet_last_error`)
- Actor model compatible design with `Arc<Mutex<>>` interior mutability
- Length-prefixed message framing (4-byte big-endian, max 1 GiB)
- Self-delivery via `LoopbackPeerConnection`
- Concurrent connection management with `DashMap`

### Configuration

- `QuicNetworkConfig` for QUIC transport settings (timeout, retries, TLS)
- `IceAgentConfig` for ICE connectivity check parameters
- `HolePunchConfig` for hole punch timing and retry settings
- `StunServerConfig` for STUN server addresses and timeouts

### Error Types

- `ConnectionError` for QUIC connection failures
- `NetworkError` for high-level network operations
- `IceError` for ICE state machine errors
- `StunError` for STUN client errors
- `HolePunchError` for hole punch coordination failures
- `ConfigError` for configuration validation errors
