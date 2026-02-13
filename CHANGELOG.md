# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-02-XX

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
- Length-prefixed message framing (4-byte big-endian, max 100MB)
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
