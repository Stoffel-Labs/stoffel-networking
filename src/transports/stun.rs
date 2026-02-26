//! STUN (Session Traversal Utilities for NAT) client implementation.
//!
//! Provides reflexive address discovery for NAT traversal using STUN binding requests.
//! Implements a minimal STUN client per [RFC 5389](https://datatracker.ietf.org/doc/html/rfc5389)
//! and [RFC 8489](https://datatracker.ietf.org/doc/html/rfc8489).

use byteorder::{BigEndian, ByteOrder};
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DurationMilliSeconds};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tracing::{debug, trace, warn};

/// STUN message types
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_RESPONSE: u16 = 0x0101;

/// STUN attribute types
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// STUN magic cookie (RFC 5389)
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

/// STUN header size
const STUN_HEADER_SIZE: usize = 20;

/// Configuration for a STUN server.
///
/// Specifies connection parameters for querying a single STUN server.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StunServerConfig {
    /// Server address
    pub address: SocketAddr,
    /// Timeout for each request (serialized as milliseconds)
    #[serde_as(as = "DurationMilliSeconds<u64>")]
    pub timeout: Duration,
    /// Maximum retries
    pub max_retries: u32,
}

impl StunServerConfig {
    /// Creates a new STUN server config with default timeout and retries
    pub fn new(address: SocketAddr) -> Self {
        Self {
            address,
            timeout: Duration::from_millis(500),
            max_retries: 3,
        }
    }
}

impl Default for StunServerConfig {
    fn default() -> Self {
        Self {
            // Use localhost as a placeholder - users should configure actual STUN servers
            address: "127.0.0.1:3478".parse().unwrap(),
            timeout: Duration::from_millis(500),
            max_retries: 3,
        }
    }
}

/// Result of a successful STUN binding request
#[derive(Debug, Clone)]
pub struct StunBindingResult {
    /// Discovered reflexive (external) address
    pub reflexive_address: SocketAddr,
    /// STUN server that provided the response
    pub server_address: SocketAddr,
    /// Round-trip time for the request
    pub rtt: Duration,
}

/// STUN client errors.
///
/// These errors are returned by [`StunClient`] methods when STUN operations fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StunError {
    /// Network I/O error
    NetworkError(String),
    /// Request timed out
    Timeout,
    /// Invalid or malformed response
    InvalidResponse(String),
    /// No STUN servers available
    NoServersAvailable,
    /// All retries exhausted
    AllRetriesFailed,
}

impl std::fmt::Display for StunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NetworkError(msg) => write!(f, "Network error: {}", msg),
            Self::Timeout => write!(f, "STUN request timed out"),
            Self::InvalidResponse(msg) => write!(f, "Invalid STUN response: {}", msg),
            Self::NoServersAvailable => write!(f, "No STUN servers available"),
            Self::AllRetriesFailed => write!(f, "All STUN retries failed"),
        }
    }
}

impl std::error::Error for StunError {}

/// STUN client for discovering reflexive addresses
#[derive(Debug, Clone)]
pub struct StunClient {
    servers: Vec<StunServerConfig>,
}

impl StunClient {
    /// Creates a new STUN client with the specified servers
    pub fn new(servers: Vec<StunServerConfig>) -> Self {
        Self { servers }
    }

    /// Creates a STUN client with no servers configured
    ///
    /// Note: Google STUN servers (stun.l.google.com:19302) require DNS resolution
    /// which SocketAddr doesn't support. Users should resolve addresses and use
    /// `StunClient::new()` with resolved IP addresses.
    pub fn with_default_servers() -> Self {
        Self { servers: vec![] }
    }

    /// Discovers the reflexive address using the given UDP socket
    ///
    /// Uses the same socket that will be used for QUIC connections to ensure
    /// accurate NAT mapping discovery.
    pub async fn discover_reflexive(
        &self,
        socket: &UdpSocket,
    ) -> Result<StunBindingResult, StunError> {
        if self.servers.is_empty() {
            return Err(StunError::NoServersAvailable);
        }

        // Try each server in order
        for server in &self.servers {
            match self.query_server(socket, server).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    debug!("STUN server {} failed: {}", server.address, e);
                    continue;
                }
            }
        }

        Err(StunError::AllRetriesFailed)
    }

    /// Discovers reflexive addresses from all available servers.
    ///
    /// Returns results from all servers that respond successfully.
    /// Useful for detecting symmetric NAT (different mappings per destination).
    ///
    /// # Design Note
    ///
    /// This method intentionally does NOT call `discover_reflexive` because the behaviors
    /// differ significantly:
    /// - `discover_reflexive`: Returns on first success (early exit), suitable for
    ///   simple NAT traversal where any server-reflexive address suffices.
    /// - `discover_all`: Queries ALL servers to collect multiple mappings, needed for
    ///   symmetric NAT detection where each destination may produce different mappings.
    ///
    /// Both methods use `query_server` as the common underlying implementation.
    pub async fn discover_all(&self, socket: &UdpSocket) -> Vec<StunBindingResult> {
        let mut results = Vec::with_capacity(self.servers.len());

        for server in &self.servers {
            match self.query_server(socket, server).await {
                Ok(result) => {
                    results.push(result);
                }
                Err(e) => {
                    debug!("STUN server {} failed: {}", server.address, e);
                }
            }
        }

        results
    }

    /// Queries a single STUN server with retries
    async fn query_server(
        &self,
        socket: &UdpSocket,
        server: &StunServerConfig,
    ) -> Result<StunBindingResult, StunError> {
        let transaction_id = Self::generate_transaction_id();
        let request = Self::build_binding_request(&transaction_id);

        for attempt in 0..server.max_retries {
            let start = Instant::now();

            // Send request
            socket
                .send_to(&request, server.address)
                .await
                .map_err(|e| StunError::NetworkError(e.to_string()))?;

            trace!(
                "Sent STUN binding request to {} (attempt {})",
                server.address,
                attempt + 1
            );

            // Wait for response with timeout
            let mut buf = [0u8; 512];
            match tokio::time::timeout(server.timeout, socket.recv_from(&mut buf)).await {
                Ok(Ok((len, from))) => {
                    let rtt = start.elapsed();

                    // Verify response is from the server we queried
                    if from != server.address {
                        debug!(
                            "Received response from unexpected source: {} (expected {})",
                            from, server.address
                        );
                        continue;
                    }

                    // Parse response
                    match Self::parse_binding_response(&buf[..len], &transaction_id) {
                        Ok(reflexive_address) => {
                            debug!(
                                "STUN discovered reflexive address {} from {} (RTT: {:?})",
                                reflexive_address, server.address, rtt
                            );
                            return Ok(StunBindingResult {
                                reflexive_address,
                                server_address: server.address,
                                rtt,
                            });
                        }
                        Err(e) => {
                            warn!("Failed to parse STUN response: {}", e);
                            continue;
                        }
                    }
                }
                Ok(Err(e)) => {
                    debug!("STUN receive error: {}", e);
                    continue;
                }
                Err(_) => {
                    debug!(
                        "STUN request to {} timed out (attempt {})",
                        server.address,
                        attempt + 1
                    );
                    continue;
                }
            }
        }

        Err(StunError::AllRetriesFailed)
    }

    /// Generates a random 12-byte transaction ID
    fn generate_transaction_id() -> [u8; 12] {
        let mut rng = rand::thread_rng();
        let mut id = [0u8; 12];
        rng.fill(&mut id);
        id
    }

    /// Builds a STUN Binding Request message
    fn build_binding_request(transaction_id: &[u8; 12]) -> Vec<u8> {
        let mut msg = vec![0u8; STUN_HEADER_SIZE];

        // Message Type: Binding Request (0x0001)
        BigEndian::write_u16(&mut msg[0..2], STUN_BINDING_REQUEST);

        // Message Length: 0 (no attributes)
        BigEndian::write_u16(&mut msg[2..4], 0);

        // Magic Cookie
        BigEndian::write_u32(&mut msg[4..8], STUN_MAGIC_COOKIE);

        // Transaction ID
        msg[8..20].copy_from_slice(transaction_id);

        msg
    }

    /// Parses a STUN Binding Response and extracts the mapped address
    fn parse_binding_response(
        data: &[u8],
        expected_transaction_id: &[u8; 12],
    ) -> Result<SocketAddr, StunError> {
        if data.len() < STUN_HEADER_SIZE {
            return Err(StunError::InvalidResponse("Message too short".to_string()));
        }

        // Verify message type
        let msg_type = BigEndian::read_u16(&data[0..2]);
        if msg_type != STUN_BINDING_RESPONSE {
            return Err(StunError::InvalidResponse(format!(
                "Unexpected message type: 0x{:04x}",
                msg_type
            )));
        }

        // Verify magic cookie
        let magic = BigEndian::read_u32(&data[4..8]);
        if magic != STUN_MAGIC_COOKIE {
            return Err(StunError::InvalidResponse(
                "Invalid magic cookie".to_string(),
            ));
        }

        // Verify transaction ID
        if &data[8..20] != expected_transaction_id {
            return Err(StunError::InvalidResponse(
                "Transaction ID mismatch".to_string(),
            ));
        }

        // Parse message length
        let msg_len = BigEndian::read_u16(&data[2..4]) as usize;
        if data.len() < STUN_HEADER_SIZE + msg_len {
            return Err(StunError::InvalidResponse(
                "Message length mismatch".to_string(),
            ));
        }

        // Parse attributes
        let mut offset = STUN_HEADER_SIZE;
        let mut xor_mapped_addr: Option<SocketAddr> = None;
        let mut mapped_addr: Option<SocketAddr> = None;

        while offset + 4 <= STUN_HEADER_SIZE + msg_len {
            let attr_type = BigEndian::read_u16(&data[offset..offset + 2]);
            let attr_len = BigEndian::read_u16(&data[offset + 2..offset + 4]) as usize;

            if offset + 4 + attr_len > data.len() {
                break;
            }

            let attr_data = &data[offset + 4..offset + 4 + attr_len];

            match attr_type {
                ATTR_XOR_MAPPED_ADDRESS => {
                    xor_mapped_addr =
                        Self::parse_xor_mapped_address(attr_data, &data[4..8], &data[8..20]);
                }
                ATTR_MAPPED_ADDRESS => {
                    mapped_addr = Self::parse_mapped_address(attr_data);
                }
                _ => {
                    trace!("Ignoring STUN attribute 0x{:04x}", attr_type);
                }
            }

            // Attributes are padded to 4-byte boundaries
            offset += 4 + ((attr_len + 3) & !3);
        }

        // Prefer XOR-MAPPED-ADDRESS over MAPPED-ADDRESS
        xor_mapped_addr
            .or(mapped_addr)
            .ok_or_else(|| StunError::InvalidResponse("No mapped address in response".to_string()))
    }

    /// Parses XOR-MAPPED-ADDRESS attribute (RFC 5389 Section 15.2)
    fn parse_xor_mapped_address(
        data: &[u8],
        magic_cookie: &[u8],
        transaction_id: &[u8],
    ) -> Option<SocketAddr> {
        if data.len() < 8 {
            return None;
        }

        let family = data[1];
        let xor_port = BigEndian::read_u16(&data[2..4]);
        let port = xor_port ^ ((STUN_MAGIC_COOKIE >> 16) as u16);

        match family {
            0x01 => {
                // IPv4
                if data.len() < 8 {
                    return None;
                }
                let xor_addr = BigEndian::read_u32(&data[4..8]);
                let addr = xor_addr ^ STUN_MAGIC_COOKIE;
                let ip = std::net::Ipv4Addr::from(addr);
                Some(SocketAddr::new(ip.into(), port))
            }
            0x02 => {
                // IPv6
                if data.len() < 20 || transaction_id.len() < 12 {
                    return None;
                }
                let mut addr_bytes = [0u8; 16];
                addr_bytes.copy_from_slice(&data[4..20]);
                // XOR with magic cookie (first 4 bytes) and transaction ID (remaining 12 bytes)
                for i in 0..4 {
                    addr_bytes[i] ^= magic_cookie[i];
                }
                for i in 0..12 {
                    addr_bytes[4 + i] ^= transaction_id[i];
                }
                let ip = std::net::Ipv6Addr::from(addr_bytes);
                Some(SocketAddr::new(ip.into(), port))
            }
            _ => None,
        }
    }

    /// Parses MAPPED-ADDRESS attribute (legacy, non-XOR)
    fn parse_mapped_address(data: &[u8]) -> Option<SocketAddr> {
        if data.len() < 8 {
            return None;
        }

        let family = data[1];
        let port = BigEndian::read_u16(&data[2..4]);

        match family {
            0x01 => {
                // IPv4
                let addr = BigEndian::read_u32(&data[4..8]);
                let ip = std::net::Ipv4Addr::from(addr);
                Some(SocketAddr::new(ip.into(), port))
            }
            0x02 => {
                // IPv6
                if data.len() < 20 {
                    return None;
                }
                let mut addr_bytes = [0u8; 16];
                addr_bytes.copy_from_slice(&data[4..20]);
                let ip = std::net::Ipv6Addr::from(addr_bytes);
                Some(SocketAddr::new(ip.into(), port))
            }
            _ => None,
        }
    }

    /// Returns the configured STUN servers
    pub fn servers(&self) -> &[StunServerConfig] {
        &self.servers
    }

    /// Checks if this client has any configured servers
    pub fn has_servers(&self) -> bool {
        !self.servers.is_empty()
    }
}

impl Default for StunClient {
    fn default() -> Self {
        Self::with_default_servers()
    }
}

/// Helper to detect symmetric NAT by comparing reflexive addresses from multiple servers
pub fn detect_symmetric_nat(results: &[StunBindingResult]) -> bool {
    if results.len() < 2 {
        return false;
    }

    // If we get different reflexive addresses from different servers,
    // we're likely behind a symmetric NAT
    let first_addr = results[0].reflexive_address;
    results
        .iter()
        .skip(1)
        .any(|r| r.reflexive_address != first_addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_binding_request() {
        let transaction_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let request = StunClient::build_binding_request(&transaction_id);

        assert_eq!(request.len(), 20);
        // Message type
        assert_eq!(BigEndian::read_u16(&request[0..2]), STUN_BINDING_REQUEST);
        // Message length
        assert_eq!(BigEndian::read_u16(&request[2..4]), 0);
        // Magic cookie
        assert_eq!(BigEndian::read_u32(&request[4..8]), STUN_MAGIC_COOKIE);
        // Transaction ID
        assert_eq!(&request[8..20], &transaction_id);
    }

    #[test]
    fn test_parse_xor_mapped_address_ipv4() {
        // XOR-MAPPED-ADDRESS for 192.0.2.1:32853
        // Port: 32853 XOR (0x2112A442 >> 16) = 32853 XOR 0x2112 = 0xE157
        // Addr: 192.0.2.1 XOR 0x2112A442 = 0xE112A643
        let magic = STUN_MAGIC_COOKIE.to_be_bytes();
        let xor_port: u16 = 32853 ^ 0x2112;
        let xor_addr: u32 = u32::from(std::net::Ipv4Addr::new(192, 0, 2, 1)) ^ STUN_MAGIC_COOKIE;

        let mut data = vec![0u8; 8];
        data[1] = 0x01; // IPv4
        BigEndian::write_u16(&mut data[2..4], xor_port);
        BigEndian::write_u32(&mut data[4..8], xor_addr);

        // Transaction ID (12 bytes) - not used for IPv4 XOR
        let transaction_id = [0u8; 12];
        let result = StunClient::parse_xor_mapped_address(&data, &magic, &transaction_id);
        assert!(result.is_some());

        let addr = result.unwrap();
        assert_eq!(addr.port(), 32853);
        assert_eq!(
            addr.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1))
        );
    }

    #[test]
    fn test_symmetric_nat_detection() {
        let result1 = StunBindingResult {
            reflexive_address: "203.0.113.1:12345".parse().unwrap(),
            server_address: "8.8.8.8:3478".parse().unwrap(),
            rtt: Duration::from_millis(50),
        };

        let result2 = StunBindingResult {
            reflexive_address: "203.0.113.1:12345".parse().unwrap(),
            server_address: "8.8.4.4:3478".parse().unwrap(),
            rtt: Duration::from_millis(60),
        };

        let result3 = StunBindingResult {
            reflexive_address: "203.0.113.1:12346".parse().unwrap(), // Different port!
            server_address: "1.1.1.1:3478".parse().unwrap(),
            rtt: Duration::from_millis(70),
        };

        // Same addresses - not symmetric
        assert!(!detect_symmetric_nat(&[result1.clone(), result2.clone()]));

        // Different addresses - symmetric NAT
        assert!(detect_symmetric_nat(&[result1, result3]));
    }

    // ==================== Helper functions ====================

    fn build_test_response(transaction_id: &[u8; 12], attrs: &[u8]) -> Vec<u8> {
        let mut msg = vec![0u8; 20 + attrs.len()];
        BigEndian::write_u16(&mut msg[0..2], STUN_BINDING_RESPONSE);
        BigEndian::write_u16(&mut msg[2..4], attrs.len() as u16);
        BigEndian::write_u32(&mut msg[4..8], STUN_MAGIC_COOKIE);
        msg[8..20].copy_from_slice(transaction_id);
        msg[20..].copy_from_slice(attrs);
        msg
    }

    fn build_attr(attr_type: u16, data: &[u8]) -> Vec<u8> {
        let mut attr = vec![0u8; 4 + data.len()];
        BigEndian::write_u16(&mut attr[0..2], attr_type);
        BigEndian::write_u16(&mut attr[2..4], data.len() as u16);
        attr[4..].copy_from_slice(data);
        // Pad to 4-byte boundary if needed
        while attr.len() % 4 != 0 {
            attr.push(0);
        }
        attr
    }

    // ==================== Happy path tests ====================

    #[test]
    fn test_parse_xor_mapped_address_ipv6() {
        let transaction_id: [u8; 12] = [
            0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        ];
        let magic_cookie = STUN_MAGIC_COOKIE.to_be_bytes();

        // Target: IPv6 address 2001:db8::1, port 9876
        let expected_ip = std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let expected_port: u16 = 9876;
        let ip_bytes = expected_ip.octets();

        // XOR the port with high 16 bits of magic cookie
        let xor_port = expected_port ^ ((STUN_MAGIC_COOKIE >> 16) as u16);

        // XOR the address: first 4 bytes with magic cookie, next 12 with transaction_id
        let mut xor_addr = [0u8; 16];
        xor_addr.copy_from_slice(&ip_bytes);
        for i in 0..4 {
            xor_addr[i] ^= magic_cookie[i];
        }
        for i in 0..12 {
            xor_addr[4 + i] ^= transaction_id[i];
        }

        // Build attribute data: 1 byte reserved, 1 byte family, 2 bytes port, 16 bytes addr = 20 bytes
        let mut data = vec![0u8; 20];
        data[1] = 0x02; // IPv6
        BigEndian::write_u16(&mut data[2..4], xor_port);
        data[4..20].copy_from_slice(&xor_addr);

        let result = StunClient::parse_xor_mapped_address(&data, &magic_cookie, &transaction_id);
        assert!(
            result.is_some(),
            "Expected Some for valid IPv6 XOR-MAPPED-ADDRESS"
        );

        let addr = result.unwrap();
        assert_eq!(addr.port(), expected_port);
        assert_eq!(addr.ip(), std::net::IpAddr::V6(expected_ip));
    }

    #[test]
    fn test_parse_mapped_address_ipv4() {
        // MAPPED-ADDRESS for 10.0.0.1:8080
        let mut data = vec![0u8; 8];
        data[1] = 0x01; // IPv4 family
        BigEndian::write_u16(&mut data[2..4], 8080);
        let ip = std::net::Ipv4Addr::new(10, 0, 0, 1);
        BigEndian::write_u32(&mut data[4..8], u32::from(ip));

        let result = StunClient::parse_mapped_address(&data);
        assert!(
            result.is_some(),
            "Expected Some for valid IPv4 MAPPED-ADDRESS"
        );

        let addr = result.unwrap();
        assert_eq!(addr.port(), 8080);
        assert_eq!(
            addr.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))
        );
    }

    #[test]
    fn test_parse_mapped_address_ipv6() {
        // MAPPED-ADDRESS for [fe80::1]:4433
        let expected_ip = std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let expected_port: u16 = 4433;

        let mut data = vec![0u8; 20];
        data[1] = 0x02; // IPv6 family
        BigEndian::write_u16(&mut data[2..4], expected_port);
        data[4..20].copy_from_slice(&expected_ip.octets());

        let result = StunClient::parse_mapped_address(&data);
        assert!(
            result.is_some(),
            "Expected Some for valid IPv6 MAPPED-ADDRESS"
        );

        let addr = result.unwrap();
        assert_eq!(addr.port(), expected_port);
        assert_eq!(addr.ip(), std::net::IpAddr::V6(expected_ip));
    }

    #[test]
    fn test_xor_mapped_preferred_over_mapped() {
        let transaction_id: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

        // Build MAPPED-ADDRESS attribute with IP 10.0.0.1:1111
        let mut mapped_data = vec![0u8; 8];
        mapped_data[1] = 0x01; // IPv4
        BigEndian::write_u16(&mut mapped_data[2..4], 1111);
        BigEndian::write_u32(
            &mut mapped_data[4..8],
            u32::from(std::net::Ipv4Addr::new(10, 0, 0, 1)),
        );
        let mapped_attr = build_attr(ATTR_MAPPED_ADDRESS, &mapped_data);

        // Build XOR-MAPPED-ADDRESS attribute with IP 192.168.1.1:2222
        let xor_port: u16 = 2222 ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
        let xor_addr: u32 = u32::from(std::net::Ipv4Addr::new(192, 168, 1, 1)) ^ STUN_MAGIC_COOKIE;
        let mut xor_data = vec![0u8; 8];
        xor_data[1] = 0x01; // IPv4
        BigEndian::write_u16(&mut xor_data[2..4], xor_port);
        BigEndian::write_u32(&mut xor_data[4..8], xor_addr);
        let xor_attr = build_attr(ATTR_XOR_MAPPED_ADDRESS, &xor_data);

        // Combine: MAPPED-ADDRESS first, then XOR-MAPPED-ADDRESS
        let mut attrs = Vec::new();
        attrs.extend_from_slice(&mapped_attr);
        attrs.extend_from_slice(&xor_attr);

        let response = build_test_response(&transaction_id, &attrs);
        let result = StunClient::parse_binding_response(&response, &transaction_id);
        assert!(
            result.is_ok(),
            "Expected Ok for valid response with both attributes"
        );

        let addr = result.unwrap();
        // XOR-MAPPED-ADDRESS should be preferred
        assert_eq!(
            addr.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(addr.port(), 2222);
    }

    // ==================== Semi-honest (invalid but not malicious) tests ====================

    #[test]
    fn test_response_too_short() {
        let transaction_id: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        // Less than 20 bytes (STUN_HEADER_SIZE)
        let short_data = vec![0u8; 10];

        let result = StunClient::parse_binding_response(&short_data, &transaction_id);
        assert!(result.is_err());
        match result.unwrap_err() {
            StunError::InvalidResponse(msg) => {
                assert!(
                    msg.contains("too short"),
                    "Expected 'too short' in error message, got: {}",
                    msg
                );
            }
            other => panic!("Expected InvalidResponse, got: {:?}", other),
        }
    }

    #[test]
    fn test_wrong_message_type() {
        let transaction_id: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        // Build a response with wrong message type (use BINDING_REQUEST instead of RESPONSE)
        let mut msg = vec![0u8; 20];
        BigEndian::write_u16(&mut msg[0..2], STUN_BINDING_REQUEST); // Wrong type
        BigEndian::write_u16(&mut msg[2..4], 0);
        BigEndian::write_u32(&mut msg[4..8], STUN_MAGIC_COOKIE);
        msg[8..20].copy_from_slice(&transaction_id);

        let result = StunClient::parse_binding_response(&msg, &transaction_id);
        assert!(result.is_err());
        match result.unwrap_err() {
            StunError::InvalidResponse(msg) => {
                assert!(
                    msg.contains("message type"),
                    "Expected 'message type' in error, got: {}",
                    msg
                );
            }
            other => panic!("Expected InvalidResponse, got: {:?}", other),
        }
    }

    #[test]
    fn test_message_length_mismatch() {
        let transaction_id: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        // Build response header claiming 100 bytes of attributes, but only 20 bytes total (no attrs)
        let mut msg = vec![0u8; 20];
        BigEndian::write_u16(&mut msg[0..2], STUN_BINDING_RESPONSE);
        BigEndian::write_u16(&mut msg[2..4], 100); // Claims 100 bytes of attributes
        BigEndian::write_u32(&mut msg[4..8], STUN_MAGIC_COOKIE);
        msg[8..20].copy_from_slice(&transaction_id);

        let result = StunClient::parse_binding_response(&msg, &transaction_id);
        assert!(result.is_err());
        match result.unwrap_err() {
            StunError::InvalidResponse(msg) => {
                assert!(
                    msg.contains("length mismatch"),
                    "Expected 'length mismatch' in error, got: {}",
                    msg
                );
            }
            other => panic!("Expected InvalidResponse, got: {:?}", other),
        }
    }

    // ==================== Malicious tests ====================

    #[test]
    fn test_wrong_magic_cookie() {
        let transaction_id: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let mut msg = vec![0u8; 20];
        BigEndian::write_u16(&mut msg[0..2], STUN_BINDING_RESPONSE);
        BigEndian::write_u16(&mut msg[2..4], 0);
        BigEndian::write_u32(&mut msg[4..8], 0xDEADBEEF); // Wrong magic cookie
        msg[8..20].copy_from_slice(&transaction_id);

        let result = StunClient::parse_binding_response(&msg, &transaction_id);
        assert!(result.is_err());
        match result.unwrap_err() {
            StunError::InvalidResponse(msg) => {
                assert!(
                    msg.contains("magic cookie"),
                    "Expected 'magic cookie' in error, got: {}",
                    msg
                );
            }
            other => panic!("Expected InvalidResponse, got: {:?}", other),
        }
    }

    #[test]
    fn test_transaction_id_mismatch() {
        let expected_id: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let wrong_id: [u8; 12] = [99, 98, 97, 96, 95, 94, 93, 92, 91, 90, 89, 88];

        // Build response with wrong transaction ID
        let response = build_test_response(&wrong_id, &[]);

        let result = StunClient::parse_binding_response(&response, &expected_id);
        assert!(result.is_err());
        match result.unwrap_err() {
            StunError::InvalidResponse(msg) => {
                assert!(
                    msg.contains("Transaction ID mismatch"),
                    "Expected 'Transaction ID mismatch' in error, got: {}",
                    msg
                );
            }
            other => panic!("Expected InvalidResponse, got: {:?}", other),
        }
    }

    #[test]
    fn test_no_mapped_address_in_response() {
        let transaction_id: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        // Valid header with no attributes at all
        let response = build_test_response(&transaction_id, &[]);

        let result = StunClient::parse_binding_response(&response, &transaction_id);
        assert!(result.is_err());
        match result.unwrap_err() {
            StunError::InvalidResponse(msg) => {
                assert!(
                    msg.contains("No mapped address"),
                    "Expected 'No mapped address' in error, got: {}",
                    msg
                );
            }
            other => panic!("Expected InvalidResponse, got: {:?}", other),
        }
    }

    #[test]
    fn test_unknown_address_family() {
        let magic_cookie = STUN_MAGIC_COOKIE.to_be_bytes();
        let transaction_id: [u8; 12] = [0; 12];

        // Build XOR-MAPPED-ADDRESS with unknown family 0x03
        let mut data = vec![0u8; 8];
        data[1] = 0x03; // Unknown family
        BigEndian::write_u16(&mut data[2..4], 1234);
        BigEndian::write_u32(&mut data[4..8], 0x12345678);

        let result = StunClient::parse_xor_mapped_address(&data, &magic_cookie, &transaction_id);
        assert!(
            result.is_none(),
            "Expected None for unknown address family 0x03"
        );
    }

    #[test]
    fn test_truncated_attribute_too_short_for_header() {
        let magic_cookie = STUN_MAGIC_COOKIE.to_be_bytes();
        let transaction_id: [u8; 12] = [0; 12];

        // Only 6 bytes — less than the minimum 8 required.
        // The initial length guard (data.len() < 8) rejects this before
        // the family byte is even examined.
        let mut data = vec![0u8; 6];
        data[1] = 0x01; // IPv4 family (irrelevant — rejected by length)

        let result = StunClient::parse_xor_mapped_address(&data, &magic_cookie, &transaction_id);
        assert!(
            result.is_none(),
            "Expected None for attribute shorter than 8 bytes"
        );
    }

    #[test]
    fn test_truncated_ipv6_attribute() {
        let magic_cookie = STUN_MAGIC_COOKIE.to_be_bytes();
        let transaction_id: [u8; 12] = [0; 12];

        // 12 bytes with IPv6 family - less than the 20 required for IPv6
        let mut data = vec![0u8; 12];
        data[1] = 0x02; // IPv6 family
        BigEndian::write_u16(&mut data[2..4], 5555);

        let result = StunClient::parse_xor_mapped_address(&data, &magic_cookie, &transaction_id);
        assert!(
            result.is_none(),
            "Expected None for truncated IPv6 attribute (< 20 bytes)"
        );
    }

    // ==================== Edge case tests ====================

    #[test]
    fn test_no_servers_configured() {
        let client = StunClient::new(vec![]);
        assert!(
            !client.has_servers(),
            "Expected has_servers() to return false for empty server list"
        );
    }

    #[test]
    fn test_single_result_not_symmetric_nat() {
        let result = StunBindingResult {
            reflexive_address: "203.0.113.1:12345".parse().unwrap(),
            server_address: "8.8.8.8:3478".parse().unwrap(),
            rtt: Duration::from_millis(50),
        };

        assert!(
            !detect_symmetric_nat(&[result]),
            "Expected false for single STUN result (need at least 2 to detect symmetric NAT)"
        );
    }

    #[test]
    fn test_empty_results_not_symmetric_nat() {
        assert!(
            !detect_symmetric_nat(&[]),
            "Expected false for empty STUN results"
        );
    }

    #[test]
    fn test_transaction_id_uniqueness() {
        let id1 = StunClient::generate_transaction_id();
        let id2 = StunClient::generate_transaction_id();

        assert_ne!(
            id1, id2,
            "Two consecutive transaction IDs should be different (with overwhelming probability)"
        );
    }
}
