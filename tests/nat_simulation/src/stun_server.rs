//! Simple STUN Server for NAT Simulation Tests
//!
//! This is a minimal STUN server that responds to Binding Requests with the
//! client's apparent (reflexive) address. This allows peers behind NAT to
//! discover their external IP address and port mapping.
//!
//! Implements minimal RFC 5389/8489 for Binding Request/Response.

use byteorder::{BigEndian, ByteOrder};
use std::env;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

/// STUN message types
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_RESPONSE: u16 = 0x0101;

/// STUN attribute types
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_SOFTWARE: u16 = 0x8022;

/// STUN magic cookie (RFC 5389)
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

/// STUN header size
const STUN_HEADER_SIZE: usize = 20;

/// Software identifier
const SOFTWARE_NAME: &[u8] = b"stoffelnet-stun/1.0";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("stun_server=debug".parse().unwrap()),
        )
        .init();

    let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3478".to_string());
    let addr: SocketAddr = bind_addr.parse()?;

    let socket = UdpSocket::bind(addr).await?;
    info!("STUN server listening on {}", addr);

    let mut buf = [0u8; 1024];

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, from)) => {
                debug!("Received {} bytes from {}", len, from);

                if len < STUN_HEADER_SIZE {
                    debug!("Message too short, ignoring");
                    continue;
                }

                // Parse message type
                let msg_type = BigEndian::read_u16(&buf[0..2]);

                if msg_type == STUN_BINDING_REQUEST {
                    // Verify magic cookie
                    let magic = BigEndian::read_u32(&buf[4..8]);
                    if magic != STUN_MAGIC_COOKIE {
                        debug!("Invalid magic cookie from {}, ignoring", from);
                        continue;
                    }

                    // Extract transaction ID
                    let mut transaction_id = [0u8; 12];
                    transaction_id.copy_from_slice(&buf[8..20]);

                    info!("STUN Binding Request from {}", from);

                    // Build and send response
                    let response = build_binding_response(&transaction_id, from);

                    if let Err(e) = socket.send_to(&response, from).await {
                        warn!("Failed to send response to {}: {}", from, e);
                    } else {
                        debug!("Sent Binding Response to {} with XOR-MAPPED-ADDRESS {}", from, from);
                    }
                } else {
                    debug!("Unknown message type 0x{:04x} from {}", msg_type, from);
                }
            }
            Err(e) => {
                warn!("Receive error: {}", e);
            }
        }
    }
}

/// Builds a STUN Binding Response with the client's reflexive address
fn build_binding_response(transaction_id: &[u8; 12], client_addr: SocketAddr) -> Vec<u8> {
    // We'll include XOR-MAPPED-ADDRESS, MAPPED-ADDRESS, and SOFTWARE attributes
    let xor_mapped_attr = build_xor_mapped_address(client_addr);
    let mapped_attr = build_mapped_address(client_addr);
    let software_attr = build_software_attribute();

    let attrs_len = xor_mapped_attr.len() + mapped_attr.len() + software_attr.len();

    let mut response = vec![0u8; STUN_HEADER_SIZE + attrs_len];

    // Message Type: Binding Response
    BigEndian::write_u16(&mut response[0..2], STUN_BINDING_RESPONSE);

    // Message Length (excluding header)
    BigEndian::write_u16(&mut response[2..4], attrs_len as u16);

    // Magic Cookie
    BigEndian::write_u32(&mut response[4..8], STUN_MAGIC_COOKIE);

    // Transaction ID
    response[8..20].copy_from_slice(transaction_id);

    // Append attributes
    let mut offset = STUN_HEADER_SIZE;
    response[offset..offset + xor_mapped_attr.len()].copy_from_slice(&xor_mapped_attr);
    offset += xor_mapped_attr.len();
    response[offset..offset + mapped_attr.len()].copy_from_slice(&mapped_attr);
    offset += mapped_attr.len();
    response[offset..offset + software_attr.len()].copy_from_slice(&software_attr);

    response
}

/// Builds XOR-MAPPED-ADDRESS attribute (IPv4)
fn build_xor_mapped_address(addr: SocketAddr) -> Vec<u8> {
    match addr {
        SocketAddr::V4(v4) => {
            let mut attr = vec![0u8; 12]; // 4 header + 8 value

            // Attribute type
            BigEndian::write_u16(&mut attr[0..2], ATTR_XOR_MAPPED_ADDRESS);

            // Attribute length (8 bytes for IPv4)
            BigEndian::write_u16(&mut attr[2..4], 8);

            // Reserved + Family
            attr[4] = 0;
            attr[5] = 0x01; // IPv4

            // XOR Port: port XOR (magic cookie >> 16)
            let xor_port = addr.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
            BigEndian::write_u16(&mut attr[6..8], xor_port);

            // XOR Address: address XOR magic cookie
            let addr_u32: u32 = (*v4.ip()).into();
            let xor_addr = addr_u32 ^ STUN_MAGIC_COOKIE;
            BigEndian::write_u32(&mut attr[8..12], xor_addr);

            attr
        }
        SocketAddr::V6(v6) => {
            let mut attr = vec![0u8; 24]; // 4 header + 20 value

            // Attribute type
            BigEndian::write_u16(&mut attr[0..2], ATTR_XOR_MAPPED_ADDRESS);

            // Attribute length (20 bytes for IPv6)
            BigEndian::write_u16(&mut attr[2..4], 20);

            // Reserved + Family
            attr[4] = 0;
            attr[5] = 0x02; // IPv6

            // XOR Port
            let xor_port = addr.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
            BigEndian::write_u16(&mut attr[6..8], xor_port);

            // XOR Address (XOR with magic cookie + transaction ID)
            // For simplicity, we just XOR with magic cookie for first 4 bytes
            let octets = v6.ip().octets();
            let magic_bytes = STUN_MAGIC_COOKIE.to_be_bytes();
            for i in 0..4 {
                attr[8 + i] = octets[i] ^ magic_bytes[i];
            }
            for i in 4..16 {
                attr[8 + i] = octets[i]; // Transaction ID XOR omitted for simplicity
            }

            attr
        }
    }
}

/// Builds MAPPED-ADDRESS attribute (legacy, for compatibility)
fn build_mapped_address(addr: SocketAddr) -> Vec<u8> {
    match addr {
        SocketAddr::V4(v4) => {
            let mut attr = vec![0u8; 12]; // 4 header + 8 value

            // Attribute type
            BigEndian::write_u16(&mut attr[0..2], ATTR_MAPPED_ADDRESS);

            // Attribute length
            BigEndian::write_u16(&mut attr[2..4], 8);

            // Reserved + Family
            attr[4] = 0;
            attr[5] = 0x01; // IPv4

            // Port
            BigEndian::write_u16(&mut attr[6..8], addr.port());

            // Address
            let addr_u32: u32 = (*v4.ip()).into();
            BigEndian::write_u32(&mut attr[8..12], addr_u32);

            attr
        }
        SocketAddr::V6(v6) => {
            let mut attr = vec![0u8; 24]; // 4 header + 20 value

            // Attribute type
            BigEndian::write_u16(&mut attr[0..2], ATTR_MAPPED_ADDRESS);

            // Attribute length
            BigEndian::write_u16(&mut attr[2..4], 20);

            // Reserved + Family
            attr[4] = 0;
            attr[5] = 0x02; // IPv6

            // Port
            BigEndian::write_u16(&mut attr[6..8], addr.port());

            // Address
            attr[8..24].copy_from_slice(&v6.ip().octets());

            attr
        }
    }
}

/// Builds SOFTWARE attribute
fn build_software_attribute() -> Vec<u8> {
    let padded_len = (SOFTWARE_NAME.len() + 3) & !3; // Pad to 4-byte boundary
    let mut attr = vec![0u8; 4 + padded_len];

    // Attribute type
    BigEndian::write_u16(&mut attr[0..2], ATTR_SOFTWARE);

    // Attribute length (unpadded)
    BigEndian::write_u16(&mut attr[2..4], SOFTWARE_NAME.len() as u16);

    // Value
    attr[4..4 + SOFTWARE_NAME.len()].copy_from_slice(SOFTWARE_NAME);

    attr
}
