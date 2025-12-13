//! NAT Test Peer - Attempts hole punching through simulated NAT
//!
//! This binary:
//! 1. Connects to the signaling server
//! 2. Gathers ICE candidates (including STUN reflexive addresses)
//! 3. Exchanges candidates with the other peer
//! 4. Coordinates timing and attempts hole punching
//! 5. Reports success/failure

use std::env;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use stoffelnet::transports::ice::{LocalCandidates, CandidateType};
use stoffelnet::transports::ice_agent::IceRole;
use stoffelnet::transports::stun::{StunClient, StunServerConfig};

use quinn::{Endpoint, ClientConfig, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Remote peer's candidates
struct RemotePeerInfo {
    peer_id: usize,
    candidates: LocalCandidates,
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    // Initialize crypto provider for rustls
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install crypto provider");

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("nat_test_peer=debug".parse().unwrap())
                .add_directive("stoffelnet=debug".parse().unwrap()),
        )
        .init();

    // Read configuration from environment
    let peer_id: usize = env::var("PEER_ID")
        .expect("PEER_ID required")
        .parse()
        .expect("PEER_ID must be a number");

    let peer_name = env::var("PEER_NAME").unwrap_or_else(|_| format!("peer_{}", peer_id));

    let signaling_server = env::var("SIGNALING_SERVER")
        .unwrap_or_else(|_| "172.16.0.10:9000".to_string());

    let local_addr: SocketAddr = env::var("LOCAL_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:5000".to_string())
        .parse()
        .expect("Invalid LOCAL_ADDR");

    let stun_server = env::var("STUN_SERVER").ok();

    info!("Starting {} (ID: {})", peer_name, peer_id);
    info!("Signaling server: {}", signaling_server);
    info!("Local bind address: {}", local_addr);
    info!("STUN server: {:?}", stun_server);

    // Connect to signaling server - resolve hostname if needed
    let signaling_addr: SocketAddr = signaling_server
        .to_socket_addrs()
        .map_err(|e| format!("Failed to resolve signaling server address: {}", e))?
        .next()
        .ok_or("No addresses found for signaling server")?;
    info!("Resolved signaling server to: {}", signaling_addr);
    let stream = TcpStream::connect(signaling_addr).await?;
    info!("Connected to signaling server");

    let (reader, writer) = stream.into_split();
    let reader = Arc::new(Mutex::new(BufReader::new(reader)));
    let writer = Arc::new(Mutex::new(writer));

    // Phase 1: Bind the ONE socket we'll use for everything
    // This socket will be used for STUN discovery, hole punching, and QUIC
    // Keeping the same socket preserves NAT mappings throughout
    let socket = UdpSocket::bind(local_addr).await
        .map_err(|e| format!("Failed to bind UDP socket: {}", e))?;
    info!("Bound UDP socket to {} - will reuse for STUN and QUIC", socket.local_addr()?);

    // Discover reflexive address using STUN (using the same socket)
    let stun_reflexive: Option<SocketAddr> = if let Some(stun_addr_str) = &stun_server {
        let stun_addr: SocketAddr = stun_addr_str
            .to_socket_addrs()
            .map_err(|e| format!("Failed to resolve STUN server address: {}", e))?
            .next()
            .ok_or("No addresses found for STUN server")?;

        info!("Querying STUN server at {} for reflexive address", stun_addr);

        let stun_client = StunClient::new(vec![StunServerConfig::new(stun_addr)]);

        match stun_client.discover_reflexive(&socket).await {
            Ok(result) => {
                info!("STUN discovered reflexive address: {} (RTT: {:?})",
                      result.reflexive_address, result.rtt);
                Some(result.reflexive_address)
            }
            Err(e) => {
                warn!("STUN reflexive discovery failed: {}", e);
                None
            }
        }
        // Socket NOT dropped - we keep it for QUIC
    } else {
        None
    };

    // Phase 2: Register with signaling and exchange candidates
    // We don't start QUIC yet - we need to do hole punching first

    // Register with signaling server
    {
        let mut w = writer.lock().await;
        w.write_all(format!("REGISTER {}\n", peer_id).as_bytes()).await?;
        w.flush().await?;
    }
    info!("Registered with signaling server");

    // Build local candidates (manually, since QUIC isn't bound yet)
    let mut local_candidates = LocalCandidates::new();

    // Get our local IPs for host candidates using UDP socket trick
    // This finds IPs that have routes to the network
    let targets = ["8.8.8.8:53", "1.1.1.1:53", "10.100.0.10:9000"];
    for target in targets {
        if let Ok(socket) = std::net::UdpSocket::bind("0.0.0.0:0") {
            if let Ok(target_addr) = target.parse::<SocketAddr>() {
                if socket.connect(target_addr).is_ok() {
                    if let Ok(local) = socket.local_addr() {
                        let ip = local.ip();
                        if !ip.is_loopback() && !ip.is_unspecified() {
                            let host_addr = SocketAddr::new(ip, local_addr.port());
                            if !local_candidates.candidates.iter().any(|c| c.address == host_addr) {
                                local_candidates.add_host(host_addr);
                                info!("Added host candidate: {}", host_addr);
                            }
                        }
                    }
                }
            }
        }
    }

    // Add STUN reflexive candidate if we discovered one
    if let Some(reflexive_addr) = stun_reflexive {
        if !local_candidates.candidates.iter().any(|c| c.address == reflexive_addr) {
            let base_addr = local_candidates.candidates.first()
                .map(|c| c.address)
                .unwrap_or(local_addr);
            let stun_addr: SocketAddr = stun_server.as_ref().unwrap().parse().unwrap_or_else(|_| "0.0.0.0:3478".parse().unwrap());
            local_candidates.add_server_reflexive(reflexive_addr, base_addr, stun_addr);
            info!("Added STUN reflexive candidate: {}", reflexive_addr);
        }
    } else {
        // Fall back to signaling server reflexive IP (TCP-based, less accurate)
        let reflexive_ip = wait_for_reflexive(reader.clone()).await?;
        info!("Using signaling server reflexive IP (fallback): {}", reflexive_ip);

        let reflexive_addr: SocketAddr = format!("{}:{}", reflexive_ip, local_addr.port()).parse()
            .map_err(|e| format!("Failed to parse reflexive address: {}", e))?;

        if !local_candidates.candidates.iter().any(|c| c.address == reflexive_addr) {
            let base_addr = local_candidates.candidates.first()
                .map(|c| c.address)
                .unwrap_or(local_addr);
            local_candidates.add_server_reflexive(reflexive_addr, base_addr, signaling_addr);
            info!("Added fallback reflexive candidate: {}", reflexive_addr);
        }
    }

    info!("Gathered {} local candidates", local_candidates.len());

    for candidate in &local_candidates.candidates {
        info!("  - {:?} at {}", candidate.candidate_type, candidate.address);
    }

    // Send candidates to signaling server
    let candidates_json = serde_json::to_string(&local_candidates)?;
    {
        let mut w = writer.lock().await;
        w.write_all(format!("CANDIDATES {}\n", candidates_json).as_bytes()).await?;
        w.flush().await?;
    }
    info!("Sent candidates to signaling server");

    // Wait for remote peer's candidates
    let remote_peer = wait_for_remote_candidates(reader.clone()).await?;
    info!(
        "Received {} candidates from peer {}",
        remote_peer.candidates.len(),
        remote_peer.peer_id
    );

    for candidate in &remote_peer.candidates.candidates {
        info!("  Remote: {:?} at {}", candidate.candidate_type, candidate.address);
    }

    // Signal that we're ready
    {
        let mut w = writer.lock().await;
        w.write_all(format!("READY {}\n", peer_id).as_bytes()).await?;
        w.flush().await?;
    }
    info!("Signaled ready for hole punching");

    // Wait for START signal with synchronized timestamp
    let start_timestamp = wait_for_start_signal(reader.clone()).await?;
    info!("Received START signal for timestamp {}", start_timestamp);

    // Wait until the synchronized start time
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    if start_timestamp > now {
        let delay = Duration::from_millis(start_timestamp - now);
        info!("Waiting {:?} until synchronized start", delay);
        tokio::time::sleep(delay).await;
    }

    // Determine role based on peer IDs
    let role = if peer_id > remote_peer.peer_id {
        IceRole::Controlling
    } else {
        IceRole::Controlled
    };
    info!("Role: {:?}", role);

    // Get remote address for hole punching - prefer server-reflexive, fall back to host
    let remote_srflx = remote_peer
        .candidates
        .candidates
        .iter()
        .find(|c| matches!(c.candidate_type, CandidateType::ServerReflexive))
        .or_else(|| {
            info!("No server-reflexive candidate, falling back to host candidate");
            remote_peer.candidates.candidates.iter()
                .find(|c| matches!(c.candidate_type, CandidateType::Host))
        })
        .map(|c| c.address)
        .ok_or("No usable candidate from remote peer")?;

    // Skip separate STUN hole punch phase - QUIC Initial packets will punch the hole directly
    // This is based on the paper "Implementing NAT Hole Punching with QUIC" (arXiv:2408.01791)
    // which shows QUIC hole punching is 0.5 RTT faster than TCP because the Initial packets
    // themselves create the NAT mapping
    info!("Skipping STUN hole punch - QUIC Initial packets will punch the hole directly");

    // Signal that we're ready to start QUIC
    {
        let mut w = writer.lock().await;
        w.write_all(format!("HOLE_PUNCHED {}\n", peer_id).as_bytes()).await?;
        w.flush().await?;
    }
    info!("Signaled ready for QUIC, waiting for peer...");

    // Wait for START_QUIC signal (with timeout)
    let start_quic_timeout = Duration::from_secs(5);
    let start_quic_result = tokio::time::timeout(
        start_quic_timeout,
        wait_for_start_quic(reader.clone())
    ).await;

    match start_quic_result {
        Ok(Ok(_)) => info!("Received START_QUIC, both peers ready"),
        Ok(Err(e)) => warn!("Error waiting for START_QUIC: {}, proceeding anyway", e),
        Err(_) => warn!("Timeout waiting for START_QUIC, proceeding anyway"),
    }

    // Phase 2: Start QUIC using the SAME socket used for STUN discovery
    // This preserves the NAT mapping created during STUN
    info!("Phase 2: Starting QUIC directly to {} (no separate hole punch)", remote_srflx);

    // Clone socket for keep-alive before converting to QUIC endpoint
    let std_socket = socket.into_std()?;

    // Pre-QUIC UDP warmup: Send packets to punch holes BEFORE creating QUIC endpoint
    // This creates NAT mappings so QUIC Initial packets can get through
    // We convert back to tokio socket temporarily for the warmup
    let socket = UdpSocket::from_std(std_socket)?;
    udp_warmup(&socket, remote_srflx).await?;

    // Drain any buffered warmup packets from the socket before starting QUIC
    // This prevents them from being received by the QUIC endpoint as "invalid CID"
    info!("Draining any buffered warmup packets...");
    let mut drain_buf = [0u8; 2048];
    let mut drained_count = 0;
    loop {
        // Non-blocking receive to drain any buffered packets
        match tokio::time::timeout(Duration::from_millis(50), socket.recv_from(&mut drain_buf)).await {
            Ok(Ok((len, from))) => {
                debug!("Drained warmup packet: {} bytes from {}", len, from);
                drained_count += 1;
            }
            _ => {
                // No more packets
                break;
            }
        }
    }
    info!("Drained {} warmup packets", drained_count);

    let std_socket = socket.into_std()?;

    // Create QUIC endpoint from the socket
    info!("Creating QUIC endpoint from STUN-discovery socket");
    let endpoint = create_quic_endpoint_from_std_socket(std_socket).await?;

    info!("QUIC endpoint listening on {:?}", endpoint.local_addr());

    // Attempt QUIC connection
    let result = attempt_quic_connection_with_endpoint(&endpoint, peer_id, remote_srflx, role).await;

    // Report result to signaling server
    let (success, message) = match &result {
        Ok(remote_addr) => (true, format!("Connected to {}", remote_addr)),
        Err(e) => (false, e.to_string()),
    };

    {
        let mut w = writer.lock().await;
        let result_str = if success { "success" } else { "failure" };
        w.write_all(format!("RESULT {} {}\n", result_str, message).as_bytes()).await?;
        w.flush().await?;
    }

    if success {
        info!("SUCCESS: {}", message);
    } else {
        error!("FAILURE: {}", message);
    }

    // Wait for test completion
    wait_for_test_complete(reader.clone()).await?;

    Ok(())
}

async fn wait_for_reflexive(
    reader: Arc<Mutex<BufReader<tokio::net::tcp::OwnedReadHalf>>>,
) -> Result<String, BoxError> {
    let mut line = String::new();

    loop {
        line.clear();
        {
            let mut r = reader.lock().await;
            r.read_line(&mut line).await?;
        }

        let line = line.trim();
        debug!("Signaling message: {}", line);

        if line.starts_with("REFLEXIVE ") {
            let ip = line[10..].to_string();
            return Ok(ip);
        }
    }
}

async fn wait_for_remote_candidates(
    reader: Arc<Mutex<BufReader<tokio::net::tcp::OwnedReadHalf>>>,
) -> Result<RemotePeerInfo, BoxError> {
    let mut line = String::new();

    loop {
        line.clear();
        {
            let mut r = reader.lock().await;
            r.read_line(&mut line).await?;
        }

        let line = line.trim();
        debug!("Signaling message: {}", line);

        if line.starts_with("CANDIDATES ") {
            let parts: Vec<&str> = line.splitn(3, ' ').collect();
            if parts.len() >= 3 {
                let peer_id: usize = parts[1].parse()?;
                let candidates: LocalCandidates = serde_json::from_str(parts[2])?;

                return Ok(RemotePeerInfo { peer_id, candidates });
            }
        }
    }
}

async fn wait_for_start_signal(
    reader: Arc<Mutex<BufReader<tokio::net::tcp::OwnedReadHalf>>>,
) -> Result<u64, BoxError> {
    let mut line = String::new();

    loop {
        line.clear();
        {
            let mut r = reader.lock().await;
            r.read_line(&mut line).await?;
        }

        let line = line.trim();
        debug!("Signaling message: {}", line);

        if line.starts_with("START ") {
            let timestamp: u64 = line[6..].parse()?;
            return Ok(timestamp);
        }
    }
}

/// Option B: Wait for START_QUIC signal indicating both peers have hole punched
async fn wait_for_start_quic(
    reader: Arc<Mutex<BufReader<tokio::net::tcp::OwnedReadHalf>>>,
) -> Result<(), BoxError> {
    let mut line = String::new();

    loop {
        line.clear();
        {
            let mut r = reader.lock().await;
            r.read_line(&mut line).await?;
        }

        let line = line.trim();
        debug!("Signaling message: {}", line);

        if line == "START_QUIC" {
            return Ok(());
        }
        // Also accept if we see PEER_HOLE_PUNCHED (means the other peer is ready)
        if line.starts_with("PEER_HOLE_PUNCHED") {
            debug!("Peer has hole punched, continuing to wait for START_QUIC");
        }
    }
}

async fn wait_for_test_complete(
    reader: Arc<Mutex<BufReader<tokio::net::tcp::OwnedReadHalf>>>,
) -> Result<bool, BoxError> {
    let mut line = String::new();

    // Wait with timeout
    let result = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            line.clear();
            {
                let mut r = reader.lock().await;
                r.read_line(&mut line).await?;
            }

            let line = line.trim();
            debug!("Signaling message: {}", line);

            if line.starts_with("TEST_COMPLETE ") {
                let success = line.contains("success");
                return Ok::<bool, BoxError>(success);
            }
        }
    }).await;

    match result {
        Ok(Ok(success)) => Ok(success),
        Ok(Err(e)) => Err(e),
        Err(_) => {
            warn!("Timeout waiting for test completion");
            Ok(false)
        }
    }
}

/// Create insecure client config (for development only)
fn create_insecure_client_config() -> Result<ClientConfig, BoxError> {
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    crypto.alpn_protocols = vec![b"hp".to_vec()];

    let mut config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .map_err(|e| format!("Failed to create QUIC client config: {}", e))?,
    ));

    config.transport_config(Arc::new({
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_uni_streams(0u32.into());
        transport.keep_alive_interval(Some(Duration::from_secs(5)));
        transport
    }));

    Ok(config)
}

/// Create self-signed server config (for development only)
fn create_self_signed_server_config() -> Result<ServerConfig, BoxError> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .map_err(|e| format!("Failed to generate certificate: {}", e))?;

    let cert_der = CertificateDer::from(cert.cert.der().to_vec());
    let key_der = PrivateKeyDer::Pkcs8(
        PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der())
    );

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .map_err(|e| format!("Failed to create server crypto config: {}", e))?;

    server_crypto.alpn_protocols = vec![b"hp".to_vec()];

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| format!("Failed to create QUIC server config: {}", e))?,
    ));

    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0u32.into());
    transport_config.keep_alive_interval(Some(Duration::from_secs(5)));

    Ok(server_config)
}

/// Create a QUIC endpoint from an existing tokio UDP socket
/// This is critical for NAT traversal - we must reuse the socket that punched the hole
async fn create_quic_endpoint_from_socket(socket: UdpSocket) -> Result<Endpoint, BoxError> {
    let std_socket = socket.into_std()?;
    create_quic_endpoint_from_std_socket(std_socket).await
}

/// Create a QUIC endpoint from an existing std UDP socket
async fn create_quic_endpoint_from_std_socket(std_socket: std::net::UdpSocket) -> Result<Endpoint, BoxError> {
    let server_config = create_self_signed_server_config()?;
    let client_config = create_insecure_client_config()?;

    // Create endpoint with runtime and existing socket
    let runtime = Arc::new(quinn::TokioRuntime);
    let mut endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        std_socket,
        runtime,
    ).map_err(|e| format!("Failed to create endpoint from socket: {}", e))?;

    endpoint.set_default_client_config(client_config);

    Ok(endpoint)
}

/// Create a fresh QUIC endpoint bound to the given address
async fn create_quic_endpoint(bind_addr: SocketAddr) -> Result<Endpoint, BoxError> {
    let server_config = create_self_signed_server_config()?;
    let client_config = create_insecure_client_config()?;

    let mut endpoint = Endpoint::server(server_config, bind_addr)
        .map_err(|e| format!("Failed to create server endpoint: {}", e))?;

    endpoint.set_default_client_config(client_config);

    Ok(endpoint)
}

/// Attempt QUIC connection using bidirectional strategy
///
/// Both peers simultaneously:
/// 1. Accept incoming connections
/// 2. Attempt outgoing connections (with role-based timing)
///
/// This maximizes success probability by allowing either direction to succeed.
/// Includes UDP keep-alive to maintain NAT mappings during handshake.
async fn attempt_quic_connection_with_endpoint(
    endpoint: &Endpoint,
    _local_peer_id: usize,
    remote_addr: SocketAddr,
    role: IceRole,
) -> Result<SocketAddr, BoxError> {
    use tokio::sync::oneshot;

    // Increase timeout to allow handshake to complete through NAT
    // QUIC handshake needs time for Initial → Handshake → 1-RTT exchange
    let overall_timeout = Duration::from_secs(30);
    let attempt_timeout = Duration::from_secs(10);  // Increased from 3s to allow full handshake

    // Channel to signal success from either direction
    let (success_tx, success_rx) = oneshot::channel::<SocketAddr>();
    let success_tx = Arc::new(std::sync::Mutex::new(Some(success_tx)));

    // Clone endpoint for both tasks
    let endpoint_accept = endpoint.clone();
    let endpoint_connect = endpoint.clone();
    let success_tx_connect = success_tx.clone();

    // Option D: Bidirectional - spawn accept task
    let accept_handle = tokio::spawn(async move {
        loop {
            match endpoint_accept.accept().await {
                Some(incoming) => {
                    debug!("Received incoming QUIC connection attempt");
                    match incoming.await {
                        Ok(conn) => {
                            let addr = conn.remote_address();
                            info!("Accepted QUIC connection from {}", addr);
                            // Try to send success signal
                            if let Some(tx) = success_tx.lock().unwrap().take() {
                                let _ = tx.send(addr);
                            }
                            return Ok::<_, BoxError>(addr);
                        }
                        Err(e) => {
                            debug!("Failed to accept incoming connection: {}", e);
                        }
                    }
                }
                None => {
                    debug!("Accept returned None, endpoint closed");
                    return Err("Endpoint closed".into());
                }
            }
        }
    });

    // Both peers initiate connections - QUIC handles the race gracefully
    // The first successful handshake wins. Both peers sending Initial packets
    // simultaneously helps punch holes from both directions.
    let connect_handle = {
        let handle = tokio::spawn(async move {
            // Small delay to let accept task start
            tokio::time::sleep(Duration::from_millis(50)).await;

            info!("QUIC connect attempt to {} (timeout: {:?}) - role: {:?}", remote_addr, attempt_timeout, role);

            let connecting = match endpoint_connect.connect(remote_addr, "localhost") {
                Ok(c) => c,
                Err(e) => {
                    error!("QUIC connect call failed: {}", e);
                    return Err::<SocketAddr, BoxError>(e.into());
                }
            };

            match tokio::time::timeout(attempt_timeout, connecting).await {
                Ok(Ok(conn)) => {
                    let addr = conn.remote_address();
                    info!("Successfully connected to {}", addr);
                    // Try to send success signal
                    if let Some(tx) = success_tx_connect.lock().unwrap().take() {
                        let _ = tx.send(addr);
                    }
                    Ok(addr)
                }
                Ok(Err(e)) => {
                    debug!("QUIC handshake failed: {}", e);
                    Err(e.into())
                }
                Err(_) => {
                    debug!("QUIC connect attempt timed out");
                    Err("Connection timed out".into())
                }
            }
        });
        Some(handle)
    };

    info!("Starting bidirectional QUIC connection (role: {:?})", role);

    // Wait for either direction to succeed or timeout
    let result = tokio::time::timeout(overall_timeout, success_rx).await;

    // Clean up tasks
    accept_handle.abort();
    if let Some(handle) = connect_handle {
        handle.abort();
    }

    match result {
        Ok(Ok(addr)) => {
            info!("QUIC connection established to {}", addr);
            Ok(addr)
        }
        Ok(Err(_)) => {
            // Channel closed without success
            Err("QUIC connection failed - channel closed".into())
        }
        Err(_) => {
            Err("QUIC connection timed out after hole punch".into())
        }
    }
}

/// Option E: Pre-QUIC UDP warming phase
/// Sends a burst of UDP packets to prime the NAT path before QUIC handshake
/// Extended to 500ms to ensure NAT mappings are established before QUIC starts
async fn udp_warmup(socket: &UdpSocket, remote_addr: SocketAddr) -> Result<(), BoxError> {
    use byteorder::{BigEndian, ByteOrder};

    const STUN_BINDING_REQUEST: u16 = 0x0001;
    const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

    info!("Pre-QUIC UDP warming: sending burst to {} over 500ms", remote_addr);

    // Generate a random transaction ID
    let mut transaction_id = [0u8; 12];
    for i in 0..12 {
        transaction_id[i] = rand::random();
    }

    // Build STUN-like packet (NAT will see it as continuation of STUN traffic)
    let mut packet = [0u8; 20];
    BigEndian::write_u16(&mut packet[0..2], STUN_BINDING_REQUEST);
    BigEndian::write_u16(&mut packet[2..4], 0);
    BigEndian::write_u32(&mut packet[4..8], STUN_MAGIC_COOKIE);
    packet[8..20].copy_from_slice(&transaction_id);

    // Send packets over 500ms to ensure NAT mappings are created
    // and both peers have time to send packets to each other
    let warmup_duration = Duration::from_millis(500);
    let start = std::time::Instant::now();
    let mut count = 0;

    while start.elapsed() < warmup_duration {
        // Regenerate transaction ID periodically
        if count % 10 == 0 {
            for i in 0..12 {
                transaction_id[i] = rand::random();
            }
            packet[8..20].copy_from_slice(&transaction_id);
        }

        socket.send_to(&packet, remote_addr).await?;
        count += 1;

        // Send every 10ms = ~50 packets over 500ms
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    info!("UDP warming complete: sent {} packets over {:?}", count, start.elapsed());
    Ok(())
}

/// Spawn an aggressive keep-alive task that sends packets during QUIC handshake
/// Sends packets every 20ms to keep NAT mapping alive and help punch hole
/// Returns a handle that can be used to stop the keep-alive
fn spawn_aggressive_keepalive(
    socket: std::net::UdpSocket,
    remote_addr: SocketAddr,
) -> tokio::task::JoinHandle<()> {
    use byteorder::{BigEndian, ByteOrder};

    tokio::spawn(async move {
        const STUN_BINDING_REQUEST: u16 = 0x0001;
        const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

        // Generate a random transaction ID
        let mut transaction_id = [0u8; 12];
        for i in 0..12 {
            transaction_id[i] = rand::random();
        }

        let mut packet = [0u8; 20];
        BigEndian::write_u16(&mut packet[0..2], STUN_BINDING_REQUEST);
        BigEndian::write_u16(&mut packet[2..4], 0);
        BigEndian::write_u32(&mut packet[4..8], STUN_MAGIC_COOKIE);
        packet[8..20].copy_from_slice(&transaction_id);

        // First phase: aggressive burst to punch hole (every 10ms for 500ms)
        info!("Starting aggressive keep-alive burst to {}", remote_addr);
        let burst_end = std::time::Instant::now() + Duration::from_millis(500);
        let mut count = 0;
        while std::time::Instant::now() < burst_end {
            if let Err(e) = socket.send_to(&packet, remote_addr) {
                debug!("Keep-alive send failed: {}", e);
                break;
            }
            count += 1;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        debug!("Sent {} burst packets in 500ms", count);

        // Second phase: steady keep-alive every 50ms
        let mut interval = tokio::time::interval(Duration::from_millis(50));

        loop {
            interval.tick().await;
            // Regenerate transaction ID periodically for variety
            for i in 0..12 {
                transaction_id[i] = rand::random();
            }
            packet[8..20].copy_from_slice(&transaction_id);

            if let Err(e) = socket.send_to(&packet, remote_addr) {
                debug!("Keep-alive send failed: {}", e);
                break;
            }
        }
    })
}

/// Skip server certificate verification (for development only)
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Perform STUN-based hole punching with retry logic and random jitter
///
/// Sends STUN Binding Requests to the remote address while listening for
/// incoming requests. Returns the socket on success so it can be reused for QUIC.
/// This is critical - we must keep the same socket to preserve the NAT mapping.
///
/// Uses random jitter to avoid synchronized packet collisions between peers.
async fn stun_hole_punch(
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
    timeout: Duration,
) -> Result<(bool, UdpSocket), BoxError> {
    use byteorder::{BigEndian, ByteOrder};

    // STUN constants
    const STUN_BINDING_REQUEST: u16 = 0x0001;
    const STUN_BINDING_RESPONSE: u16 = 0x0101;
    const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
    const STUN_HEADER_SIZE: usize = 20;

    // Create UDP socket - bind to the same port we'll use for QUIC
    // so the NAT mapping applies to both STUN and QUIC traffic
    let socket = UdpSocket::bind(local_addr).await
        .map_err(|e| format!("Failed to bind hole punch socket: {}", e))?;

    info!("Hole punch socket bound to {}", socket.local_addr()?);

    // Generate a random transaction ID
    let mut transaction_id = [0u8; 12];
    for i in 0..12 {
        transaction_id[i] = rand::random();
    }

    // Build STUN Binding Request
    let mut request = [0u8; STUN_HEADER_SIZE];
    BigEndian::write_u16(&mut request[0..2], STUN_BINDING_REQUEST);
    BigEndian::write_u16(&mut request[2..4], 0); // Message length (no attributes)
    BigEndian::write_u32(&mut request[4..8], STUN_MAGIC_COOKIE);
    request[8..20].copy_from_slice(&transaction_id);

    let start = std::time::Instant::now();
    let mut recv_buf = [0u8; 1024];
    let mut request_sent = 0;
    let mut response_received = false;
    let mut request_received = false;

    // Send interval - no jitter, we want predictable timing
    let send_interval = Duration::from_millis(50);

    info!("Starting STUN hole punch loop (timeout: {:?})", timeout);

    // Send an initial burst of packets immediately to punch the hole ASAP
    // This is critical - we need to create the outbound NAT mapping before
    // the other peer's packets arrive and create an inbound-only entry
    info!("Sending initial burst of 5 packets to punch hole");
    for i in 0..5 {
        socket.send_to(&request, remote_addr).await?;
        request_sent += 1;
        debug!("Sent initial burst packet #{} to {}", i + 1, remote_addr);
        // Very short delay between burst packets
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    let mut last_send = std::time::Instant::now();

    while start.elapsed() < timeout {
        // Send STUN Binding Request periodically
        if last_send.elapsed() >= send_interval {
            socket.send_to(&request, remote_addr).await?;
            request_sent += 1;
            if request_sent <= 5 || request_sent % 10 == 0 {
                debug!("Sent STUN Binding Request #{} to {}", request_sent, remote_addr);
            }
            last_send = std::time::Instant::now();
        }

        // Try to receive with short timeout
        let recv_result = tokio::time::timeout(
            Duration::from_millis(30),
            socket.recv_from(&mut recv_buf)
        ).await;

        if let Ok(Ok((len, from))) = recv_result {
            debug!("Received {} bytes from {}", len, from);
            if len >= STUN_HEADER_SIZE {
                let msg_type = BigEndian::read_u16(&recv_buf[0..2]);
                let magic = BigEndian::read_u32(&recv_buf[4..8]);
                debug!("msg_type=0x{:04x}, magic=0x{:08x}", msg_type, magic);

                if magic == STUN_MAGIC_COOKIE {
                    match msg_type {
                        STUN_BINDING_REQUEST => {
                            info!("Received STUN Binding Request from {}", from);
                            request_received = true;

                            // Send Binding Response immediately - multiple times for reliability
                            let mut response = [0u8; STUN_HEADER_SIZE];
                            BigEndian::write_u16(&mut response[0..2], STUN_BINDING_RESPONSE);
                            BigEndian::write_u16(&mut response[2..4], 0);
                            BigEndian::write_u32(&mut response[4..8], STUN_MAGIC_COOKIE);
                            response[8..20].copy_from_slice(&recv_buf[8..20]); // Echo transaction ID

                            // Send response multiple times for reliability
                            for i in 0..3 {
                                socket.send_to(&response, from).await?;
                                if i < 2 {
                                    // Small delay between retries
                                    tokio::time::sleep(Duration::from_millis(10)).await;
                                }
                            }
                            debug!("Sent STUN Binding Response to {} (3x)", from);
                        }
                        STUN_BINDING_RESPONSE => {
                            // Check if this is a response to our request
                            if &recv_buf[8..20] == &transaction_id {
                                info!("Received STUN Binding Response from {} - connectivity confirmed!", from);
                                response_received = true;
                            } else {
                                debug!("Received STUN Response with different transaction ID from {}", from);
                            }
                        }
                        _ => {
                            debug!("Received unknown STUN message type 0x{:04x} from {}", msg_type, from);
                        }
                    }
                }
            }
        }

        // Success: we've received a response confirming bidirectional connectivity
        if response_received {
            info!("STUN hole punch successful after {} requests", request_sent);
            // Continue sending for a bit to help the other side also confirm
            let confirmation_end = std::time::Instant::now() + Duration::from_millis(500);
            while std::time::Instant::now() < confirmation_end {
                socket.send_to(&request, remote_addr).await?;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            return Ok((true, socket));
        }

        // If we've received requests, we know the other side can reach us
        // After enough requests, exit early - the hole is punched
        if request_received && request_sent > 20 {
            info!("Received requests and sent {} - hole punched, exiting early", request_sent);
            // Send a few more packets then exit
            for _ in 0..5 {
                socket.send_to(&request, remote_addr).await?;
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            return Ok((true, socket));
        }
    }

    warn!("STUN hole punch timed out after {} requests (response_received: {}, request_received: {})",
          request_sent, response_received, request_received);

    // If we received requests but no responses, the hole might still be punched
    // (the other side might have received our response)
    if request_received {
        info!("Received requests but no responses - hole may be partially punched, proceeding...");
        return Ok((true, socket));
    }

    Ok((false, socket))
}
