//! Signaling Server for NAT Hole Punching Tests
//!
//! This server facilitates ICE candidate exchange between peers during NAT traversal.
//! It uses a simple TCP-based protocol where peers:
//! 1. Register with their peer ID
//! 2. Send ICE candidates
//! 3. Receive candidates from the other peer
//! 4. Coordinate hole punching timing

use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

/// Message types for signaling protocol
#[derive(Debug, Clone)]
enum SignalingMessage {
    /// Peer registration: REGISTER <peer_id>
    Register { peer_id: usize },
    /// ICE candidates: CANDIDATES <json_candidates>
    Candidates { from_peer: usize, candidates_json: String },
    /// Ready to punch: READY <peer_id>
    Ready { peer_id: usize },
    /// Start hole punch: START <timestamp_ms>
    Start { timestamp_ms: u64 },
    /// Connection result: RESULT <success|failure> <message>
    Result { success: bool, message: String },
}

/// Shared state for the signaling server
struct ServerState {
    /// Registered peers: peer_id -> sender channel
    peers: HashMap<usize, tokio::sync::mpsc::Sender<String>>,
    /// Stored candidates per peer
    candidates: HashMap<usize, String>,
    /// Peers that are ready for hole punching
    ready_peers: Vec<usize>,
    /// Peers that have completed STUN hole punching (Option B)
    hole_punched_peers: Vec<usize>,
    /// Test results
    results: Vec<(usize, bool, String)>,
}

impl ServerState {
    fn new() -> Self {
        Self {
            peers: HashMap::new(),
            candidates: HashMap::new(),
            ready_peers: Vec::new(),
            hole_punched_peers: Vec::new(),
            results: Vec::new(),
        }
    }
}

type SharedState = Arc<Mutex<ServerState>>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("signaling=debug".parse().unwrap()),
        )
        .init();

    let bind_addr = env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:9000".to_string());
    let addr: SocketAddr = bind_addr.parse()?;

    let listener = TcpListener::bind(addr).await?;
    info!("Signaling server listening on {}", addr);

    let state: SharedState = Arc::new(Mutex::new(ServerState::new()));

    loop {
        let (socket, peer_addr) = listener.accept().await?;
        info!("New connection from {}", peer_addr);

        let state_clone = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(socket, peer_addr, state_clone).await {
                error!("Connection error from {}: {}", peer_addr, e);
            }
        });
    }
}

async fn handle_connection(
    socket: TcpStream,
    peer_addr: SocketAddr,
    state: SharedState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (reader, mut writer) = socket.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    // Create a channel for sending messages to this peer
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(100);

    let mut peer_id: Option<usize> = None;

    // Spawn a task to forward messages from channel to socket
    let writer_handle = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if writer.write_all(msg.as_bytes()).await.is_err() {
                break;
            }
            if writer.write_all(b"\n").await.is_err() {
                break;
            }
            let _ = writer.flush().await;
        }
    });

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).await?;
        if bytes_read == 0 {
            info!("Connection closed from {}", peer_addr);
            break;
        }

        let line = line.trim();
        debug!("Received from {}: {}", peer_addr, line);

        // Parse the message
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        let command = parts.get(0).unwrap_or(&"");
        let payload = parts.get(1).unwrap_or(&"");

        match *command {
            "REGISTER" => {
                let id: usize = payload.parse()?;
                peer_id = Some(id);

                let mut state = state.lock().await;
                state.peers.insert(id, tx.clone());
                info!("Peer {} registered from {}", id, peer_addr);

                // Send the peer its apparent (NAT-translated) address
                // This acts like a lightweight STUN response
                let reflexive_msg = format!("REFLEXIVE {}", peer_addr.ip());
                let _ = tx.send(reflexive_msg).await;
                info!("Sent reflexive address {} to peer {}", peer_addr.ip(), id);

                // Send any existing candidates from other peers
                for (other_id, candidates) in &state.candidates {
                    if *other_id != id {
                        let msg = format!("CANDIDATES {} {}", other_id, candidates);
                        let _ = tx.send(msg).await;
                    }
                }

                // Notify about ready peers
                for ready_id in &state.ready_peers {
                    if *ready_id != id {
                        let msg = format!("PEER_READY {}", ready_id);
                        let _ = tx.send(msg).await;
                    }
                }
            }

            "CANDIDATES" => {
                if let Some(id) = peer_id {
                    let mut state = state.lock().await;
                    state.candidates.insert(id, payload.to_string());
                    info!("Stored candidates from peer {}", id);

                    // Forward to other peers
                    let msg = format!("CANDIDATES {} {}", id, payload);
                    for (other_id, sender) in &state.peers {
                        if *other_id != id {
                            let _ = sender.send(msg.clone()).await;
                        }
                    }
                }
            }

            "READY" => {
                if let Some(id) = peer_id {
                    let mut state = state.lock().await;
                    if !state.ready_peers.contains(&id) {
                        state.ready_peers.push(id);
                        info!("Peer {} is ready", id);

                        // Notify other peers
                        let msg = format!("PEER_READY {}", id);
                        for (other_id, sender) in &state.peers {
                            if *other_id != id {
                                let _ = sender.send(msg.clone()).await;
                            }
                        }

                        // If we have 2 ready peers, start the hole punch
                        if state.ready_peers.len() >= 2 {
                            let timestamp = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_millis() as u64;

                            // Schedule start 500ms in the future for synchronization
                            let start_time = timestamp + 500;
                            let start_msg = format!("START {}", start_time);

                            info!("Starting hole punch at timestamp {}", start_time);

                            for sender in state.peers.values() {
                                let _ = sender.send(start_msg.clone()).await;
                            }
                        }
                    }
                }
            }

            // Option B: HOLE_PUNCHED message - peer has completed STUN hole punching
            "HOLE_PUNCHED" => {
                if let Some(id) = peer_id {
                    let mut state = state.lock().await;
                    if !state.hole_punched_peers.contains(&id) {
                        state.hole_punched_peers.push(id);
                        info!("Peer {} completed hole punch", id);

                        // Notify other peers
                        let msg = format!("PEER_HOLE_PUNCHED {}", id);
                        for (other_id, sender) in &state.peers {
                            if *other_id != id {
                                let _ = sender.send(msg.clone()).await;
                            }
                        }

                        // If both peers have hole punched, tell them to proceed to QUIC
                        if state.hole_punched_peers.len() >= 2 {
                            info!("Both peers have hole punched, signaling START_QUIC");
                            for sender in state.peers.values() {
                                let _ = sender.send("START_QUIC".to_string()).await;
                            }
                        }
                    }
                }
            }

            "RESULT" => {
                if let Some(id) = peer_id {
                    let result_parts: Vec<&str> = payload.splitn(2, ' ').collect();
                    let success = result_parts.get(0).unwrap_or(&"false") == &"success";
                    let message = result_parts.get(1).unwrap_or(&"").to_string();

                    let mut state = state.lock().await;
                    state.results.push((id, success, message.clone()));
                    info!("Peer {} result: {} - {}", id, success, message);

                    // Forward result to other peers
                    let msg = format!("PEER_RESULT {} {} {}", id, if success { "success" } else { "failure" }, message);
                    for (other_id, sender) in &state.peers {
                        if *other_id != id {
                            let _ = sender.send(msg.clone()).await;
                        }
                    }

                    // Check if test is complete
                    if state.results.len() >= 2 {
                        let all_success = state.results.iter().all(|(_, s, _)| *s);
                        let status_msg = if all_success {
                            "TEST_COMPLETE success"
                        } else {
                            "TEST_COMPLETE failure"
                        };

                        for sender in state.peers.values() {
                            let _ = sender.send(status_msg.to_string()).await;
                        }

                        info!("Test complete: {}", if all_success { "SUCCESS" } else { "FAILURE" });
                    }
                }
            }

            "PING" => {
                let _ = tx.send("PONG".to_string()).await;
            }

            _ => {
                warn!("Unknown command from {}: {}", peer_addr, command);
            }
        }
    }

    // Cleanup
    if let Some(id) = peer_id {
        let mut state = state.lock().await;
        state.peers.remove(&id);
        state.ready_peers.retain(|&x| x != id);
        info!("Peer {} disconnected", id);
    }

    writer_handle.abort();
    Ok(())
}
