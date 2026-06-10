use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::Once;
use stoffelnet::network_utils::{Message, NetworkError, Node, NodePublicKey};
use stoffelnet::transports::quic::{
    ConnectionState, LoopbackPeerConnection, NetworkManager, PeerConnection, QuicMessage,
    QuicNetworkConfig, QuicNetworkManager, QuicNode,
};

static CRYPTO_INIT: Once = Once::new();

fn init_crypto() {
    CRYPTO_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

fn unused_localhost_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind(localhost(0)).expect("should allocate local port");
    listener
        .local_addr()
        .expect("listener should expose local address")
}

// ============================================================================
// LoopbackPeerConnection integration tests
// ============================================================================

#[tokio::test]
async fn test_loopback_full_lifecycle() {
    let addr = localhost(9000);
    let loopback = LoopbackPeerConnection::new(addr, Some(1));

    // Initial state should be Connected
    let state = loopback.state().await;
    assert_eq!(state, ConnectionState::Connected);
    assert!(loopback.is_connected().await);

    // Send data
    let payload = b"hello loopback";
    loopback.send(payload).await.expect("send should succeed");

    // Receive data
    let received = loopback.receive().await.expect("receive should succeed");
    assert_eq!(received, payload.to_vec());

    // Close the connection
    loopback.close().await.expect("close should succeed");

    // State should now be Closed
    let state = loopback.state().await;
    assert_eq!(state, ConnectionState::Closed);
    assert!(!loopback.is_connected().await);
}

#[tokio::test]
async fn test_loopback_fifo_message_ordering() {
    let addr = localhost(9001);
    let loopback = LoopbackPeerConnection::new(addr, Some(2));

    // Send 5 distinct messages
    let messages: Vec<Vec<u8>> = (0u8..5)
        .map(|i| format!("message number {}", i).into_bytes())
        .collect();

    for msg in &messages {
        loopback.send(msg).await.expect("send should succeed");
    }

    // Receive all 5 and verify order is preserved (FIFO)
    for expected in &messages {
        let received = loopback.receive().await.expect("receive should succeed");
        assert_eq!(&received, expected, "messages should arrive in FIFO order");
    }
}

#[tokio::test]
async fn test_loopback_large_message() {
    let addr = localhost(9002);
    let loopback = LoopbackPeerConnection::new(addr, Some(3));

    // 1 MB payload
    let payload = vec![0xABu8; 1024 * 1024];
    loopback
        .send(&payload)
        .await
        .expect("send of 1MB should succeed");

    let received = loopback
        .receive()
        .await
        .expect("receive of 1MB should succeed");
    assert_eq!(
        received, payload,
        "received content should match sent content"
    );
}

#[tokio::test]
async fn test_loopback_empty_message() {
    let addr = localhost(9003);
    let loopback = LoopbackPeerConnection::new(addr, Some(4));

    loopback
        .send(&[])
        .await
        .expect("send of empty message should succeed");

    let received = loopback
        .receive()
        .await
        .expect("receive of empty message should succeed");
    assert!(received.is_empty(), "received data should be empty");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_loopback_concurrent_senders() {
    let addr = localhost(9004);
    let loopback = Arc::new(LoopbackPeerConnection::new(addr, Some(5)));

    let num_tasks = 10usize;

    // Spawn receiver concurrently with senders to exercise actual contention
    let recv_conn = Arc::clone(&loopback);
    let receiver = tokio::spawn(async move {
        let mut received_messages: Vec<String> = Vec::new();
        for _ in 0..num_tasks {
            let data = recv_conn.receive().await.expect("receive should succeed");
            let msg = String::from_utf8(data).expect("message should be valid UTF-8");
            received_messages.push(msg);
        }
        received_messages
    });

    // Spawn senders
    let mut handles = Vec::new();
    for i in 0..num_tasks {
        let conn = Arc::clone(&loopback);
        let msg = format!("concurrent-{}", i).into_bytes();
        let handle = tokio::spawn(async move {
            conn.send(&msg)
                .await
                .expect("concurrent send should succeed");
        });
        handles.push(handle);
    }

    // Wait for all senders to complete
    for handle in handles {
        handle.await.expect("task should not panic");
    }

    // Collect received messages and verify completeness (order may vary)
    let mut received_messages = receiver.await.expect("receiver should not panic");
    received_messages.sort();
    let mut expected: Vec<String> = (0..num_tasks)
        .map(|i| format!("concurrent-{}", i))
        .collect();
    expected.sort();

    assert_eq!(
        received_messages, expected,
        "all unique messages should be received"
    );
}

// ============================================================================
// QuicNetworkManager tests (via public API only)
// ============================================================================

#[tokio::test]
async fn test_manager_certificate_generation() {
    init_crypto();

    // Listening triggers certificate generation internally.
    let mut manager = QuicNetworkManager::new();
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    manager
        .listen(addr)
        .await
        .expect("listen should succeed and generate certificate");

    // The manager should have a public key available after listen
    let public_key = manager.get_public_key();
    assert!(
        public_key.is_some(),
        "after listen, the manager should have a public key from the generated certificate"
    );

    // Public key should remain stable across calls
    let public_key_again = manager.get_public_key();
    assert_eq!(
        public_key, public_key_again,
        "public key should remain stable across calls"
    );
}

#[tokio::test]
async fn test_certificate_public_key_allowlist_accepts_expected_server_peer() {
    init_crypto();

    let mut listener = QuicNetworkManager::with_node_id(1);
    let mut connector = QuicNetworkManager::with_node_id(2);
    let listener_addr = unused_localhost_addr();
    let connector_addr = unused_localhost_addr();

    listener
        .listen(listener_addr)
        .await
        .expect("listener should start");
    connector
        .listen(connector_addr)
        .await
        .expect("connector should start so its certificate key is available");

    let connector_key = connector
        .get_public_key()
        .expect("connector should expose a certificate public key")
        .clone();

    listener.set_allowed_certificate_public_keys(vec![connector_key.clone()]);

    let connect_task = tokio::spawn(async move {
        let result = connector.connect_as_server(listener_addr).await;
        (connector, result)
    });

    let accept_result = listener.accept().await;
    let (connector, connect_result) = connect_task.await.expect("connect task should not panic");

    assert!(
        accept_result.is_ok(),
        "listener should accept an allowlisted certificate public key: {:?}",
        accept_result.err()
    );
    assert!(
        connect_result.is_ok(),
        "connector should establish the server-role connection: {:?}",
        connect_result.err()
    );

    let connector_id = connector
        .get_public_key()
        .expect("connector key should still be available")
        .derive_id();
    assert_eq!(
        listener.peer_public_key_bytes(connector_id),
        Some(connector_key.0),
        "listener should store the accepted peer key under its derived transport ID"
    );
}

#[tokio::test]
async fn test_certificate_public_key_allowlist_rejects_unexpected_server_peer() {
    init_crypto();

    let mut listener = QuicNetworkManager::with_node_id(1);
    listener.add_allowed_certificate_public_key(NodePublicKey(vec![0xAA, 0xBB, 0xCC]));
    let listener_addr = unused_localhost_addr();
    listener
        .listen(listener_addr)
        .await
        .expect("listener should start");

    let connect_task = tokio::spawn(async move {
        let mut unexpected_peer = QuicNetworkManager::with_node_id(2);
        unexpected_peer.connect_as_server(listener_addr).await
    });

    let accept_result = listener.accept().await;
    let _connect_result = connect_task.await.expect("connect task should not panic");

    assert!(
        accept_result.is_err(),
        "listener should reject a certificate public key outside the allowlist"
    );
    assert!(
        accept_result.unwrap_err().contains("not in allowlist"),
        "rejection should report the allowlist failure"
    );
    assert!(
        listener.get_all_server_connections().len() <= 1,
        "rejected peer should not be retained as a server connection"
    );
}

#[tokio::test]
async fn test_certificate_public_key_allowlist_clear_disables_rejection() {
    init_crypto();

    let mut listener = QuicNetworkManager::with_node_id(1);
    listener.add_allowed_certificate_public_key(NodePublicKey(vec![0xAA, 0xBB, 0xCC]));
    assert!(listener.has_certificate_public_key_allowlist());
    listener.clear_allowed_certificate_public_keys();
    assert!(!listener.has_certificate_public_key_allowlist());

    let mut config = QuicNetworkConfig::default();
    config.use_tls = false;
    let mut listener = QuicNetworkManager::with_config(config.clone());
    listener.add_allowed_certificate_public_key(NodePublicKey(vec![0xAA, 0xBB, 0xCC]));
    listener.clear_allowed_certificate_public_keys();
    let listener_addr = unused_localhost_addr();
    listener
        .listen(listener_addr)
        .await
        .expect("listener should start");

    let connect_task = tokio::spawn(async move {
        let mut connector = QuicNetworkManager::with_config(config);
        let result = connector.connect_as_server(listener_addr).await;
        (connector, result)
    });

    let accept_result = listener.accept().await;
    let (_connector, connect_result) = connect_task.await.expect("connect task should not panic");

    assert!(
        accept_result.is_ok(),
        "clearing the allowlist should disable certificate public key rejection: {:?}",
        accept_result.err()
    );
    assert!(
        connect_result.is_ok(),
        "connector should succeed once the allowlist is cleared: {:?}",
        connect_result.err()
    );
}

#[test]
fn test_node_creation_from_party_id() {
    let addr = localhost(5000);
    let node = QuicNode::from_party_id(5, addr);

    assert_eq!(node.id(), 5, "Node::id() should return the party ID");
    assert_eq!(
        node.address(),
        addr,
        "address() should return the bound address"
    );
}

#[test]
fn test_quic_message_getters() {
    let content = vec![10, 20, 30, 40];
    let msg = QuicMessage::new(7, content.clone());

    assert_eq!(
        msg.sender_id(),
        7,
        "sender_id should match what was passed to new()"
    );
    assert_eq!(
        msg.content(),
        &content[..],
        "content() should return the original content"
    );
    assert_eq!(
        msg.bytes(),
        msg.content(),
        "bytes() should be identical to content()"
    );
}

// ============================================================================
// Network config tests
// ============================================================================

#[test]
fn test_default_config_values() {
    let config = QuicNetworkConfig::default();

    assert_eq!(
        config.timeout_ms, 30000,
        "default timeout_ms should be 30000"
    );
    assert_eq!(
        config.idle_timeout_ms, 300_000,
        "default idle_timeout_ms should be 300000"
    );
    assert_eq!(config.max_retries, 3, "default max_retries should be 3");
    assert!(config.use_tls, "default use_tls should be true");
    assert!(
        !config.enable_nat_traversal,
        "default enable_nat_traversal should be false"
    );
    assert!(
        config.stun_servers.is_empty(),
        "default stun_servers should be empty"
    );
    assert!(
        config.enable_hole_punching,
        "default enable_hole_punching should be true"
    );
    assert_eq!(
        config.hole_punch_timeout_ms, 10000,
        "default hole_punch_timeout_ms should be 10000"
    );
}

#[test]
fn test_config_with_nat_traversal() {
    let config = QuicNetworkConfig::with_nat_traversal();

    assert!(
        config.enable_nat_traversal,
        "with_nat_traversal() should set enable_nat_traversal to true"
    );
    // Verify all other fields remain at defaults
    assert_eq!(config.timeout_ms, 30000);
    assert_eq!(config.max_retries, 3);
    assert!(config.use_tls);
    assert!(config.stun_servers.is_empty());
    assert!(config.enable_hole_punching);
    assert_eq!(config.hole_punch_timeout_ms, 10000);
}

// ============================================================================
// Error handling
// ============================================================================

#[test]
fn test_network_error_display_contains_relevant_info() {
    // Verify specific messages contain meaningful content
    let send_err = format!("{}", NetworkError::SendError);
    assert!(
        send_err.to_lowercase().contains("sent") || send_err.to_lowercase().contains("send"),
        "SendError display should mention sending: got '{}'",
        send_err
    );

    let timeout_err = format!("{}", NetworkError::Timeout);
    assert!(
        timeout_err.to_lowercase().contains("timeout"),
        "Timeout display should mention timeout: got '{}'",
        timeout_err
    );

    let party_err = format!("{}", NetworkError::PartyNotFound(42));
    assert!(
        party_err.contains("42"),
        "PartyNotFound display should include the party ID: got '{}'",
        party_err
    );

    let client_err = format!("{}", NetworkError::ClientNotFound(99));
    assert!(
        client_err.contains("99"),
        "ClientNotFound display should include the client ID: got '{}'",
        client_err
    );
}
