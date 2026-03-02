use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use stoffelnet::network_utils::NodePublicKey;
use stoffelnet::transports::ice::{CandidatePair, CandidateType, IceCandidate, LocalCandidates};
use stoffelnet::transports::net_envelope::NetEnvelope;
use stoffelnet::transports::quic::{LoopbackPeerConnection, PeerConnection};
use stoffelnet::transports::stun::{detect_symmetric_nat, StunBindingResult, StunClient, StunServerConfig};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

fn addr(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

// =============================================================================
// Group 1: NetEnvelope Serialization
// =============================================================================

fn bench_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialization");

    // 1. serialize_handshake
    group.bench_function("serialize_handshake", |b| {
        let envelope = NetEnvelope::Handshake { id: 42 };
        b.iter(|| {
            black_box(envelope.serialize());
        });
    });

    // 2. deserialize_handshake
    group.bench_function("deserialize_handshake", |b| {
        let bytes = NetEnvelope::Handshake { id: 42 }.serialize();
        b.iter(|| {
            black_box(NetEnvelope::try_deserialize(black_box(&bytes)).unwrap());
        });
    });

    // 3. serialize_honeybadger_64b
    group.bench_function("serialize_honeybadger_64b", |b| {
        let payload = vec![0xABu8; 64];
        let envelope = NetEnvelope::HoneyBadger(payload);
        b.iter(|| {
            black_box(envelope.serialize());
        });
    });

    // 4. serialize_honeybadger_1kb
    group.bench_function("serialize_honeybadger_1kb", |b| {
        let payload = vec![0xABu8; 1024];
        let envelope = NetEnvelope::HoneyBadger(payload);
        b.iter(|| {
            black_box(envelope.serialize());
        });
    });

    // 5. serialize_honeybadger_64kb
    group.bench_function("serialize_honeybadger_64kb", |b| {
        let payload = vec![0xABu8; 65536];
        let envelope = NetEnvelope::HoneyBadger(payload);
        b.iter(|| {
            black_box(envelope.serialize());
        });
    });

    // 6. deserialize_honeybadger_64kb
    group.bench_function("deserialize_honeybadger_64kb", |b| {
        let bytes = NetEnvelope::HoneyBadger(vec![0xABu8; 65536]).serialize();
        b.iter(|| {
            black_box(NetEnvelope::try_deserialize(black_box(&bytes)).unwrap());
        });
    });

    // 7. serialize_ice_candidates_10
    group.bench_function("serialize_ice_candidates_10", |b| {
        let candidates: Vec<IceCandidate> = (0..10)
            .map(|i| IceCandidate::host(addr(5000 + i), 1))
            .collect();
        let envelope = NetEnvelope::IceCandidates {
            ufrag: "abcd".to_string(),
            pwd: "secret_password_long_enough".to_string(),
            candidates,
        };
        b.iter(|| {
            black_box(envelope.serialize());
        });
    });

    // 8. round_trip_connectivity_check
    group.bench_function("round_trip_connectivity_check", |b| {
        let envelope = NetEnvelope::ConnectivityCheck {
            transaction_id: 12345,
            is_response: false,
            use_candidate: true,
            ufrag: "testufrag".to_string(),
        };
        b.iter(|| {
            let bytes = envelope.serialize();
            let decoded = NetEnvelope::try_deserialize(&bytes).unwrap();
            black_box(decoded);
        });
    });

    group.finish();
}

// =============================================================================
// Group 2: Loopback Throughput
// =============================================================================

fn bench_loopback(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("loopback");

    // 9-12. loopback_send_receive at various sizes
    for size in [64, 1024, 65536, 1_048_576] {
        let data = vec![0xABu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::new("send_receive", size),
            &data,
            |b, data| {
                // Create connection outside the hot loop to measure only send/receive
                let conn = LoopbackPeerConnection::new(addr(9999), Some(0));
                b.iter(|| {
                    rt.block_on(async {
                        conn.send(black_box(data)).await.unwrap();
                        let received = conn.receive().await.unwrap();
                        black_box(received);
                    });
                });
            },
        );
    }

    // 13. loopback_throughput_1000_msgs
    group.throughput(Throughput::Elements(1000));
    group.sample_size(50);
    group.bench_function("throughput_1000_msgs_64b", |b| {
        let data = vec![0xABu8; 64];
        let conn = LoopbackPeerConnection::new(addr(9999), Some(0));
        b.iter(|| {
            rt.block_on(async {
                for _ in 0..1000 {
                    conn.send(black_box(&data)).await.unwrap();
                }
                for _ in 0..1000 {
                    let received = conn.receive().await.unwrap();
                    black_box(received);
                }
            });
        });
    });

    group.finish();
}

// =============================================================================
// Group 3: ICE Operations
// =============================================================================

fn bench_ice(c: &mut Criterion) {
    let mut group = c.benchmark_group("ice");

    // 14. ice_priority_host
    group.bench_function("priority_host", |b| {
        b.iter(|| {
            black_box(IceCandidate::calculate_priority(
                black_box(CandidateType::Host),
                black_box(65535),
                black_box(1),
            ));
        });
    });

    // 15. ice_priority_srflx
    group.bench_function("priority_srflx", |b| {
        b.iter(|| {
            black_box(IceCandidate::calculate_priority(
                black_box(CandidateType::ServerReflexive),
                black_box(65535),
                black_box(1),
            ));
        });
    });

    // 16. ice_pair_priority
    group.bench_function("pair_priority", |b| {
        b.iter(|| {
            black_box(CandidatePair::calculate_pair_priority(
                black_box(1000),
                black_box(2000),
            ));
        });
    });

    // 17. ice_pair_formation_10x10
    group.bench_function("pair_formation_10x10", |b| {
        let locals: Vec<IceCandidate> = (0..10)
            .map(|i| {
                IceCandidate::host(
                    SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(192, 168, 1, i as u8)),
                        5000 + i,
                    ),
                    1,
                )
            })
            .collect();
        let remotes: Vec<IceCandidate> = (0..10)
            .map(|i| {
                IceCandidate::host(
                    SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(10, 0, 0, i as u8)),
                        6000 + i,
                    ),
                    1,
                )
            })
            .collect();
        b.iter(|| {
            black_box(CandidatePair::form_pairs(
                black_box(&locals),
                black_box(&remotes),
                true,
            ));
        });
    });

    // 18. ice_pair_formation_50x50
    group.bench_function("pair_formation_50x50", |b| {
        let locals: Vec<IceCandidate> = (0..50)
            .map(|i| {
                IceCandidate::host(
                    SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(192, 168, (i / 256) as u8, (i % 256) as u8)),
                        5000 + i,
                    ),
                    1,
                )
            })
            .collect();
        let remotes: Vec<IceCandidate> = (0..50)
            .map(|i| {
                IceCandidate::host(
                    SocketAddr::new(
                        IpAddr::V4(Ipv4Addr::new(10, 0, (i / 256) as u8, (i % 256) as u8)),
                        6000 + i,
                    ),
                    1,
                )
            })
            .collect();
        b.iter(|| {
            black_box(CandidatePair::form_pairs(
                black_box(&locals),
                black_box(&remotes),
                true,
            ));
        });
    });

    // 19. ice_candidate_host_creation
    group.bench_function("candidate_host_creation", |b| {
        let address = addr(5000);
        b.iter(|| {
            black_box(IceCandidate::host(black_box(address), black_box(1)));
        });
    });

    // 20. ice_local_candidates_add_10
    group.bench_function("local_candidates_add_10", |b| {
        b.iter(|| {
            let mut lc = LocalCandidates::new();
            for i in 0..10u16 {
                lc.add_host(addr(5000 + i));
            }
            black_box(lc);
        });
    });

    group.finish();
}

// =============================================================================
// Group 4: STUN Operations
// =============================================================================

fn bench_stun(c: &mut Criterion) {
    let mut group = c.benchmark_group("stun");

    // 21. stun_client_creation_3_servers
    group.bench_function("client_creation_3_servers", |b| {
        let servers = vec![
            StunServerConfig::new("74.125.250.129:19302".parse().unwrap()),
            StunServerConfig::new("8.8.8.8:3478".parse().unwrap()),
            StunServerConfig::new("1.1.1.1:3478".parse().unwrap()),
        ];
        b.iter(|| {
            black_box(StunClient::new(black_box(servers.clone())));
        });
    });

    // 22. stun_detect_symmetric_nat
    group.bench_function("detect_symmetric_nat_5_results", |b| {
        let results: Vec<StunBindingResult> = (0..5)
            .map(|i| StunBindingResult {
                reflexive_address: SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                    12345 + i,
                ),
                server_address: SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(8, 8, 8, i as u8)),
                    3478,
                ),
                rtt: Duration::from_millis(50),
            })
            .collect();
        b.iter(|| {
            black_box(detect_symmetric_nat(black_box(&results)));
        });
    });

    group.finish();
}

// =============================================================================
// Group 5: NodePublicKey ID derivation (FNV-1a hash)
// =============================================================================

fn bench_crypto(c: &mut Criterion) {
    let mut group = c.benchmark_group("node_id_derivation");

    // 23. node_public_key_derive_id_small (32 bytes)
    group.bench_function("derive_id_32b", |b| {
        let key = NodePublicKey(vec![0u8; 32]);
        b.iter(|| {
            black_box(black_box(&key).derive_id());
        });
    });

    // 24. node_public_key_derive_id_large (4096 bytes)
    group.bench_function("derive_id_4096b", |b| {
        let key = NodePublicKey(vec![0u8; 4096]);
        b.iter(|| {
            black_box(black_box(&key).derive_id());
        });
    });

    group.finish();
}

// =============================================================================
// Group 6: NetEnvelope variant serialization
// =============================================================================

fn bench_envelope_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("envelope_variants");

    // 25. serialize_relay_data_64b
    group.bench_function("serialize_relay_data_64b", |b| {
        let envelope = NetEnvelope::RelayedData {
            target_party_id: 1,
            source_party_id: 2,
            payload: vec![0xCDu8; 64],
        };
        b.iter(|| {
            black_box(envelope.serialize());
        });
    });

    // 26. serialize_relay_data_1kb
    group.bench_function("serialize_relay_data_1kb", |b| {
        let envelope = NetEnvelope::RelayedData {
            target_party_id: 1,
            source_party_id: 2,
            payload: vec![0xCDu8; 1024],
        };
        b.iter(|| {
            black_box(envelope.serialize());
        });
    });

    // 27. serialize_punch_request
    group.bench_function("serialize_punch_request", |b| {
        let envelope = NetEnvelope::PunchRequest {
            transaction_id: 99999,
            target_address: addr(8080),
            delay_ms: 50,
        };
        b.iter(|| {
            black_box(envelope.serialize());
        });
    });

    // 28. serialize_relay_offer
    group.bench_function("serialize_relay_offer", |b| {
        let envelope = NetEnvelope::RelayOffer {
            relay_address: addr(9090),
            allocation_token: vec![0xEFu8; 32],
            for_party_id: 7,
        };
        b.iter(|| {
            black_box(envelope.serialize());
        });
    });

    group.finish();
}

// =============================================================================
// Criterion harness
// =============================================================================

criterion_group!(
    benches,
    bench_serialization,
    bench_loopback,
    bench_ice,
    bench_stun,
    bench_crypto,
    bench_envelope_sizes,
);
criterion_main!(benches);
