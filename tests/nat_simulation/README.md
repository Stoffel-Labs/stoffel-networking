# Full-cone NAT integration test

Run from the repository root with Docker and Docker Compose installed:

```sh
COMPOSE_PROJECT_NAME=stoffel-cone-nat bash tests/nat_simulation/run_test.sh
```

The runner builds the three test binaries from the isolated, locked Cargo package
in this directory. It starts two peers on separate private networks, two NAT
routers, a signaling server and a STUN server. Both peers reuse their UDP socket
on port 5000 for STUN and QUIC.

The public and private Docker bridges disable Docker masquerading: translation
belongs to the two router containers. Docker masquerading on the public bridge
can otherwise rewrite the remote address a second time and break QUIC handshakes.
The routers use fixed-port SNAT and unrestricted-source DNAT to model full-cone
NAT. Established replies may use conntrack reverse SNAT rather than incrementing
the explicit DNAT rule.

Success requires both peers to exit successfully, discover the expected public
STUN addresses, exchange a QUIC payload round trip with the other public address, and produce nonzero SNAT and
inbound/outbound forwarding counters on both routers. Logs and counters are saved
under `tests/nat_simulation/logs/`.

Use `--verbose` for build and progress output, `--timeout 180` to change the peer
run deadline, or `--keep` to retain containers after success or failure. To remove
retained containers:

```sh
COMPOSE_PROJECT_NAME=stoffel-cone-nat docker compose -f tests/nat_simulation/docker-compose.yml down --volumes
```

This is a controlled local full-cone simulation. It does not cover symmetric NAT,
CGNAT, or arbitrary Internet firewall policies. Certificates are self-signed and
the peer verifier is deliberately test-only.
