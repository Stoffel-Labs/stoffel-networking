#!/bin/bash
# NAT Hole Punching Integration Test Runner
#
# This script:
# 1. Builds the Docker images
# 2. Starts the simulated NAT environment
# 3. Runs the hole punching test
# 4. Collects results and logs
# 5. Cleans up

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

cleanup() {
    log_info "Cleaning up..."
    docker compose -f "$COMPOSE_FILE" down --volumes --remove-orphans 2>/dev/null || true
}

# Set up cleanup trap
trap cleanup EXIT

# Parse arguments
VERBOSE=false
KEEP_RUNNING=false
TIMEOUT=120

while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -k|--keep)
            KEEP_RUNNING=true
            shift
            ;;
        -t|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  -v, --verbose    Show detailed output"
            echo "  -k, --keep       Keep containers running after test"
            echo "  -t, --timeout    Test timeout in seconds (default: 120)"
            echo "  -h, --help       Show this help"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

if $KEEP_RUNNING; then
    trap - EXIT
fi

log_info "NAT Hole Punching Integration Test"
log_info "==================================="
log_info "Project directory: $PROJECT_DIR"
log_info "Test timeout: ${TIMEOUT}s"

# Check prerequisites
log_info "Checking prerequisites..."

if ! command -v docker &> /dev/null; then
    log_error "Docker is not installed"
    exit 1
fi

if ! docker info &> /dev/null; then
    log_error "Docker daemon is not running"
    exit 1
fi

if ! docker compose version &> /dev/null; then
    log_error "Docker Compose is not installed"
    exit 1
fi

log_info "Prerequisites OK"

# Clean up any existing test containers
log_info "Cleaning up existing containers..."
cleanup

# Build Docker images
log_info "Building Docker images..."
cd "$SCRIPT_DIR"

if $VERBOSE; then
    docker compose -f "$COMPOSE_FILE" build
else
    docker compose -f "$COMPOSE_FILE" build 2>&1 | tail -10
fi

log_info "Docker images built"

# Start the test environment - one container at a time to avoid race conditions
log_info "Starting test environment..."
log_info "Starting signaling server..."
docker compose -f "$COMPOSE_FILE" up -d signaling
sleep 2

log_info "Starting NAT A..."
docker compose -f "$COMPOSE_FILE" up -d nat_a

# Wait for NAT A to become healthy (apk install takes time)
log_info "Waiting for NAT A to become healthy..."
for i in {1..30}; do
    health=$(docker inspect --format '{{.State.Health.Status}}' "$(docker compose -f "$COMPOSE_FILE" ps -q nat_a)" 2>/dev/null || true)
    if [[ "$health" == "healthy" ]]; then
        log_info "NAT A is healthy"
        break
    fi
    sleep 2
done

log_info "Starting NAT B..."
docker compose -f "$COMPOSE_FILE" up -d nat_b

# Wait for NAT B to become healthy
log_info "Waiting for NAT B to become healthy..."
for i in {1..30}; do
    health=$(docker inspect --format '{{.State.Health.Status}}' "$(docker compose -f "$COMPOSE_FILE" ps -q nat_b)" 2>/dev/null || true)
    if [[ "$health" == "healthy" ]]; then
        log_info "NAT B is healthy"
        break
    fi
    sleep 2
done

# Inspect machine-readable state; grep -q pipelines can SIGPIPE under pipefail.
for service in nat_a nat_b signaling; do
    container_id=$(docker compose -f "$COMPOSE_FILE" ps -q "$service")
    running=$(docker inspect --format '{{.State.Running}}' "$container_id" 2>/dev/null || true)
    if [[ "$running" != "true" ]]; then
        log_error "$service container failed to start"
        docker compose -f "$COMPOSE_FILE" logs "$service"
        exit 1
    fi
done

log_info "Infrastructure ready"

# Start peer containers
log_info "Starting peer containers..."
docker compose -f "$COMPOSE_FILE" up -d peer_a peer_b

# Wait for test to complete with timeout
log_info "Running hole punch test (timeout: ${TIMEOUT}s)..."

START_TIME=$(date +%s)
TEST_PASSED=false

while true; do
    CURRENT_TIME=$(date +%s)
    ELAPSED=$((CURRENT_TIME - START_TIME))

    if [ $ELAPSED -ge $TIMEOUT ]; then
        log_error "Test timed out after ${TIMEOUT}s"
        break
    fi

    # Check if peers have exited
    PEER_A_STATUS=$(docker compose -f "$COMPOSE_FILE" ps -a peer_a --format "{{.Status}}" 2>/dev/null || echo "unknown")
    PEER_B_STATUS=$(docker compose -f "$COMPOSE_FILE" ps -a peer_b --format "{{.Status}}" 2>/dev/null || echo "unknown")

    if [[ "$PEER_A_STATUS" == *"Exited"* ]] && [[ "$PEER_B_STATUS" == *"Exited"* ]]; then
        # Check exit codes
        PEER_A_EXIT=$(docker inspect --format '{{.State.ExitCode}}' "$(docker compose -f "$COMPOSE_FILE" ps -a -q peer_a)")
        PEER_B_EXIT=$(docker inspect --format '{{.State.ExitCode}}' "$(docker compose -f "$COMPOSE_FILE" ps -a -q peer_b)")

        log_info "Both peers have completed"
        log_info "Peer A status: $PEER_A_STATUS"
        log_info "Peer B status: $PEER_B_STATUS"

        # Check logs for success indicators
        peer_a_logs=$(docker compose -f "$COMPOSE_FILE" logs peer_a 2>&1)
        peer_b_logs=$(docker compose -f "$COMPOSE_FILE" logs peer_b 2>&1)
        if [[ "$PEER_A_EXIT" == "0" && "$PEER_B_EXIT" == "0" ]] \
            && grep -Fq "STUN discovered reflexive address: 10.100.0.2:5000 " <<<"$peer_a_logs" \
            && grep -Fq "STUN discovered reflexive address: 10.100.0.3:5000 " <<<"$peer_b_logs" \
            && grep -Fq "SUCCESS: Connected to 10.100.0.3:5000" <<<"$peer_a_logs" \
            && grep -Fq "SUCCESS: Connected to 10.100.0.2:5000" <<<"$peer_b_logs"; then
            TEST_PASSED=true
        fi
        break
    fi

    if $VERBOSE; then
        echo -ne "\rElapsed: ${ELAPSED}s / ${TIMEOUT}s"
    fi

    sleep 2
done

echo ""

# Collect logs
log_info "Collecting logs..."
LOGS_DIR="$SCRIPT_DIR/logs"
mkdir -p "$LOGS_DIR"

docker compose -f "$COMPOSE_FILE" logs signaling > "$LOGS_DIR/signaling.log" 2>&1
docker compose -f "$COMPOSE_FILE" logs peer_a > "$LOGS_DIR/peer_a.log" 2>&1
docker compose -f "$COMPOSE_FILE" logs peer_b > "$LOGS_DIR/peer_b.log" 2>&1
docker compose -f "$COMPOSE_FILE" logs nat_a > "$LOGS_DIR/nat_a.log" 2>&1
docker compose -f "$COMPOSE_FILE" logs nat_b > "$LOGS_DIR/nat_b.log" 2>&1

# A successful handshake must have traversed both configured NAT routers.
# Save counters as evidence and reject accidental direct Docker bridge paths.
for router in nat_a nat_b; do
    docker compose -f "$COMPOSE_FILE" exec -T "$router" \
        iptables -t nat -L -v -n -x > "$LOGS_DIR/$router-counters.log"
    docker compose -f "$COMPOSE_FILE" exec -T "$router" \
        iptables -L FORWARD -v -n -x >> "$LOGS_DIR/$router-counters.log"
    if ! awk '$3 == "SNAT" && /to:10[.]100[.]0[.]/ && $1 > 0 { snat = 1 } $3 == "ACCEPT" && $8 ~ /^10[.]10[12][.]0[.]10$/ && $1 > 0 { outbound = 1 } $3 == "ACCEPT" && $9 ~ /^10[.]10[12][.]0[.]10$/ && $1 > 0 { inbound = 1 } END { exit !(snat && outbound && inbound) }' \
        "$LOGS_DIR/$router-counters.log"; then
        log_error "$router did not translate traffic in both directions"
        TEST_PASSED=false
    fi
done

log_info "Logs saved to $LOGS_DIR"

# Keep the complete topology available for packet/counter inspection when requested.
if $KEEP_RUNNING; then
    trap - EXIT
fi

# Show test result
echo ""
echo "========================================"
if $TEST_PASSED; then
    log_info "TEST PASSED: NAT hole punching succeeded!"
    echo "========================================"
    exit 0
else
    log_error "TEST FAILED: NAT hole punching did not succeed"
    echo "========================================"

    echo ""
    log_info "Peer A logs (last 30 lines):"
    tail -30 "$LOGS_DIR/peer_a.log"

    echo ""
    log_info "Peer B logs (last 30 lines):"
    tail -30 "$LOGS_DIR/peer_b.log"

    echo ""
    log_info "Signaling server logs (last 30 lines):"
    tail -30 "$LOGS_DIR/signaling.log"

    if $KEEP_RUNNING; then
        log_info "Containers kept running for debugging"
        log_info "To clean up: docker compose -f $COMPOSE_FILE down"
        trap - EXIT  # Remove cleanup trap
    fi

    exit 1
fi
