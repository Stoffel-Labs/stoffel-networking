//! ICE Agent - NAT traversal state machine and hole punch coordination
//!
//! Manages the ICE (Interactive Connectivity Establishment) process for
//! establishing peer-to-peer connections through NAT.

use crate::network_utils::PartyId;
use crate::transports::ice::{
    CandidatePair, CandidatePairState, IceCandidate, LocalCandidates,
};
use crate::transports::net_envelope::NetEnvelope;
use crate::transports::stun::StunClient;
use dashmap::DashMap;
use quinn::Endpoint;
use rand::Rng;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, info, trace, warn};

/// ICE agent role determines who initiates checks and nominates pairs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceRole {
    /// Initiates connectivity checks and nominates successful pairs
    Controlling,
    /// Responds to checks and waits for nomination
    Controlled,
}

/// ICE connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceState {
    /// Initial state, not started
    New,
    /// Gathering local candidates (STUN queries in progress)
    Gathering,
    /// Candidates gathered, waiting to exchange with peer
    GatheringComplete,
    /// Exchanging candidates with peer
    Exchanging,
    /// Running connectivity checks
    Checking,
    /// At least one pair succeeded but not yet nominated
    Connected,
    /// Nominated pair confirmed by both sides
    Completed,
    /// All pairs failed, no connectivity possible
    Failed,
    /// Session explicitly closed
    Closed,
}

/// Configuration for the ICE agent
#[derive(Debug, Clone)]
pub struct IceAgentConfig {
    /// STUN servers for candidate gathering
    pub stun_servers: Vec<SocketAddr>,
    /// Timeout for each connectivity check attempt
    pub check_timeout: Duration,
    /// Maximum retransmissions per check
    pub check_retries: u32,
    /// Interval between checks (pacing)
    pub check_pace: Duration,
    /// Use aggressive nomination (nominate first successful pair)
    pub aggressive_nomination: bool,
    /// Total timeout for the ICE process
    pub overall_timeout: Duration,
    /// Number of probe packets for hole punching
    pub probe_count: u32,
    /// Interval between probe packets
    pub probe_interval: Duration,
}

impl Default for IceAgentConfig {
    fn default() -> Self {
        Self {
            stun_servers: vec![
                "stun.l.google.com:19302".parse().unwrap(),
                "stun1.l.google.com:19302".parse().unwrap(),
            ],
            check_timeout: Duration::from_millis(500),
            check_retries: 3,
            check_pace: Duration::from_millis(50),
            aggressive_nomination: true,
            overall_timeout: Duration::from_secs(30),
            probe_count: 5,
            probe_interval: Duration::from_millis(20),
        }
    }
}

/// Result of a connectivity check
#[derive(Debug, Clone)]
pub struct CheckResult {
    /// Index of the pair in the check list
    pub pair_index: usize,
    /// Whether the check succeeded
    pub success: bool,
    /// Measured round-trip time (if succeeded)
    pub rtt: Option<Duration>,
    /// Peer reflexive candidate discovered (if any)
    pub peer_reflexive: Option<IceCandidate>,
}

/// Pending connectivity check tracking
#[derive(Debug)]
struct PendingCheck {
    pair_index: usize,
    sent_at: Instant,
    retries: u32,
}

/// ICE Agent errors
#[derive(Debug, Clone)]
pub enum IceError {
    /// Candidate gathering failed
    GatheringFailed(String),
    /// No candidates available
    NoCandidates,
    /// All connectivity checks failed
    AllChecksFailed,
    /// Overall timeout exceeded
    Timeout,
    /// Operation invalid in current state
    InvalidState(IceState),
    /// Signaling error
    SignalingError(String),
    /// Network error
    NetworkError(String),
    /// Hole punching failed
    HolePunchFailed(String),
}

impl std::fmt::Display for IceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GatheringFailed(msg) => write!(f, "Gathering failed: {}", msg),
            Self::NoCandidates => write!(f, "No candidates available"),
            Self::AllChecksFailed => write!(f, "All connectivity checks failed"),
            Self::Timeout => write!(f, "ICE timeout"),
            Self::InvalidState(state) => write!(f, "Invalid state: {:?}", state),
            Self::SignalingError(msg) => write!(f, "Signaling error: {}", msg),
            Self::NetworkError(msg) => write!(f, "Network error: {}", msg),
            Self::HolePunchFailed(msg) => write!(f, "Hole punch failed: {}", msg),
        }
    }
}

impl std::error::Error for IceError {}

/// ICE Agent managing NAT traversal for a single peer connection
pub struct IceAgent {
    /// Current state
    state: IceState,
    /// Agent role (controlling or controlled)
    role: IceRole,
    /// Configuration
    config: IceAgentConfig,
    /// Local party ID
    local_party_id: PartyId,
    /// Remote party ID
    remote_party_id: Option<PartyId>,
    /// Local candidates
    local_candidates: LocalCandidates,
    /// Remote candidates
    remote_candidates: Option<LocalCandidates>,
    /// Formed candidate pairs (sorted by priority)
    check_list: Vec<CandidatePair>,
    /// Index of nominated pair
    nominated_pair: Option<usize>,
    /// Transaction ID counter
    transaction_counter: u64,
    /// Pending transactions
    pending_transactions: DashMap<u64, PendingCheck>,
    /// Start time for timeout tracking
    start_time: Option<Instant>,
    /// STUN client for gathering
    stun_client: StunClient,
}

impl IceAgent {
    /// Creates a new ICE agent with the given configuration
    pub fn new(config: IceAgentConfig, local_party_id: PartyId) -> Self {
        let stun_servers = config
            .stun_servers
            .iter()
            .map(|addr| crate::transports::stun::StunServerConfig::new(*addr))
            .collect();

        Self {
            state: IceState::New,
            role: IceRole::Controlling, // Will be determined later
            config,
            local_party_id,
            remote_party_id: None,
            local_candidates: LocalCandidates::new(),
            remote_candidates: None,
            check_list: Vec::new(),
            nominated_pair: None,
            transaction_counter: 0,
            pending_transactions: DashMap::new(),
            start_time: None,
            stun_client: StunClient::new(stun_servers),
        }
    }

    /// Determines role based on party IDs (higher ID = controlling)
    pub fn determine_role(local_party_id: PartyId, remote_party_id: PartyId) -> IceRole {
        if local_party_id > remote_party_id {
            IceRole::Controlling
        } else {
            IceRole::Controlled
        }
    }

    /// Sets the agent role
    pub fn set_role(&mut self, role: IceRole) {
        self.role = role;
    }

    /// Returns current state
    pub fn state(&self) -> IceState {
        self.state
    }

    /// Returns agent role
    pub fn role(&self) -> IceRole {
        self.role
    }

    /// Returns local candidates
    pub fn local_candidates(&self) -> &LocalCandidates {
        &self.local_candidates
    }

    /// Returns the nominated pair if ICE completed
    pub fn nominated_pair(&self) -> Option<&CandidatePair> {
        self.nominated_pair.map(|idx| &self.check_list[idx])
    }

    /// Generates a new transaction ID
    fn next_transaction_id(&mut self) -> u64 {
        self.transaction_counter += 1;
        let mut rng = rand::thread_rng();
        (self.transaction_counter << 32) | (rng.r#gen::<u32>() as u64)
    }

    /// Phase 1: Gather local candidates
    pub async fn gather_candidates(&mut self, local_addr: SocketAddr) -> Result<(), IceError> {
        if self.state != IceState::New {
            return Err(IceError::InvalidState(self.state));
        }

        self.state = IceState::Gathering;
        self.start_time = Some(Instant::now());

        info!("ICE gathering started for party {}", self.local_party_id);

        // Add host candidate
        self.local_candidates.add_host(local_addr);
        debug!("Added host candidate: {}", local_addr);

        // Gather server reflexive candidates via STUN
        if self.stun_client.has_servers() {
            // Create a temporary socket for STUN queries
            // In production, this should share the QUIC endpoint's socket
            let socket = UdpSocket::bind("0.0.0.0:0")
                .await
                .map_err(|e| IceError::NetworkError(e.to_string()))?;

            let results = self.stun_client.discover_all(&socket).await;

            for result in results {
                // Only add if different from host candidate
                if result.reflexive_address != local_addr {
                    self.local_candidates.add_server_reflexive(
                        result.reflexive_address,
                        local_addr,
                        result.server_address,
                    );
                    debug!(
                        "Added server reflexive candidate: {} (from {})",
                        result.reflexive_address, result.server_address
                    );
                }
            }
        }

        if self.local_candidates.is_empty() {
            return Err(IceError::NoCandidates);
        }

        self.state = IceState::GatheringComplete;
        info!(
            "ICE gathering complete: {} candidates",
            self.local_candidates.len()
        );

        Ok(())
    }

    /// Gather candidates using a shared UDP socket (for accurate NAT mapping)
    pub async fn gather_candidates_with_socket(
        &mut self,
        local_addr: SocketAddr,
        socket: &UdpSocket,
    ) -> Result<(), IceError> {
        if self.state != IceState::New {
            return Err(IceError::InvalidState(self.state));
        }

        self.state = IceState::Gathering;
        self.start_time = Some(Instant::now());

        // Add host candidate
        self.local_candidates.add_host(local_addr);

        // Gather STUN candidates using provided socket
        if self.stun_client.has_servers() {
            let results = self.stun_client.discover_all(socket).await;
            for result in results {
                if result.reflexive_address != local_addr {
                    self.local_candidates.add_server_reflexive(
                        result.reflexive_address,
                        local_addr,
                        result.server_address,
                    );
                }
            }
        }

        if self.local_candidates.is_empty() {
            return Err(IceError::NoCandidates);
        }

        self.state = IceState::GatheringComplete;
        Ok(())
    }

    /// Phase 2: Set remote candidates and form pairs
    pub fn set_remote_candidates(
        &mut self,
        remote_party_id: PartyId,
        ufrag: String,
        pwd: String,
        candidates: Vec<IceCandidate>,
    ) -> Result<(), IceError> {
        if self.state != IceState::GatheringComplete && self.state != IceState::Exchanging {
            return Err(IceError::InvalidState(self.state));
        }

        self.remote_party_id = Some(remote_party_id);
        self.role = Self::determine_role(self.local_party_id, remote_party_id);

        debug!(
            "Set remote candidates from party {} (role: {:?}): {} candidates",
            remote_party_id,
            self.role,
            candidates.len()
        );

        self.remote_candidates = Some(LocalCandidates {
            candidates,
            ufrag,
            pwd,
        });

        // Form candidate pairs
        if let Some(ref remote) = self.remote_candidates {
            self.check_list = CandidatePair::form_pairs(
                &self.local_candidates.candidates,
                &remote.candidates,
                self.role == IceRole::Controlling,
            );

            // Unfreeze first pair to start checking
            if !self.check_list.is_empty() {
                self.check_list[0].state = CandidatePairState::Waiting;
            }

            debug!("Formed {} candidate pairs", self.check_list.len());
        }

        self.state = IceState::Checking;
        Ok(())
    }

    /// Phase 3: Run connectivity checks
    ///
    /// Attempts to establish connectivity by checking candidate pairs.
    /// Uses QUIC Initial packets for checking (not STUN).
    pub async fn run_connectivity_checks(
        &mut self,
        endpoint: &Endpoint,
    ) -> Result<CandidatePair, IceError> {
        if self.state != IceState::Checking {
            return Err(IceError::InvalidState(self.state));
        }

        let start = Instant::now();
        let timeout = self.config.overall_timeout;

        info!(
            "Starting connectivity checks ({} pairs, role: {:?})",
            self.check_list.len(),
            self.role
        );

        while start.elapsed() < timeout {
            // Find next pair to check
            let pair_idx = self
                .check_list
                .iter()
                .position(|p| p.state == CandidatePairState::Waiting);

            let pair_idx = match pair_idx {
                Some(idx) => idx,
                None => {
                    // Check if we have any successful pairs
                    if let Some(nominated_idx) = self.nominated_pair {
                        self.state = IceState::Completed;
                        return Ok(self.check_list[nominated_idx].clone());
                    }

                    // Check if all pairs failed
                    if self
                        .check_list
                        .iter()
                        .all(|p| p.state == CandidatePairState::Failed)
                    {
                        self.state = IceState::Failed;
                        return Err(IceError::AllChecksFailed);
                    }

                    // Wait and retry
                    tokio::time::sleep(self.config.check_pace).await;
                    continue;
                }
            };

            // Mark as in progress
            self.check_list[pair_idx].state = CandidatePairState::InProgress;

            let pair = &self.check_list[pair_idx];
            debug!(
                "Checking pair {}: {} -> {} (priority: {})",
                pair_idx, pair.local.address, pair.remote.address, pair.priority
            );

            // Perform QUIC-based connectivity check
            let result = self
                .perform_quic_check(endpoint, pair_idx)
                .await;

            match result {
                Ok(check_result) if check_result.success => {
                    self.check_list[pair_idx].state = CandidatePairState::Succeeded;
                    self.check_list[pair_idx].rtt_ms =
                        check_result.rtt.map(|d| d.as_millis() as u64);

                    info!(
                        "Pair {} succeeded (RTT: {:?})",
                        pair_idx, check_result.rtt
                    );

                    // Aggressive nomination: nominate first successful pair
                    if self.config.aggressive_nomination && self.role == IceRole::Controlling {
                        self.check_list[pair_idx].nominated = true;
                        self.nominated_pair = Some(pair_idx);
                        self.state = IceState::Completed;
                        return Ok(self.check_list[pair_idx].clone());
                    }

                    self.state = IceState::Connected;
                }
                Ok(_) | Err(_) => {
                    self.check_list[pair_idx].state = CandidatePairState::Failed;
                    debug!("Pair {} failed", pair_idx);

                    // Unfreeze next pair
                    if let Some(next) = self
                        .check_list
                        .iter_mut()
                        .find(|p| p.state == CandidatePairState::Frozen)
                    {
                        next.state = CandidatePairState::Waiting;
                    }
                }
            }

            // Pacing between checks
            tokio::time::sleep(self.config.check_pace).await;
        }

        self.state = IceState::Failed;
        Err(IceError::Timeout)
    }

    /// Perform a single QUIC-based connectivity check
    async fn perform_quic_check(
        &self,
        endpoint: &Endpoint,
        pair_idx: usize,
    ) -> Result<CheckResult, IceError> {
        let pair = &self.check_list[pair_idx];
        let target = pair.remote.address;
        let start = Instant::now();

        for attempt in 0..self.config.check_retries {
            trace!(
                "QUIC check attempt {} to {} from {}",
                attempt + 1,
                target,
                pair.local.address
            );

            // Attempt QUIC connection
            let connect_result = match endpoint.connect(target, "localhost") {
                Ok(connecting) => {
                    tokio::time::timeout(self.config.check_timeout, connecting).await
                }
                Err(e) => {
                    debug!("Failed to initiate connection: {}", e);
                    continue;
                }
            };

            match connect_result {
                Ok(Ok(_connection)) => {
                    let rtt = start.elapsed();
                    return Ok(CheckResult {
                        pair_index: pair_idx,
                        success: true,
                        rtt: Some(rtt),
                        peer_reflexive: None,
                    });
                }
                Ok(Err(e)) => {
                    trace!("Connection failed: {}", e);
                }
                Err(_) => {
                    trace!("Connection timed out");
                }
            }
        }

        Ok(CheckResult {
            pair_index: pair_idx,
            success: false,
            rtt: None,
            peer_reflexive: None,
        })
    }
}

/// Hole punch coordinator for synchronized NAT traversal
pub struct HolePunchCoordinator {
    /// Transaction ID for this hole punch attempt
    transaction_id: u64,
    /// Local address to punch from
    local_addr: SocketAddr,
    /// Remote address to punch towards
    remote_addr: SocketAddr,
    /// Our role in the hole punch
    role: IceRole,
    /// Maximum retry attempts
    max_retries: u32,
    /// Configuration
    config: HolePunchConfig,
}

/// Configuration for hole punching
#[derive(Debug, Clone)]
pub struct HolePunchConfig {
    /// Initial delay before first attempt
    pub initial_delay: Duration,
    /// Jitter range to add randomness
    pub jitter_range: Duration,
    /// Interval between probe packets
    pub probe_interval: Duration,
    /// Number of probe packets to send
    pub probe_count: u32,
    /// Timeout for connection attempt
    pub connection_timeout: Duration,
    /// Delay between retry attempts
    pub retry_delay: Duration,
    /// Backoff factor for retries
    pub backoff_factor: f64,
}

impl Default for HolePunchConfig {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_millis(100),
            jitter_range: Duration::from_millis(50),
            probe_interval: Duration::from_millis(20),
            probe_count: 5,
            connection_timeout: Duration::from_millis(2000),
            retry_delay: Duration::from_millis(500),
            backoff_factor: 1.5,
        }
    }
}

/// Hole punch errors
#[derive(Debug, Clone)]
pub enum HolePunchError {
    /// Timeout waiting for response
    Timeout,
    /// Connection establishment failed
    ConnectionFailed(String),
    /// Signaling error
    SignalingError(String),
    /// Maximum retries exceeded
    MaxRetriesExceeded,
    /// No incoming connection received
    NoIncoming,
    /// Network error
    NetworkError(String),
}

impl std::fmt::Display for HolePunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => write!(f, "Hole punch timeout"),
            Self::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            Self::SignalingError(msg) => write!(f, "Signaling error: {}", msg),
            Self::MaxRetriesExceeded => write!(f, "Max retries exceeded"),
            Self::NoIncoming => write!(f, "No incoming connection"),
            Self::NetworkError(msg) => write!(f, "Network error: {}", msg),
        }
    }
}

impl std::error::Error for HolePunchError {}

impl HolePunchCoordinator {
    /// Creates a new hole punch coordinator
    pub fn new(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        role: IceRole,
        config: HolePunchConfig,
    ) -> Self {
        let mut rng = rand::thread_rng();
        Self {
            transaction_id: rng.r#gen(),
            local_addr,
            remote_addr,
            role,
            max_retries: 3,
            config,
        }
    }

    /// Returns the transaction ID
    pub fn transaction_id(&self) -> u64 {
        self.transaction_id
    }

    /// Execute coordinated hole punch
    ///
    /// # Protocol
    /// 1. Controlling agent sends PunchRequest via signaling
    /// 2. Both agents synchronize timing
    /// 3. Both agents simultaneously send QUIC Initial packets
    /// 4. NAT mappings are created by outgoing packets
    /// 5. Incoming packets can traverse the created mappings
    pub async fn execute(
        &mut self,
        endpoint: &Endpoint,
        signaling_send: impl Fn(NetEnvelope) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>>,
        signaling_recv: Arc<Mutex<tokio::sync::mpsc::Receiver<NetEnvelope>>>,
    ) -> Result<quinn::Connection, HolePunchError> {
        for attempt in 0..self.max_retries {
            info!(
                "Hole punch attempt {} (role: {:?}, target: {})",
                attempt + 1,
                self.role,
                self.remote_addr
            );

            let result = self
                .attempt_punch(endpoint, &signaling_send, &signaling_recv)
                .await;

            match result {
                Ok(conn) => {
                    info!("Hole punch succeeded on attempt {}", attempt + 1);
                    return Ok(conn);
                }
                Err(HolePunchError::Timeout) if attempt < self.max_retries - 1 => {
                    let delay = Duration::from_millis(
                        (self.config.retry_delay.as_millis() as f64
                            * self.config.backoff_factor.powi(attempt as i32))
                            as u64,
                    );
                    debug!("Retrying hole punch after {:?}", delay);
                    tokio::time::sleep(delay).await;
                }
                Err(e) => {
                    warn!("Hole punch attempt {} failed: {}", attempt + 1, e);
                    if attempt == self.max_retries - 1 {
                        return Err(e);
                    }
                }
            }
        }

        Err(HolePunchError::MaxRetriesExceeded)
    }

    /// Single hole punch attempt
    async fn attempt_punch(
        &mut self,
        endpoint: &Endpoint,
        signaling_send: &impl Fn(NetEnvelope) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>>,
        signaling_recv: &Arc<Mutex<tokio::sync::mpsc::Receiver<NetEnvelope>>>,
    ) -> Result<quinn::Connection, HolePunchError> {
        // Calculate synchronized punch time
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let delay_ms = self.config.initial_delay.as_millis() as u64
            + rand::thread_rng().gen_range(0..self.config.jitter_range.as_millis() as u64);

        if self.role == IceRole::Controlling {
            // Send punch request with timing info
            let request = NetEnvelope::PunchRequest {
                transaction_id: self.transaction_id,
                target_address: self.local_addr, // Tell peer to punch towards us
                delay_ms,
            };

            signaling_send(request)
                .await
                .map_err(|e| HolePunchError::SignalingError(e))?;

            // Wait for ack
            let ack_timeout = Duration::from_secs(5);
            let ack = tokio::time::timeout(ack_timeout, async {
                let mut recv = signaling_recv.lock().await;
                while let Some(envelope) = recv.recv().await {
                    if let NetEnvelope::PunchAck { transaction_id, .. } = envelope {
                        if transaction_id == self.transaction_id {
                            return Some(envelope);
                        }
                    }
                }
                None
            })
            .await
            .map_err(|_| HolePunchError::Timeout)?
            .ok_or(HolePunchError::SignalingError("Channel closed".to_string()))?;

            debug!("Received punch ack: {:?}", ack);
        } else {
            // Controlled: wait for punch request
            let request_timeout = Duration::from_secs(10);
            let request = tokio::time::timeout(request_timeout, async {
                let mut recv = signaling_recv.lock().await;
                while let Some(envelope) = recv.recv().await {
                    if let NetEnvelope::PunchRequest { .. } = envelope {
                        return Some(envelope);
                    }
                }
                None
            })
            .await
            .map_err(|_| HolePunchError::Timeout)?
            .ok_or(HolePunchError::SignalingError("No request received".to_string()))?;

            // Send ack
            if let NetEnvelope::PunchRequest { transaction_id, .. } = request {
                let ack = NetEnvelope::PunchAck {
                    transaction_id,
                    timestamp_ms: now_ms,
                };
                signaling_send(ack)
                    .await
                    .map_err(|e| HolePunchError::SignalingError(e))?;
            }
        }

        // Wait for synchronized moment
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;

        // Execute the punch
        if self.role == IceRole::Controlling {
            self.punch_as_controlling(endpoint).await
        } else {
            self.punch_as_controlled(endpoint).await
        }
    }

    /// Controlling agent: actively establish connection
    async fn punch_as_controlling(
        &self,
        endpoint: &Endpoint,
    ) -> Result<quinn::Connection, HolePunchError> {
        // Send probe packets first to create NAT mapping
        self.send_probes(endpoint).await;

        // Attempt connection
        let connecting = endpoint
            .connect(self.remote_addr, "localhost")
            .map_err(|e| HolePunchError::ConnectionFailed(e.to_string()))?;

        tokio::time::timeout(self.config.connection_timeout, connecting)
            .await
            .map_err(|_| HolePunchError::Timeout)?
            .map_err(|e| HolePunchError::ConnectionFailed(e.to_string()))
    }

    /// Controlled agent: send probes and wait for connection
    async fn punch_as_controlled(
        &self,
        endpoint: &Endpoint,
    ) -> Result<quinn::Connection, HolePunchError> {
        // Send probe packets to create NAT mapping
        self.send_probes(endpoint).await;

        // For controlled agent, we primarily try to accept incoming connections
        // but also attempt to connect (simultaneous open pattern)

        // First, try to accept for a short time
        let accept_result = tokio::time::timeout(
            Duration::from_millis(500),
            async {
                endpoint
                    .accept()
                    .await
                    .ok_or(HolePunchError::NoIncoming)?
                    .await
                    .map_err(|e| HolePunchError::ConnectionFailed(e.to_string()))
            }
        ).await;

        match accept_result {
            Ok(Ok(conn)) => return Ok(conn),
            _ => {}
        }

        // If accept didn't work, try connecting
        let connecting = endpoint
            .connect(self.remote_addr, "localhost")
            .map_err(|e| HolePunchError::ConnectionFailed(e.to_string()))?;

        let connect_result = tokio::time::timeout(
            self.config.connection_timeout,
            connecting
        ).await;

        match connect_result {
            Ok(Ok(conn)) => Ok(conn),
            Ok(Err(e)) => Err(HolePunchError::ConnectionFailed(e.to_string())),
            Err(_) => {
                // Final attempt: try accepting again
                tokio::time::timeout(
                    Duration::from_millis(1000),
                    async {
                        endpoint
                            .accept()
                            .await
                            .ok_or(HolePunchError::NoIncoming)?
                            .await
                            .map_err(|e| HolePunchError::ConnectionFailed(e.to_string()))
                    }
                ).await
                    .map_err(|_| HolePunchError::Timeout)?
            }
        }
    }

    /// Send probe packets to create NAT mapping
    async fn send_probes(&self, endpoint: &Endpoint) {
        for i in 0..self.config.probe_count {
            trace!("Sending probe {} to {}", i + 1, self.remote_addr);

            // Attempt to connect but don't wait for completion
            // This sends QUIC Initial packets that will create NAT mapping
            let _ = endpoint.connect(self.remote_addr, "localhost");

            if i < self.config.probe_count - 1 {
                tokio::time::sleep(self.config.probe_interval).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_determination() {
        // Higher party ID should be controlling
        assert_eq!(IceAgent::determine_role(100, 50), IceRole::Controlling);
        assert_eq!(IceAgent::determine_role(50, 100), IceRole::Controlled);
        assert_eq!(IceAgent::determine_role(50, 50), IceRole::Controlled);
    }

    #[test]
    fn test_ice_state_transitions() {
        let config = IceAgentConfig::default();
        let agent = IceAgent::new(config, 1);

        assert_eq!(agent.state(), IceState::New);
    }

    #[test]
    fn test_hole_punch_config_defaults() {
        let config = HolePunchConfig::default();

        assert_eq!(config.initial_delay, Duration::from_millis(100));
        assert_eq!(config.probe_count, 5);
        assert_eq!(config.connection_timeout, Duration::from_millis(2000));
    }
}
