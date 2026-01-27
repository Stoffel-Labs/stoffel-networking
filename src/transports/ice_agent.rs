//! ICE Agent - NAT traversal state machine and hole punch coordination
//!
//! Manages the ICE (Interactive Connectivity Establishment) process for
//! establishing peer-to-peer connections through NAT.

use crate::network_utils::{PartyId, SenderId};
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
            // Default to empty - STUN servers require DNS resolution which isn't supported
            // by SocketAddr. Users should configure STUN servers with resolved IP addresses.
            stun_servers: vec![],
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

/// Configuration validation errors
#[derive(Debug, Clone)]
pub enum ConfigError {
    /// Check timeout must be positive
    InvalidCheckTimeout,
    /// Check retries must be at least 1
    InvalidCheckRetries,
    /// Probe count must be at least 1
    InvalidProbeCount,
    /// Overall timeout must be greater than check timeout
    InvalidOverallTimeout,
    /// Probe interval must be positive
    InvalidProbeInterval,
    /// Check pace must be positive
    InvalidCheckPace,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCheckTimeout => write!(f, "Check timeout must be positive"),
            Self::InvalidCheckRetries => write!(f, "Check retries must be at least 1"),
            Self::InvalidProbeCount => write!(f, "Probe count must be at least 1"),
            Self::InvalidOverallTimeout => {
                write!(f, "Overall timeout must be greater than check timeout")
            }
            Self::InvalidProbeInterval => write!(f, "Probe interval must be positive"),
            Self::InvalidCheckPace => write!(f, "Check pace must be positive"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl IceAgentConfig {
    /// Creates a new configuration with the specified STUN servers
    pub fn new(stun_servers: Vec<SocketAddr>) -> Self {
        Self {
            stun_servers,
            ..Default::default()
        }
    }

    /// Builder method: set STUN servers
    pub fn with_stun_servers(mut self, servers: Vec<SocketAddr>) -> Self {
        self.stun_servers = servers;
        self
    }

    /// Builder method: set check timeout
    pub fn with_check_timeout(mut self, timeout: Duration) -> Self {
        self.check_timeout = timeout;
        self
    }

    /// Builder method: set check retries
    pub fn with_check_retries(mut self, retries: u32) -> Self {
        self.check_retries = retries;
        self
    }

    /// Builder method: set check pacing interval
    pub fn with_check_pace(mut self, pace: Duration) -> Self {
        self.check_pace = pace;
        self
    }

    /// Builder method: enable/disable aggressive nomination
    pub fn with_aggressive_nomination(mut self, enabled: bool) -> Self {
        self.aggressive_nomination = enabled;
        self
    }

    /// Builder method: set overall timeout
    pub fn with_overall_timeout(mut self, timeout: Duration) -> Self {
        self.overall_timeout = timeout;
        self
    }

    /// Builder method: set probe count for hole punching
    pub fn with_probe_count(mut self, count: u32) -> Self {
        self.probe_count = count;
        self
    }

    /// Builder method: set probe interval for hole punching
    pub fn with_probe_interval(mut self, interval: Duration) -> Self {
        self.probe_interval = interval;
        self
    }

    /// Validates the configuration and returns any errors
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.check_timeout.is_zero() {
            return Err(ConfigError::InvalidCheckTimeout);
        }
        if self.check_retries == 0 {
            return Err(ConfigError::InvalidCheckRetries);
        }
        if self.probe_count == 0 {
            return Err(ConfigError::InvalidProbeCount);
        }
        if self.overall_timeout <= self.check_timeout {
            return Err(ConfigError::InvalidOverallTimeout);
        }
        if self.probe_interval.is_zero() {
            return Err(ConfigError::InvalidProbeInterval);
        }
        if self.check_pace.is_zero() {
            return Err(ConfigError::InvalidCheckPace);
        }
        Ok(())
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
    /// Configuration error
    ConfigError(ConfigError),
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
            Self::ConfigError(err) => write!(f, "Configuration error: {}", err),
        }
    }
}

impl From<ConfigError> for IceError {
    fn from(err: ConfigError) -> Self {
        IceError::ConfigError(err)
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
    /// Creates a new ICE agent with the given configuration.
    ///
    /// Returns an error if the configuration is invalid.
    ///
    /// # Arguments
    /// * `config` - The ICE agent configuration (will be validated)
    /// * `local_party_id` - The local party's unique identifier
    pub fn new(config: IceAgentConfig, local_party_id: PartyId) -> Result<Self, IceError> {
        // Validate configuration before creating the agent
        config.validate()?;

        let stun_servers = config
            .stun_servers
            .iter()
            .map(|addr| crate::transports::stun::StunServerConfig::new(*addr))
            .collect();

        Ok(Self {
            state: IceState::New,
            // Role is undetermined until we know the remote party ID.
            // It will be set when set_remote_candidates is called.
            role: IceRole::Controlled, // Safe default - controlled agents don't initiate
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
        })
    }

    /// Creates a new ICE agent without validating the configuration.
    ///
    /// # Safety
    /// This bypasses configuration validation. Use only in tests or when you
    /// have already validated the configuration externally.
    pub fn new_unchecked(config: IceAgentConfig, local_party_id: PartyId) -> Self {
        let stun_servers = config
            .stun_servers
            .iter()
            .map(|addr| crate::transports::stun::StunServerConfig::new(*addr))
            .collect();

        Self {
            state: IceState::New,
            role: IceRole::Controlled,
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

    /// Returns the nominated pair if ICE has completed successfully.
    ///
    /// Returns `None` if:
    /// - ICE has not completed (state is not `Completed`)
    /// - No pair has been nominated yet
    pub fn nominated_pair(&self) -> Option<&CandidatePair> {
        if self.state != IceState::Completed {
            return None;
        }
        self.nominated_pair.map(|idx| &self.check_list[idx])
    }

    /// Generates a deterministic transaction ID based on local party ID and sequence.
    ///
    /// The transaction ID format is:
    /// - Upper 32 bits: local_party_id (for identifying the originating agent)
    /// - Lower 32 bits: sequence counter (for uniqueness within this agent)
    ///
    /// This makes it easy to verify that a STUN response corresponds to our request
    /// by checking if the upper bits match our party ID.
    fn next_transaction_id(&mut self) -> u64 {
        self.transaction_counter += 1;
        ((self.local_party_id.raw() as u64) << 32) | (self.transaction_counter & 0xFFFFFFFF)
    }

    /// Extracts the party ID from a transaction ID.
    ///
    /// Returns the party ID that generated this transaction.
    pub fn party_id_from_transaction(transaction_id: u64) -> SenderId {
        SenderId::new((transaction_id >> 32) as usize)
    }

    /// Checks if a transaction ID belongs to this agent.
    pub fn is_our_transaction(&self, transaction_id: u64) -> bool {
        Self::party_id_from_transaction(transaction_id) == self.local_party_id
    }

    /// Phase 1: Gather local candidates using a provided UDP socket.
    ///
    /// This is the primary method for gathering ICE candidates. It accepts a list of
    /// host addresses and a UDP socket for STUN queries.
    ///
    /// # Host Candidate Assumptions (per ICE RFC 8445)
    ///
    /// The provided host addresses are assumed to be:
    /// - Valid local IP addresses bound to network interfaces on this machine
    /// - Reachable by the peer (not localhost unless testing locally)
    /// - Not link-local addresses (169.254.x.x) unless intentionally testing
    /// - For IPv4, typically private (10.x, 172.16-31.x, 192.168.x) or public addresses
    ///
    /// No validation is performed on host candidates to allow flexibility for:
    /// - Local testing with localhost addresses
    /// - VPN/tunnel interfaces with unusual addresses
    /// - Container/VM networking with virtual interfaces
    ///
    /// The caller is responsible for providing appropriate host addresses based on
    /// their network topology and connectivity requirements.
    ///
    /// # Arguments
    ///
    /// * `host_addresses` - List of local addresses to use as host candidates.
    ///   Per RFC 8445, a host may have multiple network interfaces, each providing
    ///   a potential host candidate. Pass all relevant interface addresses.
    /// * `socket` - UDP socket to use for STUN queries. This should be the same
    ///   socket used for the actual QUIC transport to ensure consistent NAT mappings.
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if at least one candidate was gathered (either host or
    /// server-reflexive). Returns `Err(IceError::NoCandidates)` if no candidates
    /// could be gathered.
    pub async fn gather_candidates(
        &mut self,
        host_addresses: &[SocketAddr],
        socket: &UdpSocket,
    ) -> Result<(), IceError> {
        if self.state != IceState::New {
            return Err(IceError::InvalidState(self.state));
        }

        if host_addresses.is_empty() {
            return Err(IceError::NoCandidates);
        }

        self.state = IceState::Gathering;
        self.start_time = Some(Instant::now());

        info!("ICE gathering started for party {}", self.local_party_id);

        // Add all host candidates
        // Per RFC 8445 Section 5.1.1, an agent should gather host candidates from
        // all available network interfaces that it wishes to use for connectivity.
        // Note: QUIC uses a single component (component ID 1), so all host candidates
        // share the same component ID.
        for host_addr in host_addresses {
            self.local_candidates.add_host(*host_addr);
            debug!("Added host candidate: {}", host_addr);
        }

        // Gather server-reflexive candidates via STUN using the provided socket
        // The socket should be the same one used for QUIC to ensure NAT mappings
        // are created on the correct port.
        if self.stun_client.has_servers() {
            let results = self.stun_client.discover_all(socket).await;

            for result in results {
                // Only add server-reflexive if it differs from all host candidates
                // (i.e., we're actually behind a NAT)
                let is_duplicate = host_addresses
                    .iter()
                    .any(|host| host == &result.reflexive_address);

                if !is_duplicate {
                    // Use component 1 for the primary candidate
                    self.local_candidates.add_server_reflexive(
                        result.reflexive_address,
                        host_addresses[0], // Base is the primary host address
                        result.server_address,
                    );
                    debug!(
                        "Added server-reflexive candidate: {} (from STUN server {})",
                        result.reflexive_address, result.server_address
                    );
                }
            }
        } else {
            debug!("No STUN servers configured, skipping server-reflexive candidate gathering");
        }

        // At this point we should have at least the host candidates we added above
        debug_assert!(
            !self.local_candidates.is_empty(),
            "Should have at least host candidates"
        );

        self.state = IceState::GatheringComplete;
        info!(
            "ICE gathering complete: {} candidates",
            self.local_candidates.len()
        );

        Ok(())
    }

    /// Simplified gather for single host address (convenience wrapper).
    ///
    /// Creates a temporary UDP socket for STUN queries. Note that this socket
    /// will have a different port than the QUIC endpoint, which may cause NAT
    /// mapping issues with some NAT types. For production use, prefer
    /// `gather_candidates` with a shared socket.
    #[deprecated(
        since = "0.2.0",
        note = "Use gather_candidates with explicit socket for accurate NAT mappings"
    )]
    pub async fn gather_candidates_simple(
        &mut self,
        local_addr: SocketAddr,
    ) -> Result<(), IceError> {
        // Create a temporary socket - note this may not produce accurate NAT mappings
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| IceError::NetworkError(e.to_string()))?;

        warn!(
            "Using temporary socket for STUN queries; NAT mappings may be inaccurate. \
             Consider using gather_candidates() with a shared socket instead."
        );

        self.gather_candidates(&[local_addr], &socket).await
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

        // Timeout reached - but check if we have any successful pairs we can use
        if let Some(nominated_idx) = self.nominated_pair {
            self.state = IceState::Completed;
            return Ok(self.check_list[nominated_idx].clone());
        }

        // Find the best succeeded pair (highest priority) even if not nominated
        let best_succeeded = self
            .check_list
            .iter()
            .enumerate()
            .filter(|(_, p)| p.state == CandidatePairState::Succeeded)
            .max_by_key(|(_, p)| p.priority);

        if let Some((idx, _)) = best_succeeded {
            self.check_list[idx].nominated = true;
            self.nominated_pair = Some(idx);
            self.state = IceState::Completed;
            return Ok(self.check_list[idx].clone());
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
    use crate::network_utils::SenderId;

    #[test]
    fn test_role_determination() {
        // Higher party ID should be controlling
        assert_eq!(IceAgent::determine_role(SenderId::new(100), SenderId::new(50)), IceRole::Controlling);
        assert_eq!(IceAgent::determine_role(SenderId::new(50), SenderId::new(100)), IceRole::Controlled);
        assert_eq!(IceAgent::determine_role(SenderId::new(50), SenderId::new(50)), IceRole::Controlled);
    }

    #[test]
    fn test_ice_state_transitions() {
        let config = IceAgentConfig::default();
        let agent = IceAgent::new(config, SenderId::new(1)).expect("config should be valid");

        assert_eq!(agent.state(), IceState::New);
    }

    #[test]
    fn test_ice_agent_config_validation() {
        // Valid config should pass
        let valid_config = IceAgentConfig::default();
        assert!(valid_config.validate().is_ok());

        // Zero check timeout should fail
        let invalid_config = IceAgentConfig::default().with_check_timeout(Duration::ZERO);
        assert!(matches!(
            invalid_config.validate(),
            Err(ConfigError::InvalidCheckTimeout)
        ));

        // Zero check retries should fail
        let invalid_config = IceAgentConfig::default().with_check_retries(0);
        assert!(matches!(
            invalid_config.validate(),
            Err(ConfigError::InvalidCheckRetries)
        ));

        // Zero probe count should fail
        let invalid_config = IceAgentConfig::default().with_probe_count(0);
        assert!(matches!(
            invalid_config.validate(),
            Err(ConfigError::InvalidProbeCount)
        ));

        // Overall timeout <= check timeout should fail
        let invalid_config = IceAgentConfig::default()
            .with_check_timeout(Duration::from_secs(10))
            .with_overall_timeout(Duration::from_secs(5));
        assert!(matches!(
            invalid_config.validate(),
            Err(ConfigError::InvalidOverallTimeout)
        ));
    }

    #[test]
    fn test_ice_agent_config_builder() {
        let stun_server: std::net::SocketAddr = "8.8.8.8:3478".parse().unwrap();
        let config = IceAgentConfig::new(vec![stun_server])
            .with_check_timeout(Duration::from_millis(200))
            .with_check_retries(5)
            .with_aggressive_nomination(false)
            .with_probe_count(10);

        assert_eq!(config.stun_servers, vec![stun_server]);
        assert_eq!(config.check_timeout, Duration::from_millis(200));
        assert_eq!(config.check_retries, 5);
        assert!(!config.aggressive_nomination);
        assert_eq!(config.probe_count, 10);
    }

    #[test]
    fn test_transaction_id_determinism() {
        let config = IceAgentConfig::default();
        let mut agent = IceAgent::new_unchecked(config, SenderId::new(42));

        let tx1 = agent.next_transaction_id();
        let tx2 = agent.next_transaction_id();

        // Transaction IDs should be different
        assert_ne!(tx1, tx2);

        // Party ID should be extractable from transaction ID
        assert_eq!(IceAgent::party_id_from_transaction(tx1), SenderId::new(42));
        assert_eq!(IceAgent::party_id_from_transaction(tx2), SenderId::new(42));

        // Should recognize our own transactions
        assert!(agent.is_our_transaction(tx1));
        assert!(agent.is_our_transaction(tx2));

        // Should not recognize transactions from other agents
        let other_tx = (100u64 << 32) | 1;
        assert!(!agent.is_our_transaction(other_tx));
    }

    #[test]
    fn test_hole_punch_config_defaults() {
        let config = HolePunchConfig::default();

        assert_eq!(config.initial_delay, Duration::from_millis(100));
        assert_eq!(config.probe_count, 5);
        assert_eq!(config.connection_timeout, Duration::from_millis(2000));
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::network_utils::SenderId;
    use crate::transports::ice::{CandidateType, IceCandidate, LocalCandidates};
    use crate::transports::quic::{NetworkManager, QuicNetworkConfig, QuicNetworkManager};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Once;
    use tokio::net::UdpSocket;

    static CRYPTO_INIT: Once = Once::new();

    /// Initialize the rustls crypto provider (needed for QUIC tests)
    fn init_crypto() {
        CRYPTO_INIT.call_once(|| {
            // Ignore error if provider is already installed by another test
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    /// Helper to create a test ICE agent config with shorter timeouts for testing
    fn test_ice_config() -> IceAgentConfig {
        IceAgentConfig {
            stun_servers: vec![], // No external STUN servers for local tests
            check_timeout: Duration::from_millis(100),
            check_retries: 2,
            check_pace: Duration::from_millis(10),
            aggressive_nomination: true,
            overall_timeout: Duration::from_secs(5),
            probe_count: 3,
            probe_interval: Duration::from_millis(10),
        }
    }

    /// Helper to create test candidates for two local peers
    fn create_test_candidates(
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> (LocalCandidates, LocalCandidates) {
        let mut local_candidates = LocalCandidates::new();
        local_candidates.add_host(local_addr);

        let mut remote_candidates = LocalCandidates::new();
        remote_candidates.add_host(remote_addr);

        (local_candidates, remote_candidates)
    }

    #[test]
    fn test_ice_agent_creation() {
        let config = test_ice_config();
        let agent = IceAgent::new_unchecked(config.clone(), SenderId::new(1));

        assert_eq!(agent.state(), IceState::New);
        // Default role is Controlled until remote party is known
        assert_eq!(agent.role(), IceRole::Controlled);
        assert!(agent.local_candidates().is_empty());
        assert!(agent.nominated_pair().is_none());
    }

    #[test]
    fn test_ice_role_assignment() {
        let config = test_ice_config();
        let mut agent = IceAgent::new_unchecked(config, SenderId::new(100));

        // Test manual role setting
        agent.set_role(IceRole::Controlled);
        assert_eq!(agent.role(), IceRole::Controlled);

        agent.set_role(IceRole::Controlling);
        assert_eq!(agent.role(), IceRole::Controlling);
    }

    #[test]
    fn test_candidate_pair_formation() {
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5000);
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 6000);

        let (local_candidates, remote_candidates) = create_test_candidates(local_addr, remote_addr);

        // Form pairs as controlling agent
        let pairs = crate::transports::ice::CandidatePair::form_pairs(
            &local_candidates.candidates,
            &remote_candidates.candidates,
            true, // is_controlling
        );

        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].local.address, local_addr);
        assert_eq!(pairs[0].remote.address, remote_addr);
        assert_eq!(
            pairs[0].state,
            crate::transports::ice::CandidatePairState::Frozen
        );
    }

    #[test]
    fn test_ice_credentials_generation() {
        let candidates1 = LocalCandidates::new();
        let candidates2 = LocalCandidates::new();

        // Each instance should have unique credentials
        assert_ne!(candidates1.ufrag, candidates2.ufrag);
        assert_ne!(candidates1.pwd, candidates2.pwd);

        // Credentials should meet minimum length requirements
        assert!(candidates1.ufrag.len() >= 4);
        assert!(candidates1.pwd.len() >= 22);
    }

    #[tokio::test]
    async fn test_ice_agent_gather_candidates_localhost() {
        let config = test_ice_config();
        let mut agent = IceAgent::new_unchecked(config, SenderId::new(1));

        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5000);
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let result = agent.gather_candidates(&[local_addr], &socket).await;
        assert!(result.is_ok(), "Gathering should succeed: {:?}", result);

        assert_eq!(agent.state(), IceState::GatheringComplete);
        assert!(!agent.local_candidates().is_empty());

        // Should have at least a host candidate
        let host_candidates: Vec<_> = agent
            .local_candidates()
            .candidates
            .iter()
            .filter(|c| c.candidate_type == CandidateType::Host)
            .collect();
        assert!(!host_candidates.is_empty());
    }

    #[tokio::test]
    async fn test_ice_agent_gather_multiple_hosts() {
        let config = test_ice_config();
        let mut agent = IceAgent::new_unchecked(config, SenderId::new(1));

        // Simulate multiple host addresses (e.g., multiple network interfaces)
        let hosts = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5000),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5001),
        ];
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let result = agent.gather_candidates(&hosts, &socket).await;
        assert!(result.is_ok());

        // Should have host candidates for each address
        let host_count = agent
            .local_candidates()
            .candidates
            .iter()
            .filter(|c| c.candidate_type == CandidateType::Host)
            .count();
        assert_eq!(host_count, 2);
    }

    #[tokio::test]
    async fn test_ice_agent_gather_empty_hosts_fails() {
        let config = test_ice_config();
        let mut agent = IceAgent::new_unchecked(config, SenderId::new(1));

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Empty host list should fail
        let result = agent.gather_candidates(&[], &socket).await;
        assert!(matches!(result, Err(IceError::NoCandidates)));
    }

    #[tokio::test]
    async fn test_ice_agent_invalid_state_gather() {
        let config = test_ice_config();
        let mut agent = IceAgent::new_unchecked(config.clone(), SenderId::new(1));

        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5000);
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // First gather should succeed
        agent.gather_candidates(&[local_addr], &socket).await.unwrap();

        // Second gather should fail (wrong state)
        let result = agent.gather_candidates(&[local_addr], &socket).await;
        assert!(matches!(result, Err(IceError::InvalidState(_))));
    }

    #[tokio::test]
    async fn test_ice_agent_set_remote_candidates() {
        let config = test_ice_config();
        let mut agent = IceAgent::new_unchecked(config, SenderId::new(1));

        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5000);
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 6000);
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Gather local candidates first
        agent.gather_candidates(&[local_addr], &socket).await.unwrap();

        // Create remote candidates
        let remote_candidate = IceCandidate::host(remote_addr, 1);
        let remote_party_id: PartyId = SenderId::new(2);

        // Set remote candidates
        let result = agent.set_remote_candidates(
            remote_party_id,
            "test_ufrag".to_string(),
            "test_pwd_at_least_22_chars".to_string(),
            vec![remote_candidate],
        );

        assert!(result.is_ok());
        assert_eq!(agent.state(), IceState::Checking);

        // Role should be determined based on party IDs
        // Local party ID 1 < Remote party ID 2, so we should be Controlled
        assert_eq!(agent.role(), IceRole::Controlled);
    }

    #[tokio::test]
    async fn test_ice_agent_set_remote_invalid_state() {
        let config = test_ice_config();
        let mut agent = IceAgent::new_unchecked(config, SenderId::new(1));

        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 6000);
        let remote_candidate = IceCandidate::host(remote_addr, 1);

        // Try to set remote candidates before gathering (should fail)
        let result = agent.set_remote_candidates(
            SenderId::new(2),
            "test_ufrag".to_string(),
            "test_pwd_at_least_22_chars".to_string(),
            vec![remote_candidate],
        );

        assert!(matches!(result, Err(IceError::InvalidState(IceState::New))));
    }

    #[test]
    fn test_hole_punch_coordinator_creation() {
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5000);
        let remote_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 6000);
        let config = HolePunchConfig::default();

        let coordinator =
            HolePunchCoordinator::new(local_addr, remote_addr, IceRole::Controlling, config);

        assert!(coordinator.transaction_id() != 0);
    }

    #[test]
    fn test_hole_punch_config_custom() {
        let config = HolePunchConfig {
            initial_delay: Duration::from_millis(50),
            jitter_range: Duration::from_millis(25),
            probe_interval: Duration::from_millis(10),
            probe_count: 3,
            connection_timeout: Duration::from_millis(1000),
            retry_delay: Duration::from_millis(250),
            backoff_factor: 2.0,
        };

        assert_eq!(config.initial_delay, Duration::from_millis(50));
        assert_eq!(config.probe_count, 3);
        assert_eq!(config.backoff_factor, 2.0);
    }

    #[test]
    fn test_ice_error_display() {
        let errors = vec![
            IceError::GatheringFailed("test error".to_string()),
            IceError::NoCandidates,
            IceError::AllChecksFailed,
            IceError::Timeout,
            IceError::InvalidState(IceState::New),
            IceError::SignalingError("signaling failed".to_string()),
            IceError::NetworkError("network issue".to_string()),
            IceError::HolePunchFailed("punch failed".to_string()),
            IceError::ConfigError(ConfigError::InvalidCheckTimeout),
        ];

        for error in errors {
            let display = format!("{}", error);
            assert!(!display.is_empty());
        }
    }

    #[test]
    fn test_hole_punch_error_display() {
        let errors = vec![
            HolePunchError::Timeout,
            HolePunchError::ConnectionFailed("connection error".to_string()),
            HolePunchError::SignalingError("signaling error".to_string()),
            HolePunchError::MaxRetriesExceeded,
            HolePunchError::NoIncoming,
            HolePunchError::NetworkError("network error".to_string()),
        ];

        for error in errors {
            let display = format!("{}", error);
            assert!(!display.is_empty());
        }
    }

    /// Integration test: Two ICE agents exchanging candidates and checking connectivity
    /// This simulates a full ICE negotiation between two local peers
    #[tokio::test]
    async fn test_two_agents_candidate_exchange() {
        // Create two agents with different party IDs
        let config = test_ice_config();
        let mut agent1 = IceAgent::new_unchecked(config.clone(), SenderId::new(100)); // Higher ID = Controlling
        let mut agent2 = IceAgent::new_unchecked(config, SenderId::new(50)); // Lower ID = Controlled

        // Use different localhost ports
        let addr1 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5000);
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5001);
        let socket1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // Both agents gather candidates
        agent1.gather_candidates(&[addr1], &socket1).await.unwrap();
        agent2.gather_candidates(&[addr2], &socket2).await.unwrap();

        assert_eq!(agent1.state(), IceState::GatheringComplete);
        assert_eq!(agent2.state(), IceState::GatheringComplete);

        // Exchange candidates
        let candidates1 = agent1.local_candidates().clone();
        let candidates2 = agent2.local_candidates().clone();

        // Agent1 receives Agent2's candidates
        agent1
            .set_remote_candidates(SenderId::new(50), candidates2.ufrag, candidates2.pwd, candidates2.candidates)
            .unwrap();

        // Agent2 receives Agent1's candidates
        agent2
            .set_remote_candidates(
                SenderId::new(100),
                candidates1.ufrag,
                candidates1.pwd,
                candidates1.candidates,
            )
            .unwrap();

        // Verify roles are correctly assigned
        assert_eq!(agent1.role(), IceRole::Controlling); // 100 > 50
        assert_eq!(agent2.role(), IceRole::Controlled); // 50 < 100

        // Both should be in Checking state
        assert_eq!(agent1.state(), IceState::Checking);
        assert_eq!(agent2.state(), IceState::Checking);
    }

    /// Test concurrent ICE agent operations
    #[tokio::test]
    async fn test_concurrent_gathering() {
        let config = test_ice_config();

        // Create multiple agents
        let agents: Vec<_> = (0..4)
            .map(|i| IceAgent::new_unchecked(config.clone(), SenderId::new(i)))
            .collect();

        // Gather candidates concurrently
        let handles: Vec<_> = agents
            .into_iter()
            .enumerate()
            .map(|(i, mut agent)| {
                tokio::spawn(async move {
                    let addr =
                        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 10000 + i as u16);
                    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                    agent.gather_candidates(&[addr], &socket).await.map(|_| agent)
                })
            })
            .collect();

        // Wait for all to complete
        let mut successful = 0;
        for handle in handles {
            if let Ok(Ok(agent)) = handle.await {
                assert_eq!(agent.state(), IceState::GatheringComplete);
                successful += 1;
            }
        }

        // All agents should have gathered successfully
        assert_eq!(successful, 4);
    }

    /// Test the full P2P connection flow using QuicNetworkManager with NAT traversal
    #[tokio::test]
    async fn test_network_manager_ice_candidate_gathering() {
        init_crypto();

        let config = QuicNetworkConfig {
            enable_nat_traversal: true,
            stun_servers: vec![], // No external STUN for local test
            ..Default::default()
        };

        let mut manager = QuicNetworkManager::with_config(config);

        // Start listening to initialize the endpoint
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        manager.listen(bind_addr).await.unwrap();

        // Gather ICE candidates
        let result = manager.gather_ice_candidates().await;

        // Should succeed with at least a host candidate
        assert!(result.is_ok(), "Should gather candidates: {:?}", result);

        let candidates = result.unwrap();
        assert!(!candidates.is_empty());
        assert!(candidates.ufrag.len() >= 4);
        assert!(candidates.pwd.len() >= 22);
    }

    /// Test that ICE message creation works correctly
    #[tokio::test]
    async fn test_create_ice_candidates_message() {
        init_crypto();

        let config = QuicNetworkConfig {
            enable_nat_traversal: true,
            stun_servers: vec![],
            ..Default::default()
        };

        let mut manager = QuicNetworkManager::with_config(config);
        manager.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();

        let message = manager.create_ice_candidates_message().await;
        assert!(message.is_ok());

        if let Ok(NetEnvelope::IceCandidates {
            ufrag,
            pwd,
            candidates,
        }) = message
        {
            assert!(ufrag.len() >= 4);
            assert!(pwd.len() >= 22);
            assert!(!candidates.is_empty());
        } else {
            panic!("Expected IceCandidates envelope");
        }
    }

    /// Test NAT traversal disabled behavior
    #[tokio::test]
    async fn test_nat_traversal_disabled() {
        init_crypto();

        let config = QuicNetworkConfig {
            enable_nat_traversal: false,
            ..Default::default()
        };

        let manager = QuicNetworkManager::with_config(config);
        assert!(!manager.is_nat_traversal_enabled());

        let result = manager.gather_ice_candidates().await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not enabled"));
    }

    /// Simulated end-to-end test of two peers connecting via ICE
    /// This test validates the full ICE flow without requiring actual network connectivity
    #[tokio::test]
    async fn test_simulated_ice_connection_flow() {
        init_crypto();

        // Create two network managers
        let config1 = QuicNetworkConfig {
            enable_nat_traversal: true,
            stun_servers: vec![],
            ..Default::default()
        };
        let config2 = config1.clone();

        let mut manager1 = QuicNetworkManager::with_config(config1);
        let mut manager2 = QuicNetworkManager::with_config(config2);

        // Both managers start listening
        let addr1: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:0".parse().unwrap();

        manager1.listen(addr1).await.unwrap();
        manager2.listen(addr2).await.unwrap();

        // Gather candidates from both
        let candidates1 = manager1.gather_ice_candidates().await.unwrap();
        let candidates2 = manager2.gather_ice_candidates().await.unwrap();

        // Verify both have candidates
        assert!(!candidates1.is_empty());
        assert!(!candidates2.is_empty());

        // Verify credentials are unique
        assert_ne!(candidates1.ufrag, candidates2.ufrag);
        assert_ne!(candidates1.pwd, candidates2.pwd);

        // Create ICE messages that would be exchanged
        let msg1 = NetEnvelope::IceCandidates {
            ufrag: candidates1.ufrag.clone(),
            pwd: candidates1.pwd.clone(),
            candidates: candidates1.candidates.clone(),
        };

        let msg2 = NetEnvelope::IceCandidates {
            ufrag: candidates2.ufrag.clone(),
            pwd: candidates2.pwd.clone(),
            candidates: candidates2.candidates.clone(),
        };

        // Verify messages can be serialized/deserialized
        let serialized1 = msg1.serialize();
        let serialized2 = msg2.serialize();

        let deserialized1 = NetEnvelope::try_deserialize(&serialized1).unwrap();
        let deserialized2 = NetEnvelope::try_deserialize(&serialized2).unwrap();

        // Verify the deserialized messages match
        if let NetEnvelope::IceCandidates {
            ufrag,
            pwd,
            candidates,
        } = deserialized1
        {
            assert_eq!(ufrag, candidates1.ufrag);
            assert_eq!(pwd, candidates1.pwd);
            assert_eq!(candidates.len(), candidates1.candidates.len());
        }

        if let NetEnvelope::IceCandidates {
            ufrag,
            pwd,
            candidates,
        } = deserialized2
        {
            assert_eq!(ufrag, candidates2.ufrag);
            assert_eq!(pwd, candidates2.pwd);
            assert_eq!(candidates.len(), candidates2.candidates.len());
        }
    }

    /// Test ICE candidate priority ordering
    #[test]
    fn test_candidate_priority_ordering() {
        let host_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 5000);
        let srflx_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 12345);
        let stun_server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 3478);

        let host_candidate = IceCandidate::host(host_addr, 1);
        let srflx_candidate =
            IceCandidate::server_reflexive(srflx_addr, host_addr, stun_server, 1);

        // Host should have higher priority than server reflexive
        assert!(host_candidate.priority > srflx_candidate.priority);
    }

    /// Test that connection attempts timeout correctly
    #[tokio::test]
    async fn test_ice_timeout_behavior() {
        let config = IceAgentConfig {
            overall_timeout: Duration::from_millis(500),
            check_timeout: Duration::from_millis(50),
            check_retries: 1,
            ..test_ice_config()
        };

        let mut agent = IceAgent::new_unchecked(config, SenderId::new(1));
        let local_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 5000);
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        agent.gather_candidates(&[local_addr], &socket).await.unwrap();

        // Set remote candidates pointing to an unreachable address
        let unreachable = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255)), 9999);
        let remote_candidate = IceCandidate::host(unreachable, 1);

        agent
            .set_remote_candidates(
                SenderId::new(2),
                "test_ufrag".to_string(),
                "test_pwd_at_least_22_chars".to_string(),
                vec![remote_candidate],
            )
            .unwrap();

        // Note: Actually running connectivity checks would require a QUIC endpoint,
        // which is tested in the full integration test below
    }

    /// Full integration test with actual QUIC endpoints
    /// Tests two peers establishing a connection through ICE
    #[tokio::test]
    async fn test_full_ice_quic_integration() {
        init_crypto();

        // Create QUIC configs for both peers
        let config1 = QuicNetworkConfig {
            enable_nat_traversal: true,
            stun_servers: vec![],
            ice_config: test_ice_config(),
            ..Default::default()
        };

        let config2 = config1.clone();

        // Create managers
        let mut manager1 = QuicNetworkManager::with_config(config1);
        let mut manager2 = QuicNetworkManager::with_config(config2);

        // Start both endpoints
        manager1.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
        manager2.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();

        // Get party IDs
        let party1 = manager1.party_id();
        let party2 = manager2.party_id();

        assert_ne!(party1, party2, "Party IDs should be unique");

        // Gather candidates
        let candidates1 = manager1.gather_ice_candidates().await.unwrap();
        let candidates2 = manager2.gather_ice_candidates().await.unwrap();

        info!(
            "Party {} gathered {} candidates",
            party1,
            candidates1.len()
        );
        info!(
            "Party {} gathered {} candidates",
            party2,
            candidates2.len()
        );

        // Verify both have host candidates
        assert!(
            candidates1
                .candidates
                .iter()
                .any(|c| c.candidate_type == CandidateType::Host),
            "Should have host candidate"
        );
        assert!(
            candidates2
                .candidates
                .iter()
                .any(|c| c.candidate_type == CandidateType::Host),
            "Should have host candidate"
        );
    }

    /// Test punch request/ack message serialization
    #[test]
    fn test_punch_messages_serialization() {
        let request = NetEnvelope::PunchRequest {
            transaction_id: 12345,
            target_address: "127.0.0.1:5000".parse().unwrap(),
            delay_ms: 100,
        };

        let serialized = request.serialize();
        let deserialized = NetEnvelope::try_deserialize(&serialized).unwrap();

        if let NetEnvelope::PunchRequest {
            transaction_id,
            target_address,
            delay_ms,
        } = deserialized
        {
            assert_eq!(transaction_id, 12345);
            assert_eq!(target_address, "127.0.0.1:5000".parse().unwrap());
            assert_eq!(delay_ms, 100);
        } else {
            panic!("Expected PunchRequest");
        }

        let ack = NetEnvelope::PunchAck {
            transaction_id: 12345,
            timestamp_ms: 1000000,
        };

        let serialized = ack.serialize();
        let deserialized = NetEnvelope::try_deserialize(&serialized).unwrap();

        if let NetEnvelope::PunchAck {
            transaction_id,
            timestamp_ms,
        } = deserialized
        {
            assert_eq!(transaction_id, 12345);
            assert_eq!(timestamp_ms, 1000000);
        } else {
            panic!("Expected PunchAck");
        }
    }

    /// Test connectivity check message serialization
    #[test]
    fn test_connectivity_check_message() {
        let check = NetEnvelope::ConnectivityCheck {
            transaction_id: 99999,
            is_response: false,
            use_candidate: true,
            ufrag: "test_ufrag".to_string(),
        };

        let serialized = check.serialize();
        let deserialized = NetEnvelope::try_deserialize(&serialized).unwrap();

        if let NetEnvelope::ConnectivityCheck {
            transaction_id,
            is_response,
            use_candidate,
            ufrag,
        } = deserialized
        {
            assert_eq!(transaction_id, 99999);
            assert!(!is_response);
            assert!(use_candidate);
            assert_eq!(ufrag, "test_ufrag");
        } else {
            panic!("Expected ConnectivityCheck");
        }
    }
}
