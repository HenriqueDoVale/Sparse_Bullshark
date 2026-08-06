use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use bincode::deserialize;
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier}; // Signature/Verifier kept for transport handshake
use log::{debug, error, info, warn};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{
        mpsc::{self, Receiver, Sender},
        Mutex,
    },
    time::{sleep, sleep_until, Duration, Instant},
};
use shared::{domain::{environment::Environment, node::NodeBehavior}, transaction_generator::TransactionGenerator};
use crate::{
    consensus::dag::PRBCDag,
    consensus::mempool::{batch_digest, BatchDigest, BatchStore},
    network::{
        broadcast::generate_nonce,
        message::TimeoutMessage,
        prbc_message::{
            PRBCBatchMessage, PRBCMessage, PRBCProposeMessage, PRBCRecoveryMessage,
            PRBCRecoveryRespMessage, PRBCVoteMessage,
        },
    },
    types::vertex::{NodeId, TimeoutCertificate, Vertex, VertexHash},
};

// ── Network constants (mirrors sailfish.rs) ──────────────────────────────────
const NONCE_BYTES_LENGTH: usize = 32;
const SIGNATURE_BYTES_LENGTH: usize = 64;
const MESSAGE_CHANNEL_SIZE: usize = 1024;
const SOCKET_BINDING_DELAY: u64 = 2;
const MESSAGE_BYTES_LENGTH: usize = 4;
const EXECUTION_DURATION: u64 = 60;
const CONTROL_DRAIN_BUDGET: usize = 256;
const CONSENSUS_DATA_DRAIN_BUDGET: usize = 64;
const DISSEMINATION_DRAIN_BUDGET: usize = 16;

// ── Protocol constants ────────────────────────────────────────────────────────
// Sample size = PRBC_C * sqrt(n), rounded up
const PRBC_C: f64 = 1.4; // ceil(PRBC_C * sqrt(n)) ≈ 4 for n=8

/// Deterministically selects ⌈PRBC_C * √n⌉ node IDs for a given salt.
/// Both the generator task and the consensus actor use this function so they
/// always derive identical S1/S2 routes.
fn compute_sample_for_nodes(
    node_ids: &[NodeId],
    batch_hash: &[u8],
    salt: &[u8],
) -> HashSet<NodeId> {
    let sample_size = ((node_ids.len() as f64).sqrt() * PRBC_C).ceil() as usize;
    let sample_size = sample_size.min(node_ids.len());

    let mut seed_input = Vec::new();
    seed_input.extend_from_slice(batch_hash);
    seed_input.extend_from_slice(salt);
    let seed = Sha256::digest(&seed_input);

    let mut scored: Vec<(u64, NodeId)> = node_ids
        .iter()
        .map(|id| {
            let mut h = Sha256::new();
            h.update(&seed);
            h.update(&id.to_be_bytes());
            let d = h.finalize();
            let score = u64::from_be_bytes(d[..8].try_into().unwrap());
            (score, *id)
        })
        .collect();

    scored.sort_unstable();
    scored.iter().take(sample_size).map(|(_, id)| *id).collect()
}

// Dispatcher routing tag.
#[derive(Debug)]
enum DispatchTarget {
    All,
    One(NodeId),
    Many(Vec<NodeId>),
}

type DispatchMsg = (DispatchTarget, PRBCMessage);
type PRBCVoteKey = (u64, NodeId, VertexHash);

#[derive(Clone)]
struct MessageDispatcher {
    control_tx: Sender<DispatchMsg>,
    consensus_data_tx: Sender<DispatchMsg>,
    dissemination_tx: Sender<DispatchMsg>,
}

impl MessageDispatcher {
    async fn send(
        &self,
        dispatch: DispatchMsg,
    ) -> Result<(), mpsc::error::SendError<DispatchMsg>> {
        match TrafficPlane::for_message(&dispatch.1) {
            TrafficPlane::Control => self.control_tx.send(dispatch).await,
            TrafficPlane::ConsensusData => self.consensus_data_tx.send(dispatch).await,
            TrafficPlane::Dissemination => self.dissemination_tx.send(dispatch).await,
        }
    }
}

#[cfg(test)]
mod traffic_plane_tests {
    use super::*;

    fn vertex() -> Vertex {
        Vertex {
            hash: vec![1; 32],
            round: 1,
            source: 0,
            block: vec![2; 32],
            edges: vec![],
            weak_edges: vec![],
            signed_round: vec![],
            sample_proof: vec![],
            tc: None,
            nvc: None,
        }
    }

    #[test]
    fn classifies_every_prbc_message() {
        let digest = vec![3; 32];
        let cases = [
            (
                PRBCMessage::Batch(PRBCBatchMessage {
                    digest: digest.clone(),
                    payload: vec![4],
                }),
                TrafficPlane::Dissemination,
            ),
            (
                PRBCMessage::PRBCPropose(PRBCProposeMessage { vertex: vertex() }),
                TrafficPlane::ConsensusData,
            ),
            (
                PRBCMessage::PRBCRecoveryResp(PRBCRecoveryRespMessage {
                    vertex: vertex(),
                    votes: BTreeMap::new(),
                }),
                TrafficPlane::ConsensusData,
            ),
            (
                PRBCMessage::PRBCVote(PRBCVoteMessage {
                    round: 1,
                    source: 0,
                    hash: digest.clone(),
                    voter: 1,
                    signature: vec![],
                }),
                TrafficPlane::Control,
            ),
            (
                PRBCMessage::PRBCRecovery(PRBCRecoveryMessage {
                    hash: digest,
                    requester: 1,
                }),
                TrafficPlane::Control,
            ),
            (
                PRBCMessage::Timeout(TimeoutMessage {
                    round: 1,
                    signature: vec![],
                }),
                TrafficPlane::Control,
            ),
        ];

        for (message, expected) in cases {
            assert_eq!(TrafficPlane::for_message(&message), expected);
        }
    }

    #[test]
    fn rejects_unknown_handshake_plane() {
        assert_eq!(TrafficPlane::from_byte(0), Some(TrafficPlane::Control));
        assert_eq!(
            TrafficPlane::from_byte(1),
            Some(TrafficPlane::ConsensusData)
        );
        assert_eq!(
            TrafficPlane::from_byte(2),
            Some(TrafficPlane::Dissemination)
        );
        assert_eq!(TrafficPlane::from_byte(3), None);
    }
}

/// Independent TCP/queue planes. The numeric values are part of the connection
/// handshake and therefore must remain stable across nodes running the same
/// deployment.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
enum TrafficPlane {
    Control = 0,
    ConsensusData = 1,
    Dissemination = 2,
}

impl TrafficPlane {
    const ALL: [Self; 3] = [
        Self::Control,
        Self::ConsensusData,
        Self::Dissemination,
    ];

    fn from_byte(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Control),
            1 => Some(Self::ConsensusData),
            2 => Some(Self::Dissemination),
            _ => None,
        }
    }

    fn for_message(message: &PRBCMessage) -> Self {
        match message {
            PRBCMessage::Batch(_) => Self::Dissemination,
            PRBCMessage::PRBCPropose(_) | PRBCMessage::PRBCRecoveryResp(_) => {
                Self::ConsensusData
            }
            PRBCMessage::PRBCVote(_)
            | PRBCMessage::PRBCRecovery(_)
            | PRBCMessage::Timeout(_) => Self::Control,
        }
    }
}

#[derive(Default)]
struct NetworkTrafficStats {
    control_tx_bytes: AtomicU64,
    control_rx_bytes: AtomicU64,
    consensus_data_tx_bytes: AtomicU64,
    consensus_data_rx_bytes: AtomicU64,
    dissemination_tx_bytes: AtomicU64,
    dissemination_rx_bytes: AtomicU64,
}

impl NetworkTrafficStats {
    fn record_tx(&self, plane: TrafficPlane, bytes: u64) {
        let counter = match plane {
            TrafficPlane::Control => &self.control_tx_bytes,
            TrafficPlane::ConsensusData => &self.consensus_data_tx_bytes,
            TrafficPlane::Dissemination => &self.dissemination_tx_bytes,
        };
        counter.fetch_add(bytes, Ordering::Relaxed);
    }

    fn record_rx(&self, plane: TrafficPlane, bytes: u64) {
        let counter = match plane {
            TrafficPlane::Control => &self.control_rx_bytes,
            TrafficPlane::ConsensusData => &self.consensus_data_rx_bytes,
            TrafficPlane::Dissemination => &self.dissemination_rx_bytes,
        };
        counter.fetch_add(bytes, Ordering::Relaxed);
    }

    fn load(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }
}

/// Aggregate per-node pacer used only by the dissemination plane. Consensus
/// traffic remains unthrottled, so capping batches to the non-consensus share
/// reserves the configured headroom for both consensus planes.
struct BandwidthPacer {
    bytes_per_second: f64,
    next_send: Mutex<Instant>,
}

impl BandwidthPacer {
    fn new(bytes_per_second: f64) -> Self {
        Self {
            bytes_per_second,
            next_send: Mutex::new(Instant::now()),
        }
    }

    async fn wait_for_capacity(&self, bytes: usize) {
        let spacing = Duration::from_secs_f64(bytes as f64 / self.bytes_per_second);
        let scheduled = {
            let mut next_send = self.next_send.lock().await;
            let now = Instant::now();
            if *next_send < now {
                *next_send = now;
            }
            let scheduled = *next_send;
            *next_send += spacing;
            scheduled
        };
        sleep_until(scheduled).await;
    }
}

// ── Recovery state per in-flight hash ────────────────────────────────────────
struct RecoveryState {
    vote_list: Vec<NodeId>,
    next_idx: usize,
    request_sent_at: Instant,
    requested_from: Option<NodeId>,
}

// ── Main struct ───────────────────────────────────────────────────────────────
pub struct PRBCSailfish {
    environment: Environment,
    dag: PRBCDag,
    f: usize,
    public_keys: HashMap<NodeId, PublicKey>,
    batch_receiver: Option<Receiver<(PRBCBatchMessage, Instant)>>,
    private_key: Arc<Keypair>,

    // Transaction batches are disseminated before their vertices. A PRBC
    // vertex carries exactly one SHA-256 batch digest in `Vertex.block`.
    batch_store: BatchStore,
    // Proposals received before their referenced batch are held here and do
    // not receive a PRBC vote until the batch arrives.
    pending_on_batch: HashMap<BatchDigest, Vec<(NodeId, Vertex)>>,
    // Prevent duplicate S1 relays when the same batch reaches an S1 member by
    // more than one best-effort path.
    forwarded_batches: HashSet<BatchDigest>,
    // Avoid hashing, storing, and relaying the same large batch repeatedly.
    seen_batches: HashSet<BatchDigest>,

    // ── Round / timeout ──────────────────────────────────────────────────────
    round: u64,
    round_start_time: Instant,
    timeout_sent: bool,
    timeout_store: HashMap<u64, BTreeMap<NodeId, Vec<u8>>>,
    current_round_tc: Option<TimeoutCertificate>,

    // ── PRBC control plane ───────────────────────────────────────────────────
    // hash → set of voter IDs (authenticated via TCP transport, no per-message sig)
    prbc_votes: HashMap<PRBCVoteKey, BTreeMap<NodeId, Vec<u8>>>,
    // Honest nodes cast at most one vote for each proposer slot.
    voted_hashes: HashMap<(u64, NodeId), VertexHash>,
    // (round, source) → vertex_hash; set when 2f+1 votes accumulate
    hash_committed: HashMap<(u64, NodeId), VertexHash>,
    // O(1) index: round → set of sources that are hash-committed in that round.
    // Avoids the O(total_entries) linear scan in may_advance_round and try_committing_prbc.
    hash_committed_by_round: HashMap<u64, HashSet<NodeId>>,
    // rounds for which the designated leader is hash-committed (suppresses timeout)
    timeout_suspended: HashSet<u64>,

    // ── PRBC data plane ──────────────────────────────────────────────────────
    // full Vertex bodies received via PRBCPropose or Phase 3 recovery
    prbc_payloads: HashMap<VertexHash, Vertex>,
    // vertex_hash → edges; HashSet gives O(1) contains() in the commit rule
    known_edges: HashMap<VertexHash, HashSet<VertexHash>>,
    // hashes whose payload has been locally verified
    execution_ready: HashSet<VertexHash>,
    // consensus-committed vertices that still await payload delivery
    execution_pending: HashSet<VertexHash>,
    // in-flight Phase 3 recovery state machines
    recovery_state: HashMap<VertexHash, RecoveryState>,

    // ── Metrics ──────────────────────────────────────────────────────────────
    last_ordered_round: u64,
    consensus_committed_count: usize, // ordered by hash quorum (control plane)
    pub finalized_block_count: usize, // executed (payload verified, data plane)
    already_ordered: HashSet<VertexHash>,
    total_bytes_created: u64,

    // Consensus latency tracking (vertex creation → commit, all vertices)
    vertex_timestamps: HashMap<VertexHash, Instant>,
    total_commit_latency_us: u128,
    committed_vertex_count: u64,

    // E2E latency tracking (batch creation → commit, own vertices only)
    e2e_timestamps: HashMap<VertexHash, Instant>,
    total_e2e_latency_us: u128,
    e2e_committed_count: u64,

    // Diagnostic counters (printed in stats, medianised by run_linux.py)
    recovery_triggered_count: usize, // Phase 3 recovery started (no payload at hash-quorum)
    race_condition_count: usize,     // propose arrived after hash_committed was already set
    network_traffic: Arc<NetworkTrafficStats>,
    network_limit_mbps: Option<f64>,
    consensus_network_percent: f64,
    dissemination_pacer: Option<Arc<BandwidthPacer>>,

    // Whether to sign and verify PRBC vote messages (enabled via PRBC_SIGS=on)
    sign_votes: bool,

    // Whether to use f+1 quorum instead of 2f+1 (enabled via REDUCED_QUORUM=on)
    reduced_quorum: bool,

    // Configurable timeouts (ms), read from env vars ROUND_TIMEOUT_MS / RECOVERY_TIMEOUT_MS
    round_timeout_ms: u128,
    recovery_timeout_ms: u128,
}

impl PRBCSailfish {
    pub fn new(
        environment: Environment,
        public_keys: HashMap<NodeId, PublicKey>,
        private_key: Keypair,
    ) -> Self {
        println!("PRBCSailfish");
        let n = environment.nodes.len();
        let f = (n.saturating_sub(1)) / 3;
        let network_limit_mbps = std::env::var("NETWORK_MBPS")
            .ok()
            .and_then(|value| value.parse::<f64>().ok())
            .filter(|value| value.is_finite() && *value > 0.0);
        let consensus_network_percent = std::env::var("CONSENSUS_NETWORK_PERCENT")
            .ok()
            .and_then(|value| value.parse::<f64>().ok())
            .filter(|value| value.is_finite() && *value >= 0.0 && *value < 100.0)
            .unwrap_or(20.0);
        let dissemination_pacer = network_limit_mbps.map(|total_mbps| {
            let dissemination_fraction = (100.0 - consensus_network_percent) / 100.0;
            let bytes_per_second = total_mbps * 1_000_000.0 / 8.0 * dissemination_fraction;
            Arc::new(BandwidthPacer::new(bytes_per_second))
        });

        let mut node = PRBCSailfish {
            environment,
            dag: PRBCDag::new(),
            f,
            public_keys,
            batch_receiver: None,
            private_key: Arc::new(private_key),
            batch_store: BatchStore::new(),
            pending_on_batch: HashMap::new(),
            forwarded_batches: HashSet::new(),
            seen_batches: HashSet::new(),

            round: 1,
            round_start_time: Instant::now(),
            timeout_sent: false,
            timeout_store: HashMap::new(),
            current_round_tc: None,

            prbc_votes: HashMap::new(),
            voted_hashes: HashMap::new(),
            hash_committed: HashMap::new(),
            hash_committed_by_round: HashMap::new(),
            timeout_suspended: HashSet::new(),

            prbc_payloads: HashMap::new(),
            known_edges: HashMap::new(),
            execution_ready: HashSet::new(),
            execution_pending: HashSet::new(),
            recovery_state: HashMap::new(),

            last_ordered_round: 0,
            consensus_committed_count: 0,
            finalized_block_count: 0,
            already_ordered: HashSet::new(),
            total_bytes_created: 0,
            vertex_timestamps: HashMap::new(),
            total_commit_latency_us: 0,
            committed_vertex_count: 0,

            e2e_timestamps: HashMap::new(),
            total_e2e_latency_us: 0,
            e2e_committed_count: 0,

            recovery_triggered_count: 0,
            race_condition_count: 0,
            network_traffic: Arc::new(NetworkTrafficStats::default()),
            network_limit_mbps,
            consensus_network_percent,
            dissemination_pacer,

            sign_votes: std::env::var("PRBC_SIGS").as_deref() != Ok("off"),
            reduced_quorum: std::env::var("REDUCED_QUORUM").as_deref() == Ok("on"),

            round_timeout_ms: std::env::var("ROUND_TIMEOUT_MS")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(500),
            recovery_timeout_ms: std::env::var("RECOVERY_TIMEOUT_MS")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(500),
        };
        node.add_genesis_block();
        node
    }

    fn quorum(&self) -> usize {
        if self.reduced_quorum { self.f + 1 } else { 2 * self.f + 1 }
    }

    fn try_next_batch(&mut self) -> Option<(Vec<u8>, Instant)> {
        loop {
            let queued_batch = if let Some(rx) = &mut self.batch_receiver {
                match rx.try_recv() {
                    Ok(queued_batch) => Some(queued_batch),
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => None,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => None,
                }
            } else {
                None
            };

            let Some((batch, created_at)) = queued_batch else {
                return None;
            };

            if batch.digest.len() == 32 && batch_digest(&batch.payload) == batch.digest {
                self.seen_batches.insert(batch.digest.clone());
                self.batch_store
                    .insert(batch.digest.clone(), batch.payload);
                return Some((batch.digest, created_at));
            }
            warn!(
                "[Node {}] Generator produced a batch with an invalid digest",
                self.environment.my_node.id
            );
        }
    }

    // ── Main work loop ────────────────────────────────────────────────────────

    async fn process_work_loop(&mut self, dispatcher_tx: &MessageDispatcher) {
        let mut progress = true;
        while progress {
            progress = false;

            if self.may_advance_round(dispatcher_tx).await {
                progress = true;
                let my_id = self.environment.my_node.id;

                if self.environment.my_node.behavior == NodeBehavior::Silent {
                    // Silent: advance round state but never create or announce a vertex.
                    self.round += 1;
                    self.round_start_time = Instant::now();
                    self.timeout_sent = false;
                    self.current_round_tc = None;
                    warn!("[Node {}] SILENT: skipped PRBC propose for round {}", my_id, self.round - 1);
                } else {
                    // Never block the consensus actor waiting for transaction
                    // generation; it must keep servicing votes and timeouts.
                    let Some((block, batch_time)) = self.try_next_batch() else {
                        return;
                    };
                    let new_vertex = self.create_new_vertex(self.round, block);
                    self.vertex_timestamps.entry(new_vertex.hash.clone()).or_insert_with(Instant::now);
                    self.e2e_timestamps.insert(new_vertex.hash.clone(), batch_time);
                    self.dag.insert(new_vertex.clone());
                    self.round += 1;
                    self.round_start_time = Instant::now();
                    self.timeout_sent = false;
                    self.current_round_tc = None;

                    if self.environment.my_node.behavior == NodeBehavior::Byz1 {
                        // Byz1: send PRBCPropose to only 2f+1 peers via unicast.
                        let quorum = 2 * self.f + 1;
                        let peers: Vec<NodeId> = self.environment.nodes.iter()
                            .map(|n| n.id)
                            .filter(|&id| id != my_id)
                            .take(quorum)
                            .collect();
                        warn!("[Node {}] BYZ1: PRBCPropose to only {}/{} peers",
                            my_id, peers.len(), self.environment.nodes.len() - 1);
                        for target in peers {
                            let _ = dispatcher_tx.send((
                                DispatchTarget::One(target),
                                PRBCMessage::PRBCPropose(PRBCProposeMessage { vertex: new_vertex.clone() }),
                            )).await;
                        }
                    } else {
                        // Ok / Byz2: broadcast normally (byz2 attack fires in S1→S2 forwarding).
                        self.broadcast(
                            PRBCMessage::PRBCPropose(PRBCProposeMessage { vertex: new_vertex.clone() }),
                            dispatcher_tx,
                        ).await;
                    }

                    self.handle_prbc_propose(my_id, new_vertex, dispatcher_tx).await;
                }
            }
        }
    }

    // ── Round advancement ("traffic light") ───────────────────────────────────

    async fn may_advance_round(&mut self, dispatcher_tx: &MessageDispatcher) -> bool {
        if self.round == 1 {
            return true;
        }

        let prev_round = self.round - 1;
        let quorum = self.quorum();

        // 1. Do we have quorum hash-committed vertices from prev_round? O(1) via index.
        let hc_count = self
            .hash_committed_by_round
            .get(&prev_round)
            .map_or(0, |s| s.len());

        if hc_count < quorum {
            debug!(
                "[Node {}] 🛑 STUCK Round {}: need {} hash-commits from round {}, have {}",
                self.environment.my_node.id, self.round, quorum, prev_round, hc_count
            );
            return false;
        }

        // 2. Do we have the Sailfish leader hash-committed for prev_round?
        let has_leader = self.has_leader_hash_committed(prev_round);

        // 3. Do we have a Timeout Certificate for prev_round?
        let has_tc = self.current_round_tc.is_some();

        if has_leader || has_tc {
            return true;
        }

        debug!(
            "[Node {}] 🚦 WAITING Round {}: has_leader={}, has_tc={}, timeout_sent={}",
            self.environment.my_node.id, self.round, has_leader, has_tc, self.timeout_sent
        );

        // Red-light: check if we should send a timeout.
        // Hash Override: if we have 2f+1 hash votes on the leader, suspend the timer.
        if self.timeout_suspended.contains(&prev_round) {
            debug!(
                "[Node {}] ⏸ Timeout suspended for round {} (leader hash-committed, awaiting recovery)",
                self.environment.my_node.id, prev_round
            );
            return false;
        }

        if !self.timeout_sent {
            let elapsed = self.round_start_time.elapsed().as_millis();
            if elapsed > self.round_timeout_ms {
                warn!(
                    "[Node {}] Timeout waiting for Leader in Round {}. Broadcasting TIMEOUT.",
                    self.environment.my_node.id, prev_round
                );
                let payload = prev_round.to_be_bytes();
                let signature = self.private_key.sign(&payload).to_bytes().to_vec();
                let msg = PRBCMessage::Timeout(TimeoutMessage {
                    round: prev_round,
                    signature: signature.clone(),
                });
                self.handle_timeout_vote(
                    self.environment.my_node.id,
                    prev_round,
                    signature,
                )
                .await;
                let _ = dispatcher_tx.send((DispatchTarget::All, msg)).await;
                self.timeout_sent = true;
            }
        }
        false
    }

    fn has_leader_hash_committed(&self, round: u64) -> bool {
        let leader_id = (round % self.environment.nodes.len() as u64) as NodeId;
        self.hash_committed_by_round
            .get(&round)
            .map_or(false, |s| s.contains(&leader_id))
    }

    async fn handle_timeout_vote(&mut self, sender: NodeId, round: u64, signature: Vec<u8>) {
        if round < self.round.saturating_sub(1) {
            return;
        }
        let quorum = self.quorum();
        let votes = self.timeout_store.entry(round).or_default();
        votes.insert(sender, signature);

        if votes.len() >= quorum
            && self.current_round_tc.is_none()
            && round == self.round.saturating_sub(1)
        {
            debug!(
                "[Node {}] Generated Timeout Certificate for Round {}",
                self.environment.my_node.id, round
            );
            self.current_round_tc = Some(TimeoutCertificate {
                round,
                signatures: votes.clone(),
            });
        }
    }

    // ── Vertex creation ────────────────────────────────────────────────────────

    /// BFS from the hash-committed strong edges of round r-1 through all
    /// known_edges and weak_edges. Returns hashes that are hash-committed at
    /// rounds < r-1 but are not reachable through that traversal.
    fn compute_weak_edges_prbc(&self, round: u64, strong_edges: &[VertexHash]) -> Vec<VertexHash> {
        use std::collections::VecDeque;
        let mut reachable: HashSet<VertexHash> = HashSet::new();
        let mut queue: VecDeque<VertexHash> = VecDeque::new();

        for h in strong_edges {
            if reachable.insert(h.clone()) {
                queue.push_back(h.clone());
            }
        }

        while let Some(h) = queue.pop_front() {
            let strong = self.known_edges.get(&h).cloned().unwrap_or_default();
            let weak   = self.dag.vertices.get(&h)
                .map(|v| v.weak_edges.clone())
                .unwrap_or_default();
            for ph in strong.into_iter().chain(weak.into_iter()) {
                if reachable.insert(ph.clone()) {
                    queue.push_back(ph.clone());
                }
            }
        }

        // Any hash-committed hash at round < r-1 not reachable through the chain.
        let mut weak: Vec<VertexHash> = self.hash_committed.iter()
            .filter(|((r, _), h)| {
                *r + 1 < round
                    && *r > 0
                    && !reachable.contains(*h)
                    && !self.already_ordered.contains(*h)
                    && self.dag.vertices.contains_key(*h)
            })
            .map(|(_, h)| h.clone())
            .collect();
        weak.sort();
        weak
    }

    fn create_new_vertex(&mut self, round: u64, block: Vec<u8>) -> Vertex {
        let prev_round = round - 1;

        // Strong edges = all hash-committed hashes from prev_round.
        let edges: Vec<VertexHash> = self
            .hash_committed_by_round
            .get(&prev_round)
            .map_or_else(Vec::new, |sources| {
                sources.iter()
                    .filter_map(|&src| self.hash_committed.get(&(prev_round, src)).cloned())
                    .collect()
            });

        // Weak edges: hash-committed hashes at rounds < r-1 not reachable through strong chain.
        let weak_edges = if round > 1 { self.compute_weak_edges_prbc(round, &edges) } else { vec![] };

        // Sailfish rule: include TC if leader is not hash-committed.
        let tc = if !self.has_leader_hash_committed(prev_round) {
            self.current_round_tc.clone()
        } else {
            None
        };

        let mut v = Vertex {
            hash: vec![],
            round,
            source: self.environment.my_node.id,
            block,
            edges,
            weak_edges,
            signed_round: vec![],
            sample_proof: vec![],
            tc,
            nvc: None,
        };
        v.hash = v.calculate_hash();

        if let Ok(size) = bincode::serialized_size(&v) {
            self.total_bytes_created += size;
        }
        v
    }

    // ── PRBC core ─────────────────────────────────────────────────────────────

    /// Fires when 2f+1 votes accumulate for (round, source, hash).
    async fn on_hash_quorum(
        &mut self,
        round: u64,
        source: NodeId,
        hash: VertexHash,
        votes: BTreeMap<NodeId, Vec<u8>>,
        dispatcher_tx: &MessageDispatcher,
    ) {
        // Dedup
        if self.hash_committed.contains_key(&(round, source)) {
            return;
        }
        debug!(
            "[Node {}] ✅ HASH QUORUM: round={} source={}",
            self.environment.my_node.id, round, source
        );
        self.hash_committed.insert((round, source), hash.clone());
        self.hash_committed_by_round.entry(round).or_default().insert(source);

        // Hash Override: if this is the round leader, suspend the timeout timer.
        let leader_id = (round % self.environment.nodes.len() as u64) as NodeId;
        if source == leader_id {
            self.timeout_suspended.insert(round);
            debug!(
                "[Node {}] ⏸ Suspended timeout for round {} (leader {} hash-committed)",
                self.environment.my_node.id, round, source
            );
        }

        // Insert skeleton into DAG (if full vertex not already there).
        if !self.dag.vertices.contains_key(&hash) {
            let skeleton = Vertex {
                hash: hash.clone(),
                round,
                source,
                block: vec![],       // payload pending
                edges: vec![],       // edges unknown until payload arrives
                weak_edges: vec![],  // filled in by on_execution_ready
                signed_round: vec![],
                sample_proof: vec![],
                tc: None,
                nvc: None,
            };
            self.vertex_timestamps.entry(hash.clone()).or_insert_with(Instant::now);
            self.dag.insert(skeleton);
        }

        // If we already have the payload, mark execution-ready immediately (move, no clone).
        if let Some(full_vertex) = self.prbc_payloads.remove(&hash) {
            self.on_execution_ready(hash.clone(), full_vertex, dispatcher_tx).await;
        } else if source != self.environment.my_node.id {
            // Start Phase 3 recovery: we have 2f+1 votes but no payload.
            self.recovery_triggered_count += 1;
            let vote_list: Vec<NodeId> = votes.keys().cloned().collect();
            self.start_recovery(hash.clone(), vote_list);
        }

        // Re-check commit rule now that we have a new hash-commit.
        self.try_committing_prbc();
    }

    /// Fires when a locally-verified payload is available for `hash`.
    async fn on_execution_ready(
        &mut self,
        hash: VertexHash,
        vertex: Vertex,
        _dispatcher_tx: &MessageDispatcher,
    ) {
        if self.execution_ready.contains(&hash) {
            return;
        }
        self.execution_ready.insert(hash.clone());

        // Build the edge set before moving the complete vertex into the DAG.
        let edge_set: HashSet<VertexHash> = vertex.edges.iter().cloned().collect();
        // Replace the hash-only skeleton with every hash-authenticated field,
        // including timeout/new-view certificates and sampling proofs.
        self.dag.replace_or_insert(vertex);

        // Record edges for commit counting and causal traversal.
        self.known_edges.insert(hash.clone(), edge_set);

        // Stop any in-flight recovery for this hash.
        self.recovery_state.remove(&hash);

        // Re-check commits now that we have real edges for this vertex.
        self.try_committing_prbc();

        // Finalize this hash in O(1) if consensus committed it before its
        // payload arrived. The old queue scan was quadratic during recovery
        // bursts with many missing payloads.
        if self.execution_pending.remove(&hash) {
            self.finalized_block_count += 1;
            if let Some(vertex) = self.dag.vertices.get(&hash) {
                self.batch_store.remove(&vertex.block);
            }
        }
    }

    // ── Commit logic ──────────────────────────────────────────────────────────

    fn try_committing_prbc(&mut self) {
        let start_round = self.round.saturating_sub(1);
        let end_round = self.last_ordered_round;

        for r in (end_round + 1)..=start_round {
            let leader_id = (r % self.environment.nodes.len() as u64) as NodeId;

            // Leader must be hash-committed so we know which hash to look for.
            let leader_hash = match self.hash_committed.get(&(r, leader_id)).cloned() {
                Some(h) => h,
                None => break,
            };

            // Count round-(r+1) vertices whose known edges include leader_hash.
            // Uses the per-round index for O(n_per_round) instead of O(total) scan.
            let next_round = r + 1;
            let votes = self
                .hash_committed_by_round
                .get(&next_round)
                .map_or(0, |sources| {
                    sources.iter().filter(|&&src| {
                        self.hash_committed
                            .get(&(next_round, src))
                            .and_then(|h| self.known_edges.get(h))
                            .map_or(false, |edges| edges.contains(&leader_hash))
                    }).count()
                });

            if votes >= self.quorum() {
                if !self.already_ordered.contains(&leader_hash) {
                    if self.dag.vertices.contains_key(&leader_hash) {
                        self.commit_causal_history_prbc(leader_hash.clone());
                        self.last_ordered_round = r;
                        self.dag.prune_ordered(
                            self.last_ordered_round.saturating_sub(4),
                            &self.already_ordered,
                        );
                        self.prune_prbc_caches();
                    }
                }
            } else {
                break;
            }
        }
    }

    /// Prune payload and vote caches for rounds that are too old to need recovery.
    /// A 128-round window covers a full quorum-candidate retry cycle for the
    /// current experiment sizes even when rounds advance quickly.
    fn prune_prbc_caches(&mut self) {
        // Keep enough history for a recovering node to try every quorum voter.
        // Vote certificates are small; pruning them too aggressively makes
        // healthy peers unable to answer late recovery requests.
        let cutoff = self.last_ordered_round.saturating_sub(128);
        let to_remove: Vec<VertexHash> = self.prbc_payloads
            .iter()
            .filter(|(_, v)| v.round < cutoff)
            .map(|(h, _)| h.clone())
            .collect();
        for h in to_remove {
            self.prbc_payloads.remove(&h);
        }
        self.prbc_votes
            .retain(|(round, _, _), _| *round >= cutoff);
        self.voted_hashes
            .retain(|(round, _), _| *round >= cutoff);
        self.hash_committed_by_round
            .retain(|round, _| *round == 0 || *round >= cutoff);
        self.timeout_store.retain(|round, _| *round >= cutoff);
        self.timeout_suspended.retain(|round| *round >= cutoff);
    }

    fn commit_causal_history_prbc(&mut self, leader_hash: VertexHash) {
        let mut stack = vec![leader_hash];

        while let Some(h) = stack.pop() {
            if self.already_ordered.contains(&h) {
                continue;
            }
            self.already_ordered.insert(h.clone());
            self.consensus_committed_count += 1;
            if let Some(ts) = self.vertex_timestamps.remove(&h) {
                self.total_commit_latency_us += ts.elapsed().as_micros();
                self.committed_vertex_count += 1;
            }
            if let Some(ts) = self.e2e_timestamps.remove(&h) {
                self.total_e2e_latency_us += ts.elapsed().as_micros();
                self.e2e_committed_count += 1;
            }

            // Two-tiered state:
            if self.execution_ready.contains(&h) {
                self.finalized_block_count += 1;
                if let Some(vertex) = self.dag.vertices.get(&h) {
                    self.batch_store.remove(&vertex.block);
                }
            } else {
                self.execution_pending.insert(h.clone());
            }

            // Traverse strong parents (via known_edges) and weak parents.
            // Clone only lightweight hash vecs — no 256KB Vertex copies on the stack.
            let round = self.dag.vertices.get(&h).map(|v| v.round).unwrap_or(0);
            if round > 0 {
                let strong: Vec<VertexHash> = self.known_edges
                    .get(&h)
                    .map(|s| s.iter().cloned().collect())
                    .unwrap_or_default();
                let weak: Vec<VertexHash> = self.dag.vertices
                    .get(&h)
                    .map(|v| v.weak_edges.clone())
                    .unwrap_or_default();
                for parent_hash in strong.into_iter().chain(weak.into_iter()) {
                    if !self.already_ordered.contains(&parent_hash)
                        && self.dag.vertices.contains_key(&parent_hash)
                    {
                        stack.push(parent_hash);
                    }
                }
            }
        }
    }

    // ── PRBC message handlers ─────────────────────────────────────────────────

    async fn handle_prbc_propose(
        &mut self,
        sender: NodeId,
        vertex: Vertex,
        dispatcher_tx: &MessageDispatcher,
    ) {
        let hash = vertex.hash.clone();
        // Extract Copy scalars before vertex is moved.
        let v_round = vertex.round;
        let v_source = vertex.source;

        // Payload already stored or fully execution-ready — nothing to do.
        if self.prbc_payloads.contains_key(&hash) || self.execution_ready.contains(&hash) {
            return;
        }

        debug!(
            "[Node {}] 📨 PRBCPropose received: round={} source={}",
            self.environment.my_node.id, v_round, v_source
        );

        // Validate hash correctness.
        if hash != vertex.calculate_hash() {
            warn!(
                "[Node {}] PRBCPropose: hash mismatch, dropping",
                self.environment.my_node.id
            );
            return;
        }

        // The vertex contains one raw SHA-256 batch digest. Availability of
        // the referenced batch is a prerequisite for casting a PRBC vote.
        if vertex.block.len() != 32 {
            warn!(
                "[Node {}] PRBCPropose: invalid batch digest length {}, dropping",
                self.environment.my_node.id,
                vertex.block.len()
            );
            return;
        }
        let digest = vertex.block.clone();
        if !self.batch_store.contains(&digest) {
            let waiters = self.pending_on_batch.entry(digest).or_default();
            if !waiters.iter().any(|(_, pending)| pending.hash == hash) {
                waiters.push((sender, vertex));
            }
            return;
        }

        if let Some(committed_hash) = self.hash_committed.get(&(v_round, v_source)) {
            if committed_hash != &hash {
                warn!(
                    "[Node {}] PRBCPropose: conflicting hash for committed round={} source={}",
                    self.environment.my_node.id, v_round, v_source
                );
                return;
            }

            self.race_condition_count += 1;
            self.on_execution_ready(hash, vertex, dispatcher_tx).await;
            return;
        }

        if let Some(voted_hash) = self.voted_hashes.get(&(v_round, v_source)) {
            if voted_hash != &hash {
                warn!(
                    "[Node {}] PRBCPropose: refusing a second vote for round={} source={}",
                    self.environment.my_node.id, v_round, v_source
                );
                return;
            }
        } else {
            self.voted_hashes
                .insert((v_round, v_source), hash.clone());
        }

        // Record edges before vertex is moved.
        self.known_edges.insert(hash.clone(), vertex.edges.iter().cloned().collect());

        // Build S1→S2 forward payload and target list BEFORE moving vertex.
        let my_id = self.environment.my_node.id;
        let s2_multicast: Option<(Vec<NodeId>, Vertex)> =
            if self.sample_verification(&digest) {
                let s2_salt =
                    [b"prbc_s2".as_ref(), &my_id.to_be_bytes() as &[u8]].concat();
                let s2 = self.compute_sample(&digest, &s2_salt);
                let targets: Vec<NodeId> = s2.into_iter().filter(|&t| t != my_id).collect();
                if targets.is_empty() {
                    None
                } else {
                    let fwd = if self.environment.my_node.behavior == NodeBehavior::Byz2 {
                        let mut fake = vertex.clone();
                        fake.block = b"byz2_tampered_payload".to_vec();
                        warn!("[Node {}] BYZ2: forwarding FAKE vertex in S1→S2 for round={} source={}",
                            my_id, v_round, v_source);
                        fake
                    } else {
                        vertex.clone()
                    };
                    Some((targets, fwd))
                }
            } else {
                None
            };

        // Move vertex into prbc_payloads — no clone.
        self.prbc_payloads.insert(hash.clone(), vertex);

        // S1→S2 multicast: one serialize+sign for all targets instead of one per target.
        if let Some((targets, fwd)) = s2_multicast {
            let _ = dispatcher_tx
                .send((
                    DispatchTarget::Many(targets),
                    PRBCMessage::PRBCPropose(PRBCProposeMessage { vertex: fwd }),
                ))
                .await;
        }

        // Broadcast vote. When sign_votes is on, include an Ed25519 sig over the hash.
        let my_sig = if self.sign_votes {
            self.private_key.sign(&hash).to_bytes().to_vec()
        } else {
            vec![]
        };
        let _ = dispatcher_tx
            .send((
                DispatchTarget::All,
                PRBCMessage::PRBCVote(PRBCVoteMessage {
                    round: v_round,
                    source: v_source,
                    hash: hash.clone(),
                    voter: my_id,
                    signature: my_sig.clone(),
                }),
            ))
            .await;

        // Count own vote locally.
        self.record_vote(my_id, my_sig, v_round, v_source, hash, dispatcher_tx)
            .await;
    }

    /// Accept a generator broadcast or an S1→S2 relay. Every process is a
    /// valid recipient of the generator's best-effort broadcast; integrity is
    /// established by recomputing the batch digest.
    async fn handle_batch(
        &mut self,
        _sender: NodeId,
        batch: PRBCBatchMessage,
        dispatcher_tx: &MessageDispatcher,
    ) {
        self.accept_batch(batch, dispatcher_tx).await;
    }

    /// Verify and store a batch. If this process is in the hash-derived S1, it
    /// relays the batch once to its own hash-derived S2 before releasing any
    /// pending vertex votes.
    async fn accept_batch(
        &mut self,
        batch: PRBCBatchMessage,
        dispatcher_tx: &MessageDispatcher,
    ) {
        if batch.digest.len() != 32 {
            warn!(
                "[Node {}] Batch: invalid digest length, dropping payload",
                self.environment.my_node.id
            );
            return;
        }

        // Duplicate broadcasts/relays are common in S1/S2 dissemination. Once
        // a digest has been verified, avoid hashing and copying its payload
        // again (including late duplicates after the batch was executed).
        if self.seen_batches.contains(&batch.digest) {
            return;
        }

        if batch_digest(&batch.payload) != batch.digest {
            warn!(
                "[Node {}] Batch: digest mismatch, dropping payload",
                self.environment.my_node.id
            );
            return;
        }
        self.seen_batches.insert(batch.digest.clone());

        let digest = batch.digest.clone();
        let my_id = self.environment.my_node.id;
        let targets = if self.sample_verification(&digest)
            && self.forwarded_batches.insert(digest.clone())
        {
            let s2_salt = [b"prbc_s2".as_ref(), &my_id.to_be_bytes() as &[u8]].concat();
            self
                .compute_sample(&digest, &s2_salt)
                .into_iter()
                .filter(|target| *target != my_id)
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };

        if targets.is_empty() {
            self.batch_store.insert(digest.clone(), batch.payload);
        } else {
            // Retain one copy locally and move the received message into the
            // dispatcher instead of cloning it a second time.
            self.batch_store
                .insert(digest.clone(), batch.payload.clone());
            let _ = dispatcher_tx
                .send((DispatchTarget::Many(targets), PRBCMessage::Batch(batch)))
                .await;
        }

        if let Some(waiters) = self.pending_on_batch.remove(&digest) {
            for (sender, vertex) in waiters {
                self.handle_prbc_propose(sender, vertex, dispatcher_tx).await;
            }
        }
    }

    async fn handle_prbc_vote(
        &mut self,
        sender: NodeId,
        vote: PRBCVoteMessage,
        dispatcher_tx: &MessageDispatcher,
    ) {
        // When signing is on, verify the Ed25519 signature and use msg.voter as identity.
        // When off, fall back to the TCP-authenticated sender.
        let voter = if self.sign_votes {
            match self.public_keys.get(&vote.voter).and_then(|pk| {
                Signature::from_bytes(&vote.signature).ok().and_then(|sig| {
                    pk.verify(&vote.hash, &sig).ok()
                })
            }) {
                Some(_) => vote.voter,
                None => {
                    warn!("[Node {}] PRBC: invalid vote signature from node {}",
                        self.environment.my_node.id, sender);
                    return;
                }
            }
        } else {
            sender
        };

        debug!(
            "[Node {}] PRBCVote received: round={} source={} voter={}",
            self.environment.my_node.id, vote.round, vote.source, voter
        );

        self.record_vote(voter, vote.signature, vote.round, vote.source, vote.hash, dispatcher_tx)
            .await;
    }

    /// Common path for recording a vote, regardless of whether it came from
    /// handle_prbc_propose (self-vote) or handle_prbc_vote (peer vote).
    async fn record_vote(
        &mut self,
        voter: NodeId,
        sig: Vec<u8>,
        round: u64,
        source: NodeId,
        hash: VertexHash,
        dispatcher_tx: &MessageDispatcher,
    ) {
        if self.hash_committed.contains_key(&(round, source)) {
            return;
        }

        let quorum = self.quorum();
        // Keep vote certificates separate by their complete protocol context.
        // Indexing only by hash allowed conflicting round/source metadata to
        // contribute to the same quorum.
        let vote_key = (round, source, hash.clone());
        let votes = self.prbc_votes.entry(vote_key).or_default();
        votes.insert(voter, sig);

        debug!(
            "[Node {}] vote recorded: round={} source={} voter={} count={}/{}",
            self.environment.my_node.id, round, source, voter, votes.len(), quorum
        );

        if votes.len() >= quorum {
            let votes_snapshot = votes.clone();
            // NLL: `votes` (borrow of prbc_votes) ends here.
            self.on_hash_quorum(round, source, hash, votes_snapshot, dispatcher_tx)
                .await;
        }
    }

    async fn handle_prbc_recovery(
        &mut self,
        sender: NodeId,
        msg: PRBCRecoveryMessage,
        dispatcher_tx: &MessageDispatcher,
    ) {
        // The authenticated connection is authoritative. Do not let a peer
        // reflect a large recovery response toward an arbitrary node.
        if msg.requester != sender {
            warn!(
                "[Node {}] Recovery request sender/requester mismatch: {} != {}",
                self.environment.my_node.id, sender, msg.requester
            );
            return;
        }

        // Only respond if we have the payload AND enough votes to prove it.
        // Fall back to dag.vertices if the payload was already moved there by on_hash_quorum.
        let quorum = self.quorum();
        let payload = self.prbc_payloads.get(&msg.hash)
            .or_else(|| self.dag.vertices.get(&msg.hash))
            .cloned();
        if let Some(vertex) = payload {
            let vote_key = (vertex.round, vertex.source, msg.hash.clone());
            if let Some(votes) = self.prbc_votes.get(&vote_key) {
                if votes.len() >= quorum {
                    let _ = dispatcher_tx
                        .send((
                            DispatchTarget::One(sender),
                            PRBCMessage::PRBCRecoveryResp(PRBCRecoveryRespMessage {
                                vertex,
                                votes: votes.clone(),
                            }),
                        ))
                        .await;
                }
            }
        }
    }

    async fn handle_prbc_recovery_resp(
        &mut self,
        sender: NodeId,
        msg: PRBCRecoveryRespMessage,
        dispatcher_tx: &MessageDispatcher,
    ) {
        let hash = msg.vertex.hash.clone();

        // Ignore if we're not waiting for this hash.
        if !self.recovery_state.contains_key(&hash) {
            return;
        }
        if self.execution_ready.contains(&hash) {
            return;
        }
        if self
            .recovery_state
            .get(&hash)
            .and_then(|state| state.requested_from)
            != Some(sender)
        {
            return;
        }

        // Verify hash correctness.
        if hash != msg.vertex.calculate_hash() {
            warn!(
                "[Node {}] Recovery resp from {}: hash mismatch, trying next node",
                self.environment.my_node.id, sender
            );
            self.force_recovery_retry(&hash);
            return;
        }

        // Verify vote quorum certificate.
        let quorum = self.quorum();
        if msg.votes.len() < quorum {
            warn!(
                "[Node {}] Recovery resp from {}: insufficient votes ({})",
                self.environment.my_node.id, sender, msg.votes.len()
            );
            self.force_recovery_retry(&hash);
            return;
        }

        // When vote signatures are enabled, verify each one cryptographically —
        // the certificate is self-contained and does not rely on local state.
        // When disabled, fall back to cross-referencing with TCP-authenticated votes.
        let cert_valid = if self.sign_votes {
            let valid = msg.votes.iter().filter(|(voter_id, sig)| {
                self.public_keys.get(voter_id)
                    .and_then(|pk| Signature::from_bytes(sig).ok().map(|s| (pk, s)))
                    .map_or(false, |(pk, s)| pk.verify(&hash, &s).is_ok())
            }).count();
            valid >= quorum
        } else {
            let vote_key = (msg.vertex.round, msg.vertex.source, hash.clone());
            let my_votes = self.prbc_votes.get(&vote_key).cloned().unwrap_or_default();
            let overlap = msg.votes.keys().filter(|v| my_votes.contains_key(v)).count();
            overlap >= self.f + 1
        };

        if !cert_valid {
            warn!(
                "[Node {}] Recovery resp from {}: invalid vote certificate, trying next",
                self.environment.my_node.id, sender
            );
            self.force_recovery_retry(&hash);
            return;
        }

        // Payload is valid — store and mark execution-ready.
        let digest = msg.vertex.block.clone();
        if digest.len() != 32 {
            self.force_recovery_retry(&hash);
            return;
        }
        if !self.batch_store.contains(&digest) {
            let waiters = self.pending_on_batch.entry(digest).or_default();
            if !waiters.iter().any(|(_, pending)| pending.hash == hash) {
                waiters.push((sender, msg.vertex));
            }
            // The vertex itself was recovered and certified. Batch delivery is
            // tracked independently; do not keep querying peers for the same
            // vertex while waiting for its digest payload.
            self.recovery_state.remove(&hash);
            return;
        }
        self.on_execution_ready(hash, msg.vertex, dispatcher_tx).await;
    }

    fn force_recovery_retry(&mut self, hash: &VertexHash) {
        if let Some(state) = self.recovery_state.get_mut(hash) {
            // tick_recovery advanced next_idx when it selected the current
            // target, so only make the next candidate eligible immediately.
            state.request_sent_at =
                Instant::now() - Duration::from_millis(self.recovery_timeout_ms as u64 + 1);
            state.requested_from = None;
        }
    }

    // ── Phase 3 recovery state machine ────────────────────────────────────────

    fn start_recovery(&mut self, hash: VertexHash, mut vote_list: Vec<NodeId>) {
        if self.execution_ready.contains(&hash) {
            return;
        }
        if self.recovery_state.contains_key(&hash) {
            return;
        }
        debug!(
            "[Node {}] Starting Phase 3 recovery for hash {:?}",
            self.environment.my_node.id,
            &hash[..4.min(hash.len())]
        );
        // Spread first-choice recovery requests across the certificate voters
        // instead of overloading the same lowest-ID node at every requester.
        if !vote_list.is_empty() {
            let hash_offset = hash.first().copied().unwrap_or_default() as usize;
            let rotation =
                (self.environment.my_node.id as usize + hash_offset) % vote_list.len();
            vote_list.rotate_left(rotation);
        }

        // Set request_sent_at in the past so the first tick sends immediately.
        self.recovery_state.insert(
            hash,
            RecoveryState {
                vote_list,
                next_idx: 0,
                request_sent_at: Instant::now()
                    - Duration::from_millis(self.recovery_timeout_ms as u64 + 1),
                requested_from: None,
            },
        );
    }

    /// Driven from the main event loop's 50 ms tick. Sends or retries recovery
    /// requests without spawning extra tasks.
    async fn tick_recovery(&mut self, dispatcher_tx: &MessageDispatcher) {
        let my_id = self.environment.my_node.id;

        let pending_hashes: Vec<VertexHash> = self
            .recovery_state
            .keys()
            .filter(|h| !self.execution_ready.contains(*h))
            .cloned()
            .collect();

        for hash in pending_hashes {
            let elapsed = self
                .recovery_state
                .get(&hash)
                .map(|s| s.request_sent_at.elapsed().as_millis())
                .unwrap_or(u128::MAX);

            if elapsed < self.recovery_timeout_ms {
                continue; // Still waiting for a response.
            }

            // Find next candidate (skip self).
            let target_opt = {
                let state = self.recovery_state.get_mut(&hash).unwrap();
                let mut found = None;
                while state.next_idx < state.vote_list.len() {
                    let candidate = state.vote_list[state.next_idx];
                    state.next_idx += 1;
                    if candidate != my_id {
                        found = Some(candidate);
                        break;
                    }
                }
                found
            };

            match target_opt {
                Some(target) => {
                    debug!(
                        "[Node {}] Recovery: requesting hash {:?} from Node {}",
                        my_id,
                        &hash[..4.min(hash.len())],
                        target
                    );
                    let _ = dispatcher_tx
                        .send((
                            DispatchTarget::One(target),
                            PRBCMessage::PRBCRecovery(PRBCRecoveryMessage {
                                hash: hash.clone(),
                                requester: my_id,
                            }),
                        ))
                        .await;
                    let state = self.recovery_state.get_mut(&hash).unwrap();
                    state.request_sent_at = Instant::now();
                    state.requested_from = Some(target);
                }
                None => {
                    warn!(
                        "[Node {}] Recovery: exhausted all candidates for hash {:?}",
                        my_id,
                        &hash[..4.min(hash.len())]
                    );
                    // If an unrecoverable leader suspended the timeout, resume
                    // the timeout path so the protocol can still make progress.
                    if let Some(vertex) = self.dag.vertices.get(&hash) {
                        let leader =
                            (vertex.round % self.environment.nodes.len() as u64) as NodeId;
                        if vertex.source == leader {
                            self.timeout_suspended.remove(&vertex.round);
                        }
                    }
                    self.recovery_state.remove(&hash);
                }
            }
        }
    }

    // ── Probabilistic sampling ────────────────────────────────────────────────

    /// Returns true if this node is in the S1 selected by the batch hash.
    fn sample_verification(&self, batch_hash: &[u8]) -> bool {
        self.compute_sample(batch_hash, b"prbc_s1")
            .contains(&self.environment.my_node.id)
    }

    /// Deterministically selects ⌈PRBC_C * √n⌉ nodes from a batch hash.
    fn compute_sample(&self, batch_hash: &[u8], salt: &[u8]) -> HashSet<NodeId> {
        let node_ids: Vec<NodeId> = self
            .environment
            .nodes
            .iter()
            .map(|node| node.id)
            .collect();
        compute_sample_for_nodes(&node_ids, batch_hash, salt)
    }

    // ── Network helpers ────────────────────────────────────────────────────────

    async fn broadcast(&self, msg: PRBCMessage, dispatcher_tx: &MessageDispatcher) {
        if dispatcher_tx.send((DispatchTarget::All, msg)).await.is_err() {
            error!(
                "[Node {}] Broadcast failed: channel closed",
                self.environment.my_node.id
            );
        }
    }

    fn add_genesis_block(&mut self) {
        let genesis_hash = vec![0u8; 32];
        let genesis = Vertex {
            hash: genesis_hash.clone(),
            round: 0,
            source: 0,
            block: vec![],
            edges: vec![],
            weak_edges: vec![],
            signed_round: vec![],
            sample_proof: vec![],
            tc: None,
            nvc: None,
        };
        self.dag.insert(genesis.clone());

        // Pre-populate PRBC state so round-1 vertex creation finds genesis.
        self.hash_committed.insert((0, 0), genesis_hash.clone());
        self.hash_committed_by_round.entry(0).or_default().insert(0);
        self.execution_ready.insert(genesis_hash.clone());
        self.known_edges.insert(genesis_hash.clone(), HashSet::new());
        // Genesis is protocol metadata, not an executed transaction block.
        self.already_ordered.insert(genesis_hash.clone());
        self.prbc_payloads.insert(genesis_hash, genesis);
    }

    // ── Network infrastructure (mirrors sailfish.rs) ──────────────────────────

    pub async fn start(mut self) {
        let address = format!(
            "{}:{}",
            self.environment.my_node.host, self.environment.my_node.port
        );
        let listener = TcpListener::bind(&address).await.expect("Failed to bind");
        let (control_message_tx, mut control_message_rx) =
            mpsc::channel::<(NodeId, PRBCMessage)>(MESSAGE_CHANNEL_SIZE);
        let (consensus_data_message_tx, mut consensus_data_message_rx) =
            mpsc::channel::<(NodeId, PRBCMessage)>(MESSAGE_CHANNEL_SIZE);
        let (dissemination_message_tx, mut dissemination_message_rx) =
            mpsc::channel::<(NodeId, PRBCMessage)>(MESSAGE_CHANNEL_SIZE);
        let (control_dispatch_tx, control_dispatch_rx) =
            mpsc::channel::<DispatchMsg>(MESSAGE_CHANNEL_SIZE);
        let (consensus_data_dispatch_tx, consensus_data_dispatch_rx) =
            mpsc::channel::<DispatchMsg>(MESSAGE_CHANNEL_SIZE);
        let (dissemination_dispatch_tx, dissemination_dispatch_rx) =
            mpsc::channel::<DispatchMsg>(MESSAGE_CHANNEL_SIZE);
        let dispatcher_tx = MessageDispatcher {
            control_tx: control_dispatch_tx,
            consensus_data_tx: consensus_data_dispatch_tx,
            dissemination_tx: dissemination_dispatch_tx,
        };

        sleep(Duration::from_secs(SOCKET_BINDING_DELAY)).await;

        let (control_connections, consensus_data_connections, dissemination_connections) = self
            .connect(
                control_message_tx,
                consensus_data_message_tx,
                dissemination_message_tx,
                &listener,
            )
            .await;
        self.start_message_dispatcher(
            control_dispatch_rx,
            consensus_data_dispatch_rx,
            dissemination_dispatch_rx,
            control_connections,
            consensus_data_connections,
            dissemination_connections,
        );

        // Spawn the continuous transaction generator only after network
        // writers exist. It disseminates batches independently; consensus
        // pulls the next available (digest, payload) when building a vertex.
        let tx_size    = self.environment.transaction_size;
        let n_tx       = self.environment.n_transactions;
        let n_nodes    = self.environment.nodes.len() as u64;
        let input_rate = self.environment.input_rate;
        let source = self.environment.my_node.id;
        let node_ids: Vec<NodeId> = self.environment.nodes.iter().map(|node| node.id).collect();
        let (batch_tx, batch_rx) =
            tokio::sync::mpsc::channel::<(PRBCBatchMessage, Instant)>(64);
        self.batch_receiver = Some(batch_rx);
        let batch_dispatcher = dispatcher_tx.clone();
        tokio::spawn(async move {
            let mut gen = TransactionGenerator::new(tx_size, n_tx);

            async fn disseminate_then_enqueue(
                source: NodeId,
                payload: Vec<u8>,
                created_at: Instant,
                node_ids: &[NodeId],
                dispatcher: &MessageDispatcher,
                batch_tx: &Sender<(PRBCBatchMessage, Instant)>,
            ) -> bool {
                let digest = batch_digest(&payload);
                let batch = PRBCBatchMessage {
                    digest,
                    payload,
                };

                // The generator first broadcasts the complete batch to every
                // other process, independently of consensus.
                if dispatcher
                    .send((DispatchTarget::All, PRBCMessage::Batch(batch.clone())))
                    .await
                    .is_err()
                {
                    return false;
                }

                // The source is also a process. If the batch hash selects it
                // for S1, perform its per-member S2 relay immediately.
                let s1 = compute_sample_for_nodes(node_ids, &batch.digest, b"prbc_s1");
                if s1.contains(&source) {
                    let s2_salt =
                        [b"prbc_s2".as_ref(), &source.to_be_bytes() as &[u8]].concat();
                    let s2_targets: Vec<NodeId> =
                        compute_sample_for_nodes(node_ids, &batch.digest, &s2_salt)
                            .into_iter()
                            .filter(|target| *target != source)
                            .collect();
                    if !s2_targets.is_empty()
                        && dispatcher
                            .send((
                                DispatchTarget::Many(s2_targets),
                                PRBCMessage::Batch(batch.clone()),
                            ))
                            .await
                            .is_err()
                    {
                        return false;
                    }
                }

                batch_tx.send((batch, created_at)).await.is_ok()
            }

            if input_rate > 0 {
                let per_node_rate = (input_rate / n_nodes).max(1);
                let interval_us = ((n_tx as u64 * 1_000_000) / per_node_rate).max(1);
                let mut ticker = tokio::time::interval(Duration::from_micros(interval_us));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    ticker.tick().await;
                    let transactions = gen.generate();
                    let created_at = Instant::now();
                    let payload =
                        bincode::serialize(&transactions).expect("batch serialize failed");
                    if !disseminate_then_enqueue(
                        source,
                        payload,
                        created_at,
                        &node_ids,
                        &batch_dispatcher,
                        &batch_tx,
                    ).await {
                        break;
                    }
                }
            } else {
                loop {
                    let transactions = gen.generate();
                    let created_at = Instant::now();
                    let payload =
                        bincode::serialize(&transactions).expect("batch serialize failed");
                    if !disseminate_then_enqueue(
                        source,
                        payload,
                        created_at,
                        &node_ids,
                        &batch_dispatcher,
                        &batch_tx,
                    ).await {
                        break;
                    }
                }
            }
        });

        let start_time = Instant::now();
        let duration = Duration::from_secs(EXECUTION_DURATION);

        // Initial kick
        self.process_work_loop(&dispatcher_tx).await;

        let mut control_open = true;
        let mut consensus_data_open = true;
        let mut dissemination_open = true;
        loop {
            if start_time.elapsed() > duration {
                break;
            }

            // Biased selection always observes votes, timeouts, and recovery
            // requests before considering larger consensus-data or batch frames.
            tokio::select! {
                biased;
                message = control_message_rx.recv(), if control_open => {
                    match message {
                        Some((sender, message)) => {
                            self.handle_incoming_message(sender, message, &dispatcher_tx).await;
                        }
                        None => control_open = false,
                    }
                }
                message = consensus_data_message_rx.recv(), if consensus_data_open => {
                    match message {
                        Some((sender, message)) => {
                            self.handle_incoming_message(sender, message, &dispatcher_tx).await;
                        }
                        None => consensus_data_open = false,
                    }
                }
                message = dissemination_message_rx.recv(), if dissemination_open => {
                    match message {
                        Some((sender, message)) => {
                            self.handle_incoming_message(sender, message, &dispatcher_tx).await;
                        }
                        None => dissemination_open = false,
                    }
                }
                _ = sleep(Duration::from_millis(50)) => {}
            }

            // Amortise actor work while bounding lower-priority service. A
            // batch backlog can no longer monopolise this loop indefinitely.
            for _ in 0..CONTROL_DRAIN_BUDGET {
                let Ok((sender, message)) = control_message_rx.try_recv() else {
                    break;
                };
                self.handle_incoming_message(sender, message, &dispatcher_tx).await;
            }
            for _ in 0..CONSENSUS_DATA_DRAIN_BUDGET {
                let Ok((sender, message)) = consensus_data_message_rx.try_recv() else {
                    break;
                };
                self.handle_incoming_message(sender, message, &dispatcher_tx).await;
            }
            for _ in 0..DISSEMINATION_DRAIN_BUDGET {
                let Ok((sender, message)) = dissemination_message_rx.try_recv() else {
                    break;
                };
                self.handle_incoming_message(sender, message, &dispatcher_tx).await;
                if start_time.elapsed() > duration {
                    break;
                }
            }

            self.tick_recovery(&dispatcher_tx).await;
            self.process_work_loop(&dispatcher_tx).await;

            if !control_open && !consensus_data_open && !dissemination_open {
                break;
            }
        }

        self.print_dag_stats();
        std::process::exit(0);
    }

    async fn handle_incoming_message(
        &mut self,
        sender: NodeId,
        message: PRBCMessage,
        dispatcher_tx: &MessageDispatcher,
    ) {
        match message {
            PRBCMessage::Batch(batch) => self.handle_batch(sender, batch, dispatcher_tx).await,
            PRBCMessage::PRBCPropose(propose) => {
                self.handle_prbc_propose(sender, propose.vertex, dispatcher_tx)
                    .await
            }
            PRBCMessage::PRBCVote(vote) => {
                self.handle_prbc_vote(sender, vote, dispatcher_tx).await
            }
            PRBCMessage::PRBCRecovery(recovery) => {
                self.handle_prbc_recovery(sender, recovery, dispatcher_tx)
                    .await
            }
            PRBCMessage::PRBCRecoveryResp(response) => {
                self.handle_prbc_recovery_resp(sender, response, dispatcher_tx)
                    .await
            }
            PRBCMessage::Timeout(timeout) => {
                self.handle_timeout_vote(sender, timeout.round, timeout.signature)
                    .await
            }
        }
    }

    // Returns one TcpStream per peer for each traffic plane. Keeping control,
    // consensus data, and batch dissemination separate prevents large frames
    // from head-of-line-blocking votes and timeouts.
    async fn connect(
        &self,
        control_sender: Sender<(NodeId, PRBCMessage)>,
        consensus_data_sender: Sender<(NodeId, PRBCMessage)>,
        dissemination_sender: Sender<(NodeId, PRBCMessage)>,
        listener: &TcpListener,
    ) -> (
        Vec<Option<TcpStream>>,
        Vec<Option<TcpStream>>,
        Vec<Option<TcpStream>>,
    ) {
        let n_nodes = self.environment.nodes.len();
        let my_id = self.environment.my_node.id;

        let mut control_connections: Vec<Option<TcpStream>> =
            (0..n_nodes).map(|_| None).collect();
        let mut consensus_data_connections: Vec<Option<TcpStream>> =
            (0..n_nodes).map(|_| None).collect();
        let mut dissemination_connections: Vec<Option<TcpStream>> =
            (0..n_nodes).map(|_| None).collect();

        // Outgoing: three connections per peer — one per traffic plane.
        let mut outgoing_tasks = Vec::new();
        for node in &self.environment.nodes {
            if node.id == my_id {
                continue;
            }
            let target_id = node.id;
            let address = format!("{}:{}", node.host, node.port);

            for plane in TrafficPlane::ALL {
                let address = address.clone();
                let private_key = self.private_key.clone();
                let task = tokio::spawn(async move {
                    loop {
                        if let Ok(mut stream) = TcpStream::connect(&address).await {
                            let _ = stream.set_nodelay(true);
                            let nonce = generate_nonce();
                            let signature = private_key.sign(&nonce);
                            if stream.write_all(&my_id.to_be_bytes()).await.is_err() {
                                sleep(Duration::from_millis(500)).await;
                                continue;
                            }
                            if stream.write_all(&[plane as u8]).await.is_err() {
                                sleep(Duration::from_millis(500)).await;
                                continue;
                            }
                            if stream.write_all(&nonce).await.is_err() {
                                sleep(Duration::from_millis(500)).await;
                                continue;
                            }
                            if stream.write_all(signature.as_ref()).await.is_err() {
                                sleep(Duration::from_millis(500)).await;
                                continue;
                            }
                            return (target_id, plane, Some(stream));
                        }
                        sleep(Duration::from_millis(500)).await;
                    }
                });
                outgoing_tasks.push(task);
            }
        }

        // Incoming: 3×(n-1) connections, one per peer per plane.
        let mut accepted = 0;
        let mut accepted_peer_planes = HashSet::new();
        let expected_connections = TrafficPlane::ALL.len() * (n_nodes - 1);
        info!("[Node {}] Waiting for {} connections...", my_id, expected_connections);

        while accepted < expected_connections {
            if let Ok((mut stream, addr)) = listener.accept().await {
                let _ = stream.set_nodelay(true);
                let mut id_buf = [0u8; 4];
                if stream.read_exact(&mut id_buf).await.is_err() {
                    warn!("[Node {}] Handshake failed: could not read ID from {}.", my_id, addr);
                    continue;
                }
                let claimed_id = u32::from_be_bytes(id_buf);

                let mut plane_buf = [0u8; 1];
                if stream.read_exact(&mut plane_buf).await.is_err() {
                    warn!("[Node {}] Handshake failed: could not read plane from Node {}.", my_id, claimed_id);
                    continue;
                }
                let Some(plane) = TrafficPlane::from_byte(plane_buf[0]) else {
                    warn!(
                        "[Node {}] Handshake failed: invalid traffic plane {} from Node {}.",
                        my_id, plane_buf[0], claimed_id
                    );
                    continue;
                };

                let mut nonce = vec![0u8; NONCE_BYTES_LENGTH];
                if stream.read_exact(&mut nonce).await.is_err() {
                    warn!("[Node {}] Handshake failed: could not read nonce from Node {}.", my_id, claimed_id);
                    continue;
                }
                let mut sig_bytes = vec![0u8; SIGNATURE_BYTES_LENGTH];
                if stream.read_exact(&mut sig_bytes).await.is_err() {
                    warn!("[Node {}] Handshake failed: could not read signature from Node {}.", my_id, claimed_id);
                    continue;
                }

                if let Some(key) = self.public_keys.get(&claimed_id) {
                    if let Ok(sig) = Signature::from_bytes(&sig_bytes) {
                        if key.verify(&nonce, &sig).is_ok() {
                            if !accepted_peer_planes.insert((claimed_id, plane)) {
                                warn!(
                                    "[Node {}] Ignoring duplicate {:?} connection from Node {}",
                                    my_id, plane, claimed_id
                                );
                                continue;
                            }
                            let msg_sender = match plane {
                                TrafficPlane::Control => control_sender.clone(),
                                TrafficPlane::ConsensusData => consensus_data_sender.clone(),
                                TrafficPlane::Dissemination => dissemination_sender.clone(),
                            };
                            let network_traffic = self.network_traffic.clone();
                            tokio::spawn(async move {
                                Self::handle_connection(
                                    stream,
                                    msg_sender,
                                    my_id,
                                    claimed_id,
                                    plane,
                                    network_traffic,
                                )
                                .await;
                            });
                            accepted += 1;
                            info!("[Node {}] Accepted connection from Node {} ({}/{})",
                                my_id, claimed_id, accepted, expected_connections);
                        } else {
                            warn!("[Node {}] Handshake failed: INVALID SIGNATURE from Node {}.", my_id, claimed_id);
                        }
                    }
                } else {
                    warn!("[Node {}] Handshake failed: Unknown Node ID {}.", my_id, claimed_id);
                }
            }
        }

        for task in outgoing_tasks {
            let (id, plane, stream) = task.await.unwrap();
            match plane {
                TrafficPlane::Control => control_connections[id as usize] = stream,
                TrafficPlane::ConsensusData => consensus_data_connections[id as usize] = stream,
                TrafficPlane::Dissemination => dissemination_connections[id as usize] = stream,
            }
        }
        (
            control_connections,
            consensus_data_connections,
            dissemination_connections,
        )
    }

    async fn handle_connection(
        mut stream: TcpStream,
        message_sender: Sender<(NodeId, PRBCMessage)>,
        my_id: NodeId,
        peer_id: NodeId,
        plane: TrafficPlane,
        network_traffic: Arc<NetworkTrafficStats>,
    ) {
        info!(
            "[Node {}] Listening for messages from Node {}",
            my_id, peer_id
        );
        loop {
            let mut length_bytes = [0u8; MESSAGE_BYTES_LENGTH];
            if stream.read_exact(&mut length_bytes).await.is_err() {
                error!("[Node {}] Connection dropped by Node {}", my_id, peer_id);
                return;
            }
            let length = u32::from_be_bytes(length_bytes);
            if length == 0 || length > 10 * 1024 * 1024 {
                return;
            }
            let mut buffer = vec![0; length as usize];
            if stream.read_exact(&mut buffer).await.is_err() {
                return;
            }
            // Read the reserved authentication bytes for wire compatibility.
            // The signed connection handshake already authenticates the peer.
            let mut sig_bytes = [0u8; 64];
            if stream.read_exact(&mut sig_bytes).await.is_err() {
                return;
            }
            if let Ok(message) = deserialize::<PRBCMessage>(&buffer) {
                let expected_plane = TrafficPlane::for_message(&message);
                if expected_plane != plane {
                    warn!(
                        "[Node {}] Dropping {:?} message received from Node {} on {:?} plane",
                        my_id, expected_plane, peer_id, plane
                    );
                    continue;
                }
                let frame_bytes =
                    (MESSAGE_BYTES_LENGTH + length as usize + SIGNATURE_BYTES_LENGTH) as u64;
                network_traffic.record_rx(plane, frame_bytes);
                if message_sender.send((peer_id, message)).await.is_err() {
                    return;
                }
            }
        }
    }

    fn start_message_dispatcher(
        &self,
        control_rx: mpsc::Receiver<DispatchMsg>,
        consensus_data_rx: mpsc::Receiver<DispatchMsg>,
        dissemination_rx: mpsc::Receiver<DispatchMsg>,
        control_connections: Vec<Option<TcpStream>>,
        consensus_data_connections: Vec<Option<TcpStream>>,
        dissemination_connections: Vec<Option<TcpStream>>,
    ) {
        let network_traffic = self.network_traffic.clone();
        let dissemination_pacer = self.dissemination_pacer.clone();

        // Build one write task per peer per plane. Each writer drains its own queue
        // independently, so a large propose frame on the data channel never delays a
        // vote on the control channel.
        fn build_senders(
            connections: Vec<Option<TcpStream>>,
            plane: TrafficPlane,
            network_traffic: Arc<NetworkTrafficStats>,
            pacer: Option<Arc<BandwidthPacer>>,
        ) -> Vec<Option<mpsc::Sender<Arc<Vec<u8>>>>> {
            connections.into_iter().map(|stream_opt| {
                stream_opt.map(|mut stream| {
                    let (tx, mut rx) = mpsc::channel::<Arc<Vec<u8>>>(1000);
                    let network_traffic = network_traffic.clone();
                    let pacer = pacer.clone();
                    tokio::spawn(async move {
                        while let Some(data) = rx.recv().await {
                            if let Some(pacer) = &pacer {
                                pacer.wait_for_capacity(data.len()).await;
                            }
                            if stream.write_all(&data).await.is_err() {
                                break;
                            }
                            network_traffic.record_tx(plane, data.len() as u64);
                        }
                    });
                    tx
                })
            }).collect()
        }

        fn spawn_plane_dispatcher(
            mut receiver: mpsc::Receiver<DispatchMsg>,
            senders: Vec<Option<mpsc::Sender<Arc<Vec<u8>>>>>,
        ) {
            tokio::spawn(async move {
                while let Some((target, message)) = receiver.recv().await {
                    let Ok(payload) = bincode::serialize(&message) else {
                        continue;
                    };
                    let length_bytes = (payload.len() as u32).to_be_bytes();
                    let mut frame_data = Vec::with_capacity(
                        MESSAGE_BYTES_LENGTH + payload.len() + SIGNATURE_BYTES_LENGTH,
                    );
                    frame_data.extend_from_slice(&length_bytes);
                    frame_data.extend_from_slice(&payload);
                    // Per-frame signatures were never verified and consumed
                    // substantial CPU at high batch rates. Keep the bytes for
                    // wire compatibility; authenticate once in the handshake.
                    frame_data.resize(frame_data.len() + SIGNATURE_BYTES_LENGTH, 0);
                    let frame = Arc::new(frame_data);

                    match target {
                        DispatchTarget::All => {
                            for sender in senders.iter().flatten() {
                                let _ = sender.send(frame.clone()).await;
                            }
                        }
                        DispatchTarget::One(node_id) => {
                            if let Some(Some(sender)) = senders.get(node_id as usize) {
                                let _ = sender.send(frame).await;
                            }
                        }
                        DispatchTarget::Many(ids) => {
                            for node_id in ids {
                                if let Some(Some(sender)) = senders.get(node_id as usize) {
                                    let _ = sender.send(frame.clone()).await;
                                }
                            }
                        }
                    }
                }
            });
        }

        let control_senders = build_senders(
            control_connections,
            TrafficPlane::Control,
            network_traffic.clone(),
            None,
        );
        let consensus_data_senders = build_senders(
            consensus_data_connections,
            TrafficPlane::ConsensusData,
            network_traffic.clone(),
            None,
        );
        let dissemination_senders = build_senders(
            dissemination_connections,
            TrafficPlane::Dissemination,
            network_traffic,
            dissemination_pacer,
        );

        spawn_plane_dispatcher(control_rx, control_senders);
        spawn_plane_dispatcher(consensus_data_rx, consensus_data_senders);
        spawn_plane_dispatcher(dissemination_rx, dissemination_senders);
    }

    fn print_dag_stats(&self) {
        let n           = self.environment.nodes.len();
        let f_tolerance = self.f;
        let f_actual    = self.environment.nodes.iter()
                              .filter(|node| node.behavior != NodeBehavior::Ok)
                              .count();
        let tx_size    = self.environment.transaction_size;
        let n_tx       = self.environment.n_transactions;
        let exec_secs  = EXECUTION_DURATION as f64;

        let con_tx    = self.consensus_committed_count * n_tx;
        let exe_tx    = self.finalized_block_count * n_tx;
        let con_bytes = con_tx * tx_size;
        let exe_bytes = exe_tx * tx_size;
        let con_tps   = con_tx as f64 / exec_secs;
        let con_bps   = con_bytes as f64 / exec_secs;
        let exe_tps   = exe_tx as f64 / exec_secs;
        let exe_bps   = exe_bytes as f64 / exec_secs;
        let rps       = self.last_ordered_round as f64 / exec_secs;

        let sigs_label  = if self.sign_votes { "on" } else { "off" };
        let rate_label  = if self.environment.input_rate == 0 {
            "unlimited".to_string()
        } else {
            format!("{} tx/s", self.environment.input_rate)
        };
        let avg_latency_ms = if self.committed_vertex_count > 0 {
            (self.total_commit_latency_us as f64 / self.committed_vertex_count as f64) / 1000.0
        } else { 0.0 };
        let avg_e2e_ms = if self.e2e_committed_count > 0 {
            (self.total_e2e_latency_us as f64 / self.e2e_committed_count as f64) / 1000.0
        } else { 0.0 };
        let control_tx = NetworkTrafficStats::load(&self.network_traffic.control_tx_bytes);
        let control_rx = NetworkTrafficStats::load(&self.network_traffic.control_rx_bytes);
        let consensus_data_tx =
            NetworkTrafficStats::load(&self.network_traffic.consensus_data_tx_bytes);
        let consensus_data_rx =
            NetworkTrafficStats::load(&self.network_traffic.consensus_data_rx_bytes);
        let dissemination_tx =
            NetworkTrafficStats::load(&self.network_traffic.dissemination_tx_bytes);
        let dissemination_rx =
            NetworkTrafficStats::load(&self.network_traffic.dissemination_rx_bytes);
        let consensus_tx = control_tx.saturating_add(consensus_data_tx);
        let consensus_rx = control_rx.saturating_add(consensus_data_rx);
        let total_tx = consensus_tx.saturating_add(dissemination_tx);
        let consensus_tx_share = if total_tx > 0 {
            consensus_tx as f64 * 100.0 / total_tx as f64
        } else {
            0.0
        };
        let consensus_tx_mbps = consensus_tx as f64 * 8.0 / exec_secs / 1_000_000.0;
        let dissemination_tx_mbps = dissemination_tx as f64 * 8.0 / exec_secs / 1_000_000.0;
        let (network_budget_label, consensus_reservation_label, dissemination_cap_label) =
            if let Some(total_mbps) = self.network_limit_mbps {
                (
                    format!("{:.1} Mbps/node", total_mbps),
                    format!("{:.1} %", self.consensus_network_percent),
                    format!(
                        "{:.1} Mbps/node",
                        total_mbps * (100.0 - self.consensus_network_percent) / 100.0
                    ),
                )
            } else {
                (
                    "unlimited".to_string(),
                    "disabled".to_string(),
                    "unlimited".to_string(),
                )
            };

        let quorum_label = if self.reduced_quorum { "f+1" } else { "2f+1" };
        println!("\n+ CONFIG:");
        println!("  Protocol:             PRBC-Sailfish (vote sigs: {}, quorum: {})", sigs_label, quorum_label);
        println!("  Mempool:              decoupled (batch digests)");
        println!("  Faults:               {} node(s)", f_actual);
        println!("  Fault tolerance:      {} node(s)", f_tolerance);
        println!("  Committee size:       {} node(s)", n);
        println!("  Input rate:           {}", rate_label);
        println!("  Transaction size:     {} B", tx_size);
        println!("  Transactions/block:   {}", n_tx);
        println!("  Block size:           {} B", n_tx * tx_size);
        println!("  Execution time:       {} s", EXECUTION_DURATION);
        println!("  Network budget:       {}", network_budget_label);
        println!("  Consensus reservation:  {}", consensus_reservation_label);
        println!("  Dissemination cap:    {}", dissemination_cap_label);
        println!("\n+ RESULTS:");
        println!("  Ordered rounds:       {}", self.last_ordered_round);
        println!("  Blocks finalized:     {}", self.finalized_block_count);
        println!("  Rounds/s:             {:.1}", rps);
        println!("  Consensus TPS:        {:.0} tx/s", con_tps);
        println!("  Consensus BPS:        {:.0} B/s", con_bps);
        println!("  Consensus latency:    {:.1} ms", avg_latency_ms);
        println!("  E2E latency:          {:.1} ms", avg_e2e_ms);
        println!("  Execution TPS:        {:.0} tx/s", exe_tps);
        println!("  Execution BPS:        {:.0} B/s", exe_bps);
        println!("  Phase-3 recoveries:   {}", self.recovery_triggered_count);
        println!("  Race cond. hits:      {}", self.race_condition_count);
        println!("  Batches cached:       {}", self.batch_store.len());
        println!("  Control TX bytes:     {} B", control_tx);
        println!("  Control RX bytes:     {} B", control_rx);
        println!("  Consensus-data TX:    {} B", consensus_data_tx);
        println!("  Consensus-data RX:    {} B", consensus_data_rx);
        println!("  Dissemination TX:     {} B", dissemination_tx);
        println!("  Dissemination RX:     {} B", dissemination_rx);
        println!("  Consensus total TX:   {} B", consensus_tx);
        println!("  Consensus total RX:   {} B", consensus_rx);
        println!("  Consensus TX share:   {:.1} %", consensus_tx_share);
        println!("  Consensus network:    {:.3} Mbps", consensus_tx_mbps);
        println!("  Dissemination network:  {:.3} Mbps", dissemination_tx_mbps);
    }
}
