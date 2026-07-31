use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    sync::Arc,
};
use bincode::deserialize;
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier}; // Signature/Verifier kept for transport handshake
use log::{debug, error, info, warn};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc::{self, Receiver, Sender},
    time::{sleep, timeout, Duration, Instant},
};
use shared::{domain::{environment::Environment, node::NodeBehavior}, transaction_generator::TransactionGenerator};
use crate::{
    consensus::dag::PRBCDag,
    network::{
        broadcast::generate_nonce,
        message::TimeoutMessage,
        prbc_message::{
            PRBCMessage, PRBCProposeMessage, PRBCRecoveryMessage,
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

// ── Protocol constants ────────────────────────────────────────────────────────
// Sample size = PRBC_C * sqrt(n), rounded up
const PRBC_C: f64 = 1.4; // ceil(PRBC_C * sqrt(n)) ≈ 4 for n=8

// Dispatcher routing tag.
#[derive(Debug)]
enum DispatchTarget {
    All,
    One(NodeId),
    Many(Vec<NodeId>),
}

type DispatchMsg = (DispatchTarget, PRBCMessage);

// ── Recovery state per in-flight hash ────────────────────────────────────────
struct RecoveryState {
    vote_list: Vec<NodeId>,
    next_idx: usize,
    request_sent_at: Instant,
}

// ── Main struct ───────────────────────────────────────────────────────────────
pub struct PRBCSailfish {
    environment: Environment,
    dag: PRBCDag,
    f: usize,
    public_keys: HashMap<NodeId, PublicKey>,
    batch_receiver: Option<Receiver<Vec<u8>>>,
    private_key: Arc<Keypair>,

    // ── Round / timeout ──────────────────────────────────────────────────────
    round: u64,
    round_start_time: Instant,
    timeout_sent: bool,
    timeout_store: HashMap<u64, BTreeMap<NodeId, Vec<u8>>>,
    current_round_tc: Option<TimeoutCertificate>,

    // ── PRBC control plane ───────────────────────────────────────────────────
    // hash → set of voter IDs (authenticated via TCP transport, no per-message sig)
    prbc_votes: HashMap<VertexHash, BTreeMap<NodeId, Vec<u8>>>,
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
    // (round, source, is_s1) → sample set; avoids recomputing n SHA-256 ops per round
    sample_cache: HashMap<(u64, NodeId, bool), HashSet<NodeId>>,
    // hashes whose payload has been locally verified
    execution_ready: HashSet<VertexHash>,
    // consensus-committed vertices that still await payload delivery
    execution_queue: VecDeque<VertexHash>,
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

    // E2E latency tracking (batch dequeued → commit, own vertices only)
    e2e_timestamps: HashMap<VertexHash, Instant>,
    total_e2e_latency_us: u128,
    e2e_committed_count: u64,

    // Diagnostic counters (printed in stats, medianised by run_linux.py)
    recovery_triggered_count: usize, // Phase 3 recovery started (no payload at hash-quorum)
    race_condition_count: usize,     // propose arrived after hash_committed was already set

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

        let mut node = PRBCSailfish {
            environment,
            dag: PRBCDag::new(),
            f,
            public_keys,
            batch_receiver: None,
            private_key: Arc::new(private_key),

            round: 1,
            round_start_time: Instant::now(),
            timeout_sent: false,
            timeout_store: HashMap::new(),
            current_round_tc: None,

            prbc_votes: HashMap::new(),
            hash_committed: HashMap::new(),
            hash_committed_by_round: HashMap::new(),
            timeout_suspended: HashSet::new(),

            prbc_payloads: HashMap::new(),
            known_edges: HashMap::new(),
            sample_cache: HashMap::new(),
            execution_ready: HashSet::new(),
            execution_queue: VecDeque::new(),
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

    async fn next_batch(&mut self) -> Vec<u8> {
        if let Some(rx) = &mut self.batch_receiver {
            match rx.try_recv() {
                Ok(b) => return b,
                Err(_) => {
                    if let Some(b) = rx.recv().await {
                        return b;
                    }
                }
            }
        }
        vec![]
    }

    // ── Main work loop ────────────────────────────────────────────────────────

    async fn process_work_loop(&mut self, dispatcher_tx: &Sender<DispatchMsg>) {
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
                    let block = self.next_batch().await;
                    let batch_time = Instant::now(); // E2E start: transactions dequeued, ready to propose
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

    async fn may_advance_round(&mut self, dispatcher_tx: &Sender<DispatchMsg>) -> bool {
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
            .filter(|((r, _), h)| *r + 1 < round && *r > 0 && !reachable.contains(*h))
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
        dispatcher_tx: &Sender<DispatchMsg>,
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
        _dispatcher_tx: &Sender<DispatchMsg>,
    ) {
        if self.execution_ready.contains(&hash) {
            return;
        }
        self.execution_ready.insert(hash.clone());

        // Build edge set before moving fields out of vertex.
        let edge_set: HashSet<VertexHash> = vertex.edges.iter().cloned().collect();
        // Fill the skeleton in DAG with real block, edges, and weak_edges (move, no copy).
        if let Some(entry) = self.dag.vertices.get_mut(&hash) {
            entry.block      = vertex.block;
            entry.edges      = vertex.edges;
            entry.weak_edges = vertex.weak_edges;
        }

        // Record edges for commit counting and causal traversal.
        self.known_edges.insert(hash.clone(), edge_set);

        // Stop any in-flight recovery for this hash.
        self.recovery_state.remove(&hash);

        // Re-check commits now that we have real edges for this vertex.
        self.try_committing_prbc();

        // Drain the execution queue: count any consensus-committed blocks that
        // are now execution-ready. We scan the whole queue and keep only the
        // ones still pending (order doesn't matter for the metric).
        let old_queue = std::mem::take(&mut self.execution_queue);
        for h in old_queue {
            if self.execution_ready.contains(&h) {
                self.finalized_block_count += 1;
            } else {
                self.execution_queue.push_back(h);
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
                        self.dag.prune(self.last_ordered_round.saturating_sub(4));
                        self.prune_prbc_caches();
                    }
                }
            } else {
                break;
            }
        }
    }

    /// Prune payload and vote caches for rounds that are too old to need recovery.
    /// Window of 50 rounds gives ~8 s at 6 rounds/s, enough for all recovery retries
    /// (9 peers × 500 ms recovery timeout = 4.5 s worst case).
    fn prune_prbc_caches(&mut self) {
        let cutoff = self.last_ordered_round.saturating_sub(50);
        let to_remove: Vec<VertexHash> = self.prbc_payloads
            .iter()
            .filter(|(_, v)| v.round < cutoff)
            .map(|(h, _)| h.clone())
            .collect();
        for h in to_remove {
            self.prbc_payloads.remove(&h);
            self.prbc_votes.remove(&h);
        }
        self.sample_cache.retain(|(round, _, _), _| *round >= cutoff);
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
            } else {
                self.execution_queue.push_back(h.clone());
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
        _sender: NodeId,
        vertex: Vertex,
        dispatcher_tx: &Sender<DispatchMsg>,
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

        // Record edges before vertex is moved.
        self.known_edges.insert(hash.clone(), vertex.edges.iter().cloned().collect());

        // Build S1→S2 forward payload and target list BEFORE moving vertex.
        let my_id = self.environment.my_node.id;
        let s2_multicast: Option<(Vec<NodeId>, Vertex)> =
            if self.sample_verification(v_round, v_source) {
                if !self.sample_cache.contains_key(&(v_round, v_source, false)) {
                    let s2_salt = [b"prbc_s2".as_ref(), &my_id.to_be_bytes() as &[u8]].concat();
                    let s2 = self.compute_sample(v_round, v_source, &s2_salt);
                    self.sample_cache.insert((v_round, v_source, false), s2);
                }
                let s2 = self.sample_cache[&(v_round, v_source, false)].clone();
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

        // Race-condition fast path: hash quorum already reached before propose arrived.
        if self.hash_committed.contains_key(&(v_round, v_source)) {
            self.race_condition_count += 1;
            let v = self.prbc_payloads.remove(&hash).unwrap();
            self.on_execution_ready(hash.clone(), v, dispatcher_tx).await;
            return;
        }

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

    async fn handle_prbc_vote(
        &mut self,
        sender: NodeId,
        vote: PRBCVoteMessage,
        dispatcher_tx: &Sender<DispatchMsg>,
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
        dispatcher_tx: &Sender<DispatchMsg>,
    ) {
        if self.hash_committed.contains_key(&(round, source)) {
            return;
        }

        let quorum = self.quorum();
        let votes = self.prbc_votes.entry(hash.clone()).or_default();
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
        _sender: NodeId,
        msg: PRBCRecoveryMessage,
        dispatcher_tx: &Sender<DispatchMsg>,
    ) {
        // Only respond if we have the payload AND enough votes to prove it.
        // Fall back to dag.vertices if the payload was already moved there by on_hash_quorum.
        let quorum = self.quorum();
        let payload = self.prbc_payloads.get(&msg.hash)
            .or_else(|| self.dag.vertices.get(&msg.hash))
            .cloned();
        if let Some(vertex) = payload {
            if let Some(votes) = self.prbc_votes.get(&msg.hash) {
                if votes.len() >= quorum {
                    let _ = dispatcher_tx
                        .send((
                            DispatchTarget::One(msg.requester),
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
        dispatcher_tx: &Sender<DispatchMsg>,
    ) {
        let hash = msg.vertex.hash.clone();

        // Ignore if we're not waiting for this hash.
        if !self.recovery_state.contains_key(&hash) {
            return;
        }
        if self.execution_ready.contains(&hash) {
            return;
        }

        // Verify hash correctness.
        if hash != msg.vertex.calculate_hash() {
            warn!(
                "[Node {}] Recovery resp from {}: hash mismatch, trying next node",
                self.environment.my_node.id, sender
            );
            // Advance the retry index so tick_recovery tries the next node.
            if let Some(state) = self.recovery_state.get_mut(&hash) {
                state.next_idx += 1;
                // Set sent_at far in the past to trigger retry immediately.
                state.request_sent_at =
                    Instant::now() - Duration::from_millis(self.recovery_timeout_ms as u64 + 1);
            }
            return;
        }

        // Verify vote quorum certificate.
        let quorum = self.quorum();
        if msg.votes.len() < quorum {
            warn!(
                "[Node {}] Recovery resp from {}: insufficient votes ({})",
                self.environment.my_node.id, sender, msg.votes.len()
            );
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
            let my_votes = self.prbc_votes.get(&hash).cloned().unwrap_or_default();
            let overlap = msg.votes.keys().filter(|v| my_votes.contains_key(v)).count();
            overlap >= self.f + 1
        };

        if !cert_valid {
            warn!(
                "[Node {}] Recovery resp from {}: invalid vote certificate, trying next",
                self.environment.my_node.id, sender
            );
            if let Some(state) = self.recovery_state.get_mut(&hash) {
                state.next_idx += 1;
                state.request_sent_at =
                    Instant::now() - Duration::from_millis(self.recovery_timeout_ms as u64 + 1);
            }
            return;
        }

        // Payload is valid — store and mark execution-ready.
        self.prbc_payloads.insert(hash.clone(), msg.vertex.clone());
        self.on_execution_ready(hash, msg.vertex, dispatcher_tx).await;
    }

    // ── Phase 3 recovery state machine ────────────────────────────────────────

    fn start_recovery(&mut self, hash: VertexHash, vote_list: Vec<NodeId>) {
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
        // Set request_sent_at in the past so the first tick sends immediately.
        self.recovery_state.insert(
            hash,
            RecoveryState {
                vote_list,
                next_idx: 0,
                request_sent_at: Instant::now()
                    - Duration::from_millis(self.recovery_timeout_ms as u64 + 1),
            },
        );
    }

    /// Driven from the main event loop's 50 ms tick. Sends or retries recovery
    /// requests without spawning extra tasks.
    async fn tick_recovery(&mut self, dispatcher_tx: &Sender<DispatchMsg>) {
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
                    self.recovery_state.get_mut(&hash).unwrap().request_sent_at =
                        Instant::now();
                }
                None => {
                    warn!(
                        "[Node {}] Recovery: exhausted all candidates for hash {:?}",
                        my_id,
                        &hash[..4.min(hash.len())]
                    );
                    self.recovery_state.remove(&hash);
                }
            }
        }
    }

    // ── Probabilistic sampling ────────────────────────────────────────────────

    /// Returns true if this node is in sample S1 for the given (round, source).
    fn sample_verification(&mut self, round: u64, source: NodeId) -> bool {
        if !self.sample_cache.contains_key(&(round, source, true)) {
            let s1 = self.compute_sample(round, source, b"prbc_s1");
            self.sample_cache.insert((round, source, true), s1);
        }
        self.sample_cache[&(round, source, true)].contains(&self.environment.my_node.id)
    }

    /// Deterministically selects ⌈PRBC_C * √n⌉ node IDs for a given salt.
    fn compute_sample(&self, round: u64, source: NodeId, salt: &[u8]) -> HashSet<NodeId> {
        let n = self.environment.nodes.len();
        let sample_size = ((n as f64).sqrt() * PRBC_C).ceil() as usize;
        let sample_size = sample_size.min(n);

        // Seed = SHA256(round || source || salt)
        let mut seed_input = Vec::new();
        seed_input.extend_from_slice(&round.to_be_bytes());
        seed_input.extend_from_slice(&source.to_be_bytes());
        seed_input.extend_from_slice(salt);
        let seed = Sha256::digest(&seed_input);

        // Rank each node by SHA256(seed || node_id), take the top sample_size.
        let mut scored: Vec<(u64, NodeId)> = self
            .environment
            .nodes
            .iter()
            .map(|node| {
                let mut h = Sha256::new();
                h.update(&seed);
                h.update(&node.id.to_be_bytes());
                let d = h.finalize();
                let score = u64::from_be_bytes(d[..8].try_into().unwrap());
                (score, node.id)
            })
            .collect();

        scored.sort_unstable();
        scored.iter().take(sample_size).map(|(_, id)| *id).collect()
    }

    // ── Network helpers ────────────────────────────────────────────────────────

    async fn broadcast(&self, msg: PRBCMessage, dispatcher_tx: &Sender<DispatchMsg>) {
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
        self.prbc_payloads.insert(genesis_hash, genesis);
    }

    // ── Network infrastructure (mirrors sailfish.rs) ──────────────────────────

    pub async fn start(mut self) {
        let address = format!(
            "{}:{}",
            self.environment.my_node.host, self.environment.my_node.port
        );
        let listener = TcpListener::bind(&address).await.expect("Failed to bind");
        let (message_tx, mut message_rx) = mpsc::channel::<(NodeId, PRBCMessage)>(MESSAGE_CHANNEL_SIZE);
        let (dispatcher_tx, dispatcher_rx) = mpsc::channel::<DispatchMsg>(MESSAGE_CHANNEL_SIZE);

        sleep(Duration::from_secs(SOCKET_BINDING_DELAY)).await;

        // Spawn parallel transaction generator.
        let tx_size    = self.environment.transaction_size;
        let n_tx       = self.environment.n_transactions;
        let n_nodes    = self.environment.nodes.len() as u64;
        let input_rate = self.environment.input_rate;
        let (batch_tx, batch_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
        self.batch_receiver = Some(batch_rx);
        tokio::spawn(async move {
            let mut gen = TransactionGenerator::new(tx_size, n_tx);
            if input_rate > 0 {
                let per_node_rate = input_rate / n_nodes;
                let interval_us = (n_tx as u64 * 1_000_000) / per_node_rate;
                let mut ticker = tokio::time::interval(Duration::from_micros(interval_us));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    ticker.tick().await;
                    let batch = bincode::serialize(&gen.generate()).expect("batch serialize failed");
                    if batch_tx.send(batch).await.is_err() { break; }
                }
            } else {
                loop {
                    let batch = bincode::serialize(&gen.generate()).expect("batch serialize failed");
                    if batch_tx.send(batch).await.is_err() { break; }
                }
            }
        });

        let connections = self.connect(message_tx.clone(), &listener).await;
        self.start_message_dispatcher(dispatcher_rx, connections);

        let start_time = Instant::now();
        let duration = Duration::from_secs(EXECUTION_DURATION);

        // Initial kick
        self.process_work_loop(&dispatcher_tx).await;

        loop {
            if start_time.elapsed() > duration {
                break;
            }

            let res = timeout(Duration::from_millis(50), message_rx.recv()).await;

            match res {
                Ok(Some((sender, msg))) => {
                    match msg {
                        PRBCMessage::PRBCPropose(p) => {
                            self.handle_prbc_propose(sender, p.vertex, &dispatcher_tx).await
                        }
                        PRBCMessage::PRBCVote(v) => {
                            self.handle_prbc_vote(sender, v, &dispatcher_tx).await
                        }
                        PRBCMessage::PRBCRecovery(r) => {
                            self.handle_prbc_recovery(sender, r, &dispatcher_tx).await
                        }
                        PRBCMessage::PRBCRecoveryResp(r) => {
                            self.handle_prbc_recovery_resp(sender, r, &dispatcher_tx).await
                        }
                        PRBCMessage::Timeout(t) => {
                            self.handle_timeout_vote(sender, t.round, t.signature).await
                        }
                    }
                }
                Ok(None) => break,
                Err(_) => {} // 50 ms tick — fall through to tick_recovery and work loop
            }

            // Drain any additional messages queued while processing the first one.
            // This amortises the tick_recovery / process_work_loop calls: O(1) per round
            // instead of once per message (previously O(n²) per round at high message rates).
            while let Ok((sender, msg)) = message_rx.try_recv() {
                match msg {
                    PRBCMessage::PRBCPropose(p) => {
                        self.handle_prbc_propose(sender, p.vertex, &dispatcher_tx).await
                    }
                    PRBCMessage::PRBCVote(v) => {
                        self.handle_prbc_vote(sender, v, &dispatcher_tx).await
                    }
                    PRBCMessage::PRBCRecovery(r) => {
                        self.handle_prbc_recovery(sender, r, &dispatcher_tx).await
                    }
                    PRBCMessage::PRBCRecoveryResp(r) => {
                        self.handle_prbc_recovery_resp(sender, r, &dispatcher_tx).await
                    }
                    PRBCMessage::Timeout(t) => {
                        self.handle_timeout_vote(sender, t.round, t.signature).await
                    }
                }
                if start_time.elapsed() > duration {
                    break;
                }
            }

            self.tick_recovery(&dispatcher_tx).await;
            self.process_work_loop(&dispatcher_tx).await;
        }

        self.print_dag_stats();
        std::process::exit(0);
    }

    async fn connect(
        &self,
        message_sender: Sender<(NodeId, PRBCMessage)>,
        listener: &TcpListener,
    ) -> Vec<Option<TcpStream>> {
        let n_nodes = self.environment.nodes.len();
        let my_id = self.environment.my_node.id;

        let mut connections = Vec::with_capacity(n_nodes);
        for _ in 0..n_nodes {
            connections.push(None);
        }

        // Outgoing connections (background retry loop)
        let mut outgoing_tasks = Vec::new();
        for node in &self.environment.nodes {
            if node.id == my_id {
                continue;
            }
            let target_id = node.id;
            let address = format!("{}:{}", node.host, node.port);
            let private_key = self.private_key.clone();

            let task = tokio::spawn(async move {
                loop {
                    if let Ok(mut stream) = TcpStream::connect(&address).await {
                        let nonce = generate_nonce();
                        let signature = private_key.sign(&nonce);
                        if stream.write_all(&my_id.to_be_bytes()).await.is_err() {
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
                        return (target_id, Some(stream));
                    }
                    sleep(Duration::from_millis(500)).await;
                }
            });
            outgoing_tasks.push(task);
        }

        // Incoming connections
        let mut accepted = 0;
        let expected_peers = n_nodes - 1;
        info!("[Node {}] Waiting for {} connections...", my_id, expected_peers);

        while accepted < expected_peers {
            if let Ok((mut stream, addr)) = listener.accept().await {
                let mut id_buf = [0u8; 4];
                if stream.read_exact(&mut id_buf).await.is_err() {
                    warn!(
                        "[Node {}] Handshake failed: could not read ID from {}.",
                        my_id, addr
                    );
                    continue;
                }
                let claimed_id = u32::from_be_bytes(id_buf);

                let mut nonce = vec![0u8; NONCE_BYTES_LENGTH];
                if stream.read_exact(&mut nonce).await.is_err() {
                    warn!(
                        "[Node {}] Handshake failed: could not read nonce from Node {}.",
                        my_id, claimed_id
                    );
                    continue;
                }
                let mut sig_bytes = vec![0u8; SIGNATURE_BYTES_LENGTH];
                if stream.read_exact(&mut sig_bytes).await.is_err() {
                    warn!(
                        "[Node {}] Handshake failed: could not read signature from Node {}.",
                        my_id, claimed_id
                    );
                    continue;
                }

                if let Some(key) = self.public_keys.get(&claimed_id) {
                    if let Ok(sig) = Signature::from_bytes(&sig_bytes) {
                        if key.verify(&nonce, &sig).is_ok() {
                            let msg_sender = message_sender.clone();
                            let pks = self.public_keys.clone();
                            let test_flag = self.environment.test_flag;
                            tokio::spawn(async move {
                                Self::handle_connection(
                                    stream, msg_sender, my_id, claimed_id, pks, test_flag,
                                )
                                .await;
                            });
                            accepted += 1;
                            info!(
                                "[Node {}] Accepted connection from Node {} ({}/{})",
                                my_id, claimed_id, accepted, expected_peers
                            );
                        } else {
                            warn!(
                                "[Node {}] Handshake failed: INVALID SIGNATURE from Node {}.",
                                my_id, claimed_id
                            );
                        }
                    }
                } else {
                    warn!(
                        "[Node {}] Handshake failed: Unknown Node ID {}.",
                        my_id, claimed_id
                    );
                }
            }
        }

        for task in outgoing_tasks {
            let (id, stream) = task.await.unwrap();
            connections[id as usize] = stream;
        }
        connections
    }

    async fn handle_connection(
        mut stream: TcpStream,
        message_sender: Sender<(NodeId, PRBCMessage)>,
        my_id: NodeId,
        peer_id: NodeId,
        _public_keys: HashMap<NodeId, PublicKey>,
        _test_flag: bool,
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
            // Read signature bytes for wire alignment; skip expensive Ed25519 verify
            // (TCP handshake already authenticates the sender).
            let mut sig_bytes = [0u8; 64];
            if stream.read_exact(&mut sig_bytes).await.is_err() {
                return;
            }
            let verified = true;
            if verified {
                if let Ok(message) = deserialize::<PRBCMessage>(&buffer) {
                    if message_sender.send((peer_id, message)).await.is_err() {
                        return;
                    }
                }
            }
        }
    }

    fn start_message_dispatcher(
        &self,
        mut dispatcher_rx: mpsc::Receiver<DispatchMsg>,
        connections: Vec<Option<TcpStream>>,
    ) {
        let private_key = self.private_key.clone();
        let test_flag = self.environment.test_flag;

        // Each peer writer accepts Arc<Vec<u8>> — cloning the Arc is O(1) regardless
        // of payload size, eliminating the O(n × block_size) memcopy on every broadcast.
        let mut peer_senders: Vec<Option<mpsc::Sender<Arc<Vec<u8>>>>> = Vec::new();
        for stream_opt in connections.into_iter() {
            if let Some(mut stream) = stream_opt {
                let (tx, mut rx) = mpsc::channel::<Arc<Vec<u8>>>(1000);
                peer_senders.push(Some(tx));
                tokio::spawn(async move {
                    while let Some(data) = rx.recv().await {
                        if stream.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                });
            } else {
                peer_senders.push(None);
            }
        }

        tokio::spawn(async move {
            while let Some((target, message)) = dispatcher_rx.recv().await {
                if let Ok(payload) = bincode::serialize(&message) {
                    let sig = if !test_flag {
                        private_key.sign(&payload)
                    } else {
                        Signature::from_bytes(&[0u8; 64]).unwrap()
                    };

                    let length_bytes = (payload.len() as u32).to_be_bytes();
                    let mut frame_data = Vec::with_capacity(4 + payload.len() + 64);
                    frame_data.extend_from_slice(&length_bytes);
                    frame_data.extend_from_slice(&payload);
                    frame_data.extend_from_slice(sig.as_ref());
                    // Wrap once in Arc — all broadcast clones are O(1) refcount bumps.
                    let frame = Arc::new(frame_data);

                    match target {
                        DispatchTarget::All => {
                            // Broadcast to all connected peers.
                            for tx in &peer_senders {
                                if let Some(sender) = tx {
                                    let _ = sender.send(frame.clone()).await;
                                }
                            }
                        }
                        DispatchTarget::One(node_id) => {
                            // Unicast to a specific peer.
                            if let Some(Some(sender)) = peer_senders.get(node_id as usize) {
                                let _ = sender.send(frame).await;
                            }
                        }
                        DispatchTarget::Many(ids) => {
                            // Multicast: single serialize+sign, one Arc clone per target.
                            for node_id in ids {
                                if let Some(Some(sender)) = peer_senders.get(node_id as usize) {
                                    let _ = sender.send(frame.clone()).await;
                                }
                            }
                        }
                    }
                }
            }
        });
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

        let quorum_label = if self.reduced_quorum { "f+1" } else { "2f+1" };
        println!("\n+ CONFIG:");
        println!("  Protocol:             PRBC-Sailfish (vote sigs: {}, quorum: {})", sigs_label, quorum_label);
        println!("  Faults:               {} node(s)", f_actual);
        println!("  Fault tolerance:      {} node(s)", f_tolerance);
        println!("  Committee size:       {} node(s)", n);
        println!("  Input rate:           {}", rate_label);
        println!("  Transaction size:     {} B", tx_size);
        println!("  Transactions/block:   {}", n_tx);
        println!("  Block size:           {} B", n_tx * tx_size);
        println!("  Execution time:       {} s", EXECUTION_DURATION);
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
    }
}
