use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    sync::Arc,
};
use bincode::deserialize;
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
use log::{debug, error, info, warn};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc::{self, Sender},
    time::{sleep, timeout, Duration, Instant},
};
use shared::{domain::{environment::Environment, node::NodeBehavior}, transaction_generator::TransactionGenerator};
use crate::{
    consensus::dag::DAG,
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
const ROUND_TIMEOUT_MS: u128 = 200;
const RECOVERY_TIMEOUT_MS: u128 = 500;
// Sample size = PRBC_C * sqrt(n), rounded up
const PRBC_C: f64 = 1.4; // ceil(PRBC_C * sqrt(n)) ≈ 4 for n=8

// Dispatcher channel: None = broadcast to all; Some(id) = unicast to that peer.
type DispatchMsg = (Option<NodeId>, PRBCMessage);

// ── Recovery state per in-flight hash ────────────────────────────────────────
struct RecoveryState {
    vote_list: Vec<NodeId>,
    next_idx: usize,
    request_sent_at: Instant,
}

// ── Main struct ───────────────────────────────────────────────────────────────
pub struct PRBCSailfish {
    environment: Environment,
    dag: DAG,
    f: usize,
    public_keys: HashMap<NodeId, PublicKey>,
    transaction_generator: TransactionGenerator,
    private_key: Arc<Keypair>,

    // ── Round / timeout ──────────────────────────────────────────────────────
    round: u64,
    round_start_time: Instant,
    timeout_sent: bool,
    timeout_store: HashMap<u64, BTreeMap<NodeId, Vec<u8>>>,
    current_round_tc: Option<TimeoutCertificate>,

    // ── PRBC control plane ───────────────────────────────────────────────────
    // hash → { voter_id → signature }
    prbc_votes: HashMap<VertexHash, BTreeMap<NodeId, Vec<u8>>>,
    // (round, source) → vertex_hash; set when 2f+1 votes accumulate
    hash_committed: HashMap<(u64, NodeId), VertexHash>,
    // rounds for which the designated leader is hash-committed (suppresses timeout)
    timeout_suspended: HashSet<u64>,

    // ── PRBC data plane ──────────────────────────────────────────────────────
    // full Vertex bodies received via PRBCPropose or Phase 3 recovery
    prbc_payloads: HashMap<VertexHash, Vertex>,
    // vertex_hash → edges; populated from any full Vertex we receive
    known_edges: HashMap<VertexHash, Vec<VertexHash>>,
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
        let transaction_size = environment.transaction_size;
        let n_transactions = environment.n_transactions;

        let mut node = PRBCSailfish {
            environment,
            dag: DAG::new(),
            f,
            public_keys,
            transaction_generator: TransactionGenerator::new(transaction_size, n_transactions),
            private_key: Arc::new(private_key),

            round: 1,
            round_start_time: Instant::now(),
            timeout_sent: false,
            timeout_store: HashMap::new(),
            current_round_tc: None,

            prbc_votes: HashMap::new(),
            hash_committed: HashMap::new(),
            timeout_suspended: HashSet::new(),

            prbc_payloads: HashMap::new(),
            known_edges: HashMap::new(),
            execution_ready: HashSet::new(),
            execution_queue: VecDeque::new(),
            recovery_state: HashMap::new(),

            last_ordered_round: 0,
            consensus_committed_count: 0,
            finalized_block_count: 0,
            already_ordered: HashSet::new(),
            total_bytes_created: 0,
        };
        node.add_genesis_block();
        node
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
                    let new_vertex = self.create_new_vertex(self.round);
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
                                Some(target),
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
        let quorum = 2 * self.f + 1;

        // 1. Do we have 2f+1 hash-committed vertices from prev_round?
        let hc_count = self
            .hash_committed
            .keys()
            .filter(|(r, _)| *r == prev_round)
            .count();

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
            if elapsed > ROUND_TIMEOUT_MS {
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
                let _ = dispatcher_tx.send((None, msg)).await;
                self.timeout_sent = true;
            }
        }
        false
    }

    fn has_leader_hash_committed(&self, round: u64) -> bool {
        let leader_id = (round % self.environment.nodes.len() as u64) as NodeId;
        self.hash_committed.contains_key(&(round, leader_id))
    }

    async fn handle_timeout_vote(&mut self, sender: NodeId, round: u64, signature: Vec<u8>) {
        if round < self.round.saturating_sub(1) {
            return;
        }
        let votes = self.timeout_store.entry(round).or_default();
        votes.insert(sender, signature);
        let quorum = 2 * self.f + 1;

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

    fn create_new_vertex(&mut self, round: u64) -> Vertex {
        let prev_round = round - 1;

        // Edges = all hash-committed hashes from prev_round.
        let edges: Vec<VertexHash> = self
            .hash_committed
            .iter()
            .filter(|((r, _), _)| *r == prev_round)
            .map(|(_, h)| h.clone())
            .collect();

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
            block: bincode::serialize(&self.transaction_generator.generate())
                .expect("Block gen failed"),
            edges,
            signed_round: vec![],
            sample_proof: vec![],
            tc,
            nvc: None,
        };
        v.hash = v.calculate_hash();

        if let Ok(bytes) = bincode::serialize(&v) {
            self.total_bytes_created += bytes.len() as u64;
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
                block: vec![],   // payload pending
                edges: vec![],   // edges unknown until payload arrives
                signed_round: vec![],
                sample_proof: vec![],
                tc: None,
                nvc: None,
            };
            self.dag.insert(skeleton);
        }

        // If we already have the payload, mark execution-ready immediately.
        if let Some(full_vertex) = self.prbc_payloads.get(&hash).cloned() {
            self.on_execution_ready(hash.clone(), full_vertex, dispatcher_tx).await;
        } else if source != self.environment.my_node.id {
            // Start Phase 3 recovery: we have 2f+1 votes but no payload.
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

        // Fill the skeleton in DAG with real block and edges.
        if let Some(entry) = self.dag.vertices.get_mut(&hash) {
            entry.block = vertex.block.clone();
            entry.edges = vertex.edges.clone();
        }
        if let Some(round_verts) = self.dag.rounds.get_mut(&vertex.round) {
            if let Some(v) = round_verts.iter_mut().find(|v| v.hash == hash) {
                v.block = vertex.block.clone();
                v.edges = vertex.edges.clone();
            }
        }

        // Record edges for commit counting and causal traversal.
        self.known_edges.insert(hash.clone(), vertex.edges.clone());

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

            // Leader must be hash-committed.
            let leader_hash = match self.hash_committed.get(&(r, leader_id)).cloned() {
                Some(h) => h,
                None => break,
            };

            // Count round-(r+1) vertices whose known edges include leader_hash.
            let next_round = r + 1;
            let votes = self
                .hash_committed
                .iter()
                .filter(|((rr, _), _)| *rr == next_round)
                .filter(|((_, _), child_hash)| {
                    self.known_edges
                        .get(*child_hash)
                        .map_or(false, |edges| edges.contains(&leader_hash))
                })
                .count();

            if votes >= 2 * self.f + 1 {
                if !self.already_ordered.contains(&leader_hash) {
                    if let Some(leader_v) = self.dag.vertices.get(&leader_hash).cloned() {
                        self.commit_causal_history_prbc(leader_v);
                        self.last_ordered_round = r;
                    }
                }
            } else {
                break;
            }
        }
    }

    fn commit_causal_history_prbc(&mut self, leader: Vertex) {
        let mut stack = vec![leader];

        while let Some(v) = stack.pop() {
            if self.already_ordered.contains(&v.hash) {
                continue;
            }
            self.already_ordered.insert(v.hash.clone());
            self.consensus_committed_count += 1;

            // Two-tiered state:
            if self.execution_ready.contains(&v.hash) {
                // Payload already here → execute now.
                self.finalized_block_count += 1;
            } else {
                // Payload pending → queue for later execution.
                self.execution_queue.push_back(v.hash.clone());
            }

            // Traverse parents via known_edges (real edges, not skeleton).
            if v.round > 0 {
                let edges = self.known_edges.get(&v.hash).cloned().unwrap_or_default();
                for parent_hash in edges {
                    if !self.already_ordered.contains(&parent_hash) {
                        if let Some(parent) = self.dag.vertices.get(&parent_hash).cloned() {
                            stack.push(parent);
                        }
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

        // Idempotent: if we've already processed this exact propose, bail out.
        // Without this guard every duplicate (from S1/S2 forwarding) would
        // re-forward to S2 and re-broadcast a vote, creating an exponential
        // message flood that starves the network.
        if self.prbc_payloads.contains_key(&hash)
            || self.hash_committed.contains_key(&(vertex.round, vertex.source))
        {
            return;
        }

        debug!(
            "[Node {}] 📨 PRBCPropose received: round={} source={}",
            self.environment.my_node.id, vertex.round, vertex.source
        );

        // Validate hash correctness.
        if hash != vertex.calculate_hash() {
            warn!(
                "[Node {}] PRBCPropose: hash mismatch, dropping",
                self.environment.my_node.id
            );
            return;
        }

        // Store payload — only reached once per (round, source, hash).
        self.known_edges.insert(hash.clone(), vertex.edges.clone());
        self.prbc_payloads.insert(hash.clone(), vertex.clone());

        // Sample verification: am I in S1?
        if self.sample_verification(vertex.round, vertex.source) {
            let s2 = self.compute_sample(vertex.round, vertex.source, b"prbc_s2");
            let my_id = self.environment.my_node.id;

            let forward_vertex = if self.environment.my_node.behavior == NodeBehavior::Byz2 {
                // Byz2: tamper the block data but keep the original hash so receivers detect it.
                let mut fake = vertex.clone();
                fake.block = b"byz2_tampered_payload".to_vec();
                warn!("[Node {}] BYZ2: forwarding FAKE vertex in S1→S2 for round={} source={}",
                    my_id, vertex.round, vertex.source);
                fake
            } else {
                vertex.clone()
            };

            for target in s2 {
                if target != my_id {
                    let _ = dispatcher_tx
                        .send((
                            Some(target),
                            PRBCMessage::PRBCPropose(PRBCProposeMessage {
                                vertex: forward_vertex.clone(),
                            }),
                        ))
                        .await;
                }
            }
        }

        // Every node broadcasts a vote on hash(v).
        let my_id = self.environment.my_node.id;
        let vote_payload = [hash.as_slice(), &vertex.round.to_be_bytes()].concat();
        let sig = self.private_key.sign(&vote_payload).to_bytes().to_vec();

        // Broadcast vote to all peers.
        let _ = dispatcher_tx
            .send((
                None,
                PRBCMessage::PRBCVote(PRBCVoteMessage {
                    round: vertex.round,
                    source: vertex.source,
                    hash: hash.clone(),
                    voter: my_id,
                    signature: sig.clone(),
                }),
            ))
            .await;

        // Count own vote locally.
        self.record_vote(my_id, vertex.round, vertex.source, hash, sig, dispatcher_tx)
            .await;
    }

    async fn handle_prbc_vote(
        &mut self,
        _sender: NodeId,
        vote: PRBCVoteMessage,
        dispatcher_tx: &Sender<DispatchMsg>,
    ) {
        debug!(
            "[Node {}] 🗳 PRBCVote received: round={} source={} voter={}",
            self.environment.my_node.id, vote.round, vote.source, vote.voter
        );

        // Authenticate: verify signature over hash || round.
        let vote_payload = [vote.hash.as_slice(), &vote.round.to_be_bytes()].concat();
        if let Some(pubkey) = self.public_keys.get(&vote.voter) {
            if let Ok(sig) = Signature::from_bytes(&vote.signature) {
                if pubkey.verify(&vote_payload, &sig).is_err() {
                    warn!(
                        "[Node {}] PRBCVote: INVALID SIGNATURE from voter {} for round={} source={}",
                        self.environment.my_node.id, vote.voter, vote.round, vote.source
                    );
                    return;
                }
            } else {
                warn!(
                    "[Node {}] PRBCVote: malformed signature bytes from voter {}",
                    self.environment.my_node.id, vote.voter
                );
                return;
            }
        } else {
            warn!(
                "[Node {}] PRBCVote: unknown voter id={} (not in public_keys)",
                self.environment.my_node.id, vote.voter
            );
            return;
        }

        self.record_vote(
            vote.voter,
            vote.round,
            vote.source,
            vote.hash,
            vote.signature,
            dispatcher_tx,
        )
        .await;
    }

    /// Common path for recording a vote, regardless of whether it came from
    /// handle_prbc_propose (self-vote) or handle_prbc_vote (peer vote).
    async fn record_vote(
        &mut self,
        voter: NodeId,
        round: u64,
        source: NodeId,
        hash: VertexHash,
        sig: Vec<u8>,
        dispatcher_tx: &Sender<DispatchMsg>,
    ) {
        // Skip if already hash-committed for this (round, source).
        if self.hash_committed.contains_key(&(round, source)) {
            return;
        }

        let votes = self.prbc_votes.entry(hash.clone()).or_default();
        votes.insert(voter, sig);
        let quorum = 2 * self.f + 1;

        debug!(
            "[Node {}] 📊 vote recorded: round={} source={} voter={} count={}/{}",
            self.environment.my_node.id, round, source, voter, votes.len(), quorum
        );

        if votes.len() >= quorum {
            let votes_snapshot = votes.clone();
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
        let quorum = 2 * self.f + 1;
        if let Some(vertex) = self.prbc_payloads.get(&msg.hash).cloned() {
            if let Some(votes) = self.prbc_votes.get(&msg.hash) {
                if votes.len() >= quorum {
                    let _ = dispatcher_tx
                        .send((
                            Some(msg.requester),
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
                    Instant::now() - Duration::from_millis(RECOVERY_TIMEOUT_MS as u64 + 1);
            }
            return;
        }

        // Verify vote quorum.
        let quorum = 2 * self.f + 1;
        if msg.votes.len() < quorum {
            warn!(
                "[Node {}] Recovery resp from {}: insufficient votes ({})",
                self.environment.my_node.id,
                sender,
                msg.votes.len()
            );
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
                    - Duration::from_millis(RECOVERY_TIMEOUT_MS as u64 + 1),
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

            if elapsed < RECOVERY_TIMEOUT_MS {
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
                            Some(target),
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
    fn sample_verification(&self, round: u64, source: NodeId) -> bool {
        let s1 = self.compute_sample(round, source, b"prbc_s1");
        s1.contains(&self.environment.my_node.id)
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
        if dispatcher_tx.send((None, msg)).await.is_err() {
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
            signed_round: vec![],
            sample_proof: vec![],
            tc: None,
            nvc: None,
        };
        self.dag.insert(genesis.clone());

        // Pre-populate PRBC state so round-1 vertex creation finds genesis.
        self.hash_committed.insert((0, 0), genesis_hash.clone());
        self.execution_ready.insert(genesis_hash.clone());
        self.known_edges.insert(genesis_hash.clone(), vec![]);
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
        public_keys: HashMap<NodeId, PublicKey>,
        test_flag: bool,
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
            let mut verified = test_flag;
            let mut sig_bytes = [0u8; 64];
            if stream.read_exact(&mut sig_bytes).await.is_err() {
                return;
            }
            if !test_flag {
                if let Some(pubkey) = public_keys.get(&peer_id) {
                    if let Ok(sig) = Signature::from_bytes(&sig_bytes) {
                        if pubkey.verify(&buffer, &sig).is_ok() {
                            verified = true;
                        }
                    }
                }
            }
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

        // Create a per-peer writer channel.
        let mut peer_senders: Vec<Option<mpsc::Sender<Vec<u8>>>> = Vec::new();
        for stream_opt in connections.into_iter() {
            if let Some(mut stream) = stream_opt {
                let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1000);
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
                    let mut frame = Vec::with_capacity(4 + payload.len() + 64);
                    frame.extend_from_slice(&length_bytes);
                    frame.extend_from_slice(&payload);
                    frame.extend_from_slice(sig.as_ref());

                    match target {
                        None => {
                            // Broadcast to all connected peers.
                            for tx in &peer_senders {
                                if let Some(sender) = tx {
                                    let _ = sender.send(frame.clone()).await;
                                }
                            }
                        }
                        Some(node_id) => {
                            // Unicast to a specific peer.
                            if let Some(Some(sender)) = peer_senders.get(node_id as usize) {
                                let _ = sender.send(frame).await;
                            }
                        }
                    }
                }
            }
        });
    }

    fn print_dag_stats(&self) {
        println!(
            "[Node {}] PRBC Final ordered round: {}",
            self.environment.my_node.id, self.last_ordered_round
        );
        println!(
            "Consensus committed: {}  |  Execution ready (finalized): {}",
            self.consensus_committed_count, self.finalized_block_count
        );
    }
}
