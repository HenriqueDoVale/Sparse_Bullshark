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
    consensus::mempool::{batch_digest, BatchDigest, BatchStore, RetentionStore},
    network::{
        broadcast::generate_nonce,
        message::TimeoutMessage,
        prbc_message::{
            no_vote_signing_bytes, propose_signing_bytes, vote_signing_bytes,
            PRBCBatchMessage, PRBCBatchRequestMessage, PRBCCertRequestMessage,
            PRBCCertificateMessage, PRBCMessage, PRBCNoVoteMessage, PRBCProposeMessage,
            PRBCRecoveryMessage, PRBCRecoveryRespMessage, PRBCVoteMessage,
        },
    },
    types::vertex::{NodeId, NoVoteCertificate, TimeoutCertificate, Vertex, VertexHash},
    utils::metrics::ResourceMeter,
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

// ── Recovery constants ───────────────────────────────────────────────────────
// Ordered vertices stay in the DAG for this many rounds behind the last
// ordered round (see try_committing_prbc).
const DAG_PRUNE_DEPTH: u64 = 4;
// Default for RETENTION_ROUNDS: how long a delivered vertex and batch are kept
// so peers can still fetch them. 50 matches Narwhal's default gc_depth.
const DEFAULT_RETENTION_ROUNDS: u64 = 50;
// After each full pass over the voters with no valid answer, the wait between
// requests doubles, up to 2^3 = 8 x RECOVERY_TIMEOUT_MS.
const MAX_RECOVERY_BACKOFF_SHIFT: u32 = 3;
// Votes, vote records and other pre-quorum state are kept this many rounds
// behind the last ordered round (prune_prbc_caches).
const VOTE_RECORD_ROUNDS: u64 = 128;

// ── Protocol constants ────────────────────────────────────────────────────────
// Sample size = PRBC_C * sqrt(n), rounded up. Default 1.4 (ceil ≈ 4 for n=8) is
// the value validated in RECOVERY_TESTING.md; override with PRBC_SAMPLE_C to
// study how the redundancy/recovery/network tradeoff responds to a different
// constant. Read fresh each call (cheap, once per batch — not a hot per-message
// path) rather than cached, so it's safe to leave unset in the common case.
fn prbc_c() -> f64 {
    std::env::var("PRBC_SAMPLE_C")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v > 0.0)
        .unwrap_or(1.4)
}

/// Deterministically selects ⌈PRBC_C * √n⌉ node IDs for a given salt.
/// Both the generator task and the consensus actor use this function so they
/// always derive identical S1/S2 routes.
fn compute_sample_for_nodes(
    node_ids: &[NodeId],
    batch_hash: &[u8],
    salt: &[u8],
) -> HashSet<NodeId> {
    let sample_size = ((node_ids.len() as f64).sqrt() * prbc_c()).ceil() as usize;
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

/// Check every signature a message carries; false means drop it. Votes,
/// proposals and no-votes must be signed by their voter / source. Certificate
/// votes that fail are removed, and the consensus loop then requires 2f+1 left.
fn verify_signatures(message: &mut PRBCMessage, keys: &HashMap<NodeId, PublicKey>) -> bool {
    let valid = |node: &NodeId, bytes: &[u8], signature: &[u8]| {
        keys.get(node).map_or(false, |pk| {
            Signature::from_bytes(signature).map_or(false, |sig| pk.verify(bytes, &sig).is_ok())
        })
    };
    match message {
        PRBCMessage::PRBCVote(vote) => valid(
            &vote.voter,
            &vote_signing_bytes(vote.round, vote.source, &vote.hash),
            &vote.signature,
        ),
        PRBCMessage::PRBCPropose(propose) => valid(
            &propose.vertex.source,
            &propose_signing_bytes(&propose.vertex.hash),
            &propose.signature,
        ),
        PRBCMessage::NoVote(no_vote) => valid(
            &no_vote.voter,
            &no_vote_signing_bytes(no_vote.round),
            &no_vote.signature,
        ),
        PRBCMessage::Certificate(certificate) => {
            let bytes = vote_signing_bytes(certificate.round, certificate.source, &certificate.hash);
            certificate.votes.retain(|voter, signature| valid(voter, &bytes, signature));
            true
        }
        _ => true,
    }
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
                PRBCMessage::PRBCPropose(PRBCProposeMessage {
                    vertex: vertex(),
                    signature: vec![],
                }),
                TrafficPlane::ConsensusData,
            ),
            (
                PRBCMessage::Certificate(PRBCCertificateMessage {
                    round: 1,
                    source: 0,
                    hash: digest.clone(),
                    votes: BTreeMap::new(),
                }),
                TrafficPlane::ConsensusData,
            ),
            (
                PRBCMessage::CertRequest(PRBCCertRequestMessage {
                    hash: digest.clone(),
                    requester: 1,
                }),
                TrafficPlane::Control,
            ),
            (
                PRBCMessage::NoVote(PRBCNoVoteMessage {
                    round: 1,
                    voter: 1,
                    signature: vec![],
                }),
                TrafficPlane::Control,
            ),
            (
                PRBCMessage::PRBCRecoveryResp(PRBCRecoveryRespMessage { vertex: vertex() }),
                TrafficPlane::ConsensusData,
            ),
            (
                PRBCMessage::BatchRequest(PRBCBatchRequestMessage {
                    digest: digest.clone(),
                    requester: 1,
                }),
                TrafficPlane::Control,
            ),
            (
                PRBCMessage::BatchResp(PRBCBatchMessage {
                    digest: digest.clone(),
                    payload: vec![4],
                }),
                TrafficPlane::Dissemination,
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
            PRBCMessage::Batch(_) | PRBCMessage::BatchResp(_) => Self::Dissemination,
            PRBCMessage::PRBCPropose(_)
            | PRBCMessage::PRBCRecoveryResp(_)
            | PRBCMessage::Certificate(_) => Self::ConsensusData,
            PRBCMessage::PRBCVote(_)
            | PRBCMessage::PRBCRecovery(_)
            | PRBCMessage::BatchRequest(_)
            | PRBCMessage::CertRequest(_)
            | PRBCMessage::NoVote(_)
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
// What a process is still missing for a hash-committed vertex: the vertex
// itself, or, once the vertex is known, the batch its digest names.
#[derive(Clone, Debug, PartialEq)]
enum RecoveryTarget {
    Vertex,
    Batch(BatchDigest),
}

struct RecoveryState {
    round: u64,
    target: RecoveryTarget,
    // The 2f+1 voters of the hash quorum. Each stored the batch (and so held
    // the vertex) before voting, so at least f+1 of them are correct holders.
    vote_list: Vec<NodeId>,
    next_idx: usize,
    // Completed passes over vote_list without a valid answer.
    passes: u32,
    next_request_at: Instant,
    requested_from: Option<NodeId>,
    // Everyone asked so far. A valid late answer from any of them is accepted.
    asked: HashSet<NodeId>,
}

impl RecoveryState {
    /// The vertex is now known but its batch is not: ask the same voters for
    /// the batch, after giving normal dissemination `wait` to deliver it.
    fn switch_to_batch(&mut self, digest: BatchDigest, wait: Duration) {
        self.target = RecoveryTarget::Batch(digest);
        self.next_idx = 0;
        self.passes = 0;
        self.next_request_at = Instant::now() + wait;
        self.requested_from = None;
        self.asked.clear();
    }

    /// Next voter to ask in this pass, skipping ourselves; None at the end.
    fn next_candidate(&mut self, my_id: NodeId) -> Option<NodeId> {
        while self.next_idx < self.vote_list.len() {
            let candidate = self.vote_list[self.next_idx];
            self.next_idx += 1;
            if candidate != my_id {
                return Some(candidate);
            }
        }
        None
    }
}

// ── Certificate fetch ────────────────────────────────────────────────────────
// A hash seen as a parent (of a vertex to vote on, or in a history to order)
// that this process has not certified. The first request goes to `hints` (who
// referenced it) after RECOVERY_TIMEOUT_MS, since the votes are normally still
// in flight; later ones go to everyone, with a doubling wait.
struct CertWant {
    // Round of the vertex that referenced the hash. A certified vertex's
    // parents lie within the GC window below it, so this bounds the search.
    child_round: u64,
    hints: Vec<NodeId>,
    attempts: u32,
    next_request_at: Instant,
}

// A received proposal: (sender, vertex, source signature).
type PendingPropose = (NodeId, Vertex, Vec<u8>);

// The edges of every vertex body this process holds, whether or not it has
// voted for it or holds its batch. Ordering needs only these, not the batch.
struct VertexEdges {
    round: u64,
    strong: Vec<VertexHash>,
    weak: Vec<VertexHash>,
}

/// Whether a correct process may vote for a vertex (see check_parents).
enum ParentCheck {
    Ready,
    Missing(Vec<VertexHash>),
    Invalid(&'static str),
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
    pending_on_batch: HashMap<BatchDigest, Vec<PendingPropose>>,
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
    // Reverse of hash_committed: certified hash → its slot.
    certified_slot: HashMap<VertexHash, (u64, NodeId)>,
    // Proposals with batch present whose parents are not all certified here
    // yet: a correct process votes only once every parent is certified.
    parked_on_parents: HashMap<VertexHash, PendingPropose>,
    // missing parent → proposals waiting for it
    parent_waiters: HashMap<VertexHash, Vec<VertexHash>>,
    // Parked proposals whose parents arrived, re-run by drain_released_proposals.
    released_proposals: Vec<PendingPropose>,
    cert_wanted: HashMap<VertexHash, CertWant>,
    // round r → no-votes from processes whose round-(r+1) vertex skips leader(r)
    no_votes: HashMap<u64, BTreeMap<NodeId, Vec<u8>>>,

    // ── PRBC data plane ──────────────────────────────────────────────────────
    // full Vertex bodies received via PRBCPropose or Phase 3 recovery
    prbc_payloads: HashMap<VertexHash, Vertex>,
    // vertex_hash → edges; HashSet gives O(1) contains() in the commit rule
    known_edges: HashMap<VertexHash, HashSet<VertexHash>>,
    // Edges of every vertex body held (see VertexEdges); used for ordering.
    vertex_edges: HashMap<VertexHash, VertexEdges>,
    // hashes whose payload has been locally verified
    execution_ready: HashSet<VertexHash>,
    // consensus-committed vertices that still await payload delivery
    execution_pending: HashSet<VertexHash>,
    // in-flight Phase 3 recovery state machines
    recovery_state: HashMap<VertexHash, RecoveryState>,
    // Delivered vertices and batches, kept for retention_rounds rounds after
    // they leave the DAG / batch store so peers can still recover them.
    retained_vertices: RetentionStore<Vertex>,
    retained_batches: RetentionStore<Vec<u8>>,
    retention_rounds: u64,

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

    // Diagnostic counters (printed in stats, medianised by run_linux.py).
    // A hash-vote quorum (32-byte digests, Control plane) routinely completes
    // before the 256 KB payload finishes propagating on the separate
    // Dissemination plane. That is the decoupling working as intended, not an
    // error — these track how wide the gap is and how often it actually forces
    // a network fetch (almost never: the propose/batch normally arrives first).
    payload_lag_count: usize,         // hash-quorum reached before the local payload
    payload_post_quorum_count: usize, // propose then arrived on its own — no fetch needed
    recovery_requests_sent: usize,    // PRBCRecovery messages actually put on the wire
    recovery_responses_ok: usize,     // valid PRBCRecoveryResp certificates applied locally
    recovery_responses_served: usize, // PRBCRecoveryResp this node sent to answer a peer
    batch_requests_sent: usize,       // BatchRequest messages put on the wire
    batch_responses_ok: usize,        // valid BatchResp applied locally
    batch_responses_served: usize,    // BatchResp this node sent to answer a peer
    recovery_restarts: usize,         // full passes over the voters with no valid answer
    recoveries_abandoned: usize,      // dropped because the round left the retention window
    parent_waits: usize,              // proposals parked until their parents were certified here
    cert_requests_sent: usize,        // CertRequest messages put on the wire (one per target)
    cert_responses_ok: usize,         // valid certificates applied locally
    cert_responses_served: usize,     // certificates this node sent to answer a peer
    leaders_skipped: usize,           // leaders ordered as skipped (no path from the next anchor)
    no_votes_sent: usize,             // no-votes sent to the next leader
    invalid_vertices: usize,          // proposals that break the vertex rules (never voted)
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

    // Optional cap (ms) on the synthetic batch-generator's tick interval, read
    // from MAX_BATCH_DELAY_MS. None (default/unset) reproduces today's exact
    // pacing: interval = n_tx * n_nodes / input_rate, uncapped.
    max_batch_delay_ms: Option<u64>,
    // The actual per-batch transaction count the generator task is using.
    // Equals environment.n_transactions unless max_batch_delay_ms engaged and
    // shrank it proportionally. Mirrored here so print_dag_stats() reports
    // real throughput instead of assuming a full-size batch every time.
    effective_n_tx: usize,

    // Per-process CPU / memory sampling, started when the timed run begins.
    resource_meter: Option<ResourceMeter>,
}

impl PRBCSailfish {
    pub fn new(
        environment: Environment,
        public_keys: HashMap<NodeId, PublicKey>,
        private_key: Keypair,
    ) -> Self {
        println!("PRBCSailfish");
        let n = environment.nodes.len();
        let n_tx_default = environment.n_transactions;
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
            certified_slot: HashMap::new(),
            parked_on_parents: HashMap::new(),
            parent_waiters: HashMap::new(),
            released_proposals: Vec::new(),
            cert_wanted: HashMap::new(),
            no_votes: HashMap::new(),

            prbc_payloads: HashMap::new(),
            known_edges: HashMap::new(),
            vertex_edges: HashMap::new(),
            execution_ready: HashSet::new(),
            execution_pending: HashSet::new(),
            recovery_state: HashMap::new(),
            retained_vertices: RetentionStore::new(),
            retained_batches: RetentionStore::new(),
            retention_rounds: std::env::var("RETENTION_ROUNDS")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(DEFAULT_RETENTION_ROUNDS),

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

            payload_lag_count: 0,
            payload_post_quorum_count: 0,
            recovery_requests_sent: 0,
            recovery_responses_ok: 0,
            recovery_responses_served: 0,
            batch_requests_sent: 0,
            batch_responses_ok: 0,
            batch_responses_served: 0,
            recovery_restarts: 0,
            recoveries_abandoned: 0,
            parent_waits: 0,
            cert_requests_sent: 0,
            cert_responses_ok: 0,
            cert_responses_served: 0,
            leaders_skipped: 0,
            no_votes_sent: 0,
            invalid_vertices: 0,
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

            max_batch_delay_ms: std::env::var("MAX_BATCH_DELAY_MS")
                .ok().and_then(|v| v.parse::<u64>().ok()).filter(|&v| v > 0),
            effective_n_tx: n_tx_default,

            resource_meter: None,
        };
        node.add_genesis_block();
        node
    }

    fn quorum(&self) -> usize {
        // n − f: any two quorums then share f+1 parties, one of them correct,
        // for every n ≥ 3f+1. It equals 2f+1 only when n = 3f+1; at n = 50
        // (f = 16) 2f+1 = 33 quorums could overlap in Byzantine parties only.
        // Same threshold as Narwhal's ⌊2n/3⌋+1.
        if self.reduced_quorum {
            self.f + 1
        } else {
            self.environment.nodes.len() - self.f
        }
    }

    fn leader_of(&self, round: u64) -> NodeId {
        (round % self.environment.nodes.len() as u64) as NodeId
    }

    /// How far below a vertex its weak edges may reach (Narwhal's gc_depth).
    /// Keeping every reference inside this window keeps every certificate a
    /// process may need still held by its voters.
    fn gc_depth(&self) -> u64 {
        self.retention_rounds.max(DAG_PRUNE_DEPTH)
    }

    /// The 2f+1 lowest-ID peers: who Byz1/Byz3/Byz5 still send to.
    fn lowest_peers(&self) -> Vec<NodeId> {
        let my_id = self.environment.my_node.id;
        self.environment.nodes.iter()
            .map(|node| node.id)
            .filter(|&id| id != my_id)
            .take(2 * self.f + 1)
            .collect()
    }

    fn sign(&self, bytes: &[u8]) -> Vec<u8> {
        if self.sign_votes {
            self.private_key.sign(bytes).to_bytes().to_vec()
        } else {
            vec![]
        }
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
                    let signature = self.sign(&propose_signing_bytes(&new_vertex.hash));
                    self.vertex_timestamps.entry(new_vertex.hash.clone()).or_insert_with(Instant::now);
                    self.e2e_timestamps.insert(new_vertex.hash.clone(), batch_time);
                    self.dag.insert(new_vertex.clone());

                    // Sailfish: a vertex that does not point to the previous
                    // leader is announced to the next leader as a no-vote.
                    let prev_round = self.round - 1;
                    let next_leader = self.leader_of(self.round);
                    if prev_round > 0
                        && next_leader != my_id
                        && !self.has_leader_hash_committed(prev_round)
                    {
                        let no_vote = PRBCNoVoteMessage {
                            round: prev_round,
                            voter: my_id,
                            signature: self.sign(&no_vote_signing_bytes(prev_round)),
                        };
                        let _ = dispatcher_tx
                            .send((DispatchTarget::One(next_leader), PRBCMessage::NoVote(no_vote)))
                            .await;
                        self.no_votes_sent += 1;
                    }

                    self.round += 1;
                    self.round_start_time = Instant::now();
                    self.timeout_sent = false;
                    self.current_round_tc = None;

                    if matches!(
                        self.environment.my_node.behavior,
                        NodeBehavior::Byz1 | NodeBehavior::Byz5
                    ) {
                        // Byz1: send PRBCPropose to only 2f+1 peers via unicast.
                        let peers = self.lowest_peers();
                        warn!("[Node {}] BYZ1: PRBCPropose to only {}/{} peers",
                            my_id, peers.len(), self.environment.nodes.len() - 1);
                        for target in peers {
                            let _ = dispatcher_tx.send((
                                DispatchTarget::One(target),
                                PRBCMessage::PRBCPropose(PRBCProposeMessage {
                                    vertex: new_vertex.clone(),
                                    signature: signature.clone(),
                                }),
                            )).await;
                        }
                    } else {
                        // Ok / Byz2: broadcast normally (byz2 attack fires in S1→S2 forwarding).
                        self.broadcast(
                            PRBCMessage::PRBCPropose(PRBCProposeMessage {
                                vertex: new_vertex.clone(),
                                signature: signature.clone(),
                            }),
                            dispatcher_tx,
                        ).await;
                    }

                    self.handle_prbc_propose(my_id, new_vertex, signature, dispatcher_tx).await;
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

        if has_leader {
            return true;
        }
        if has_tc {
            // Sailfish: the leader of this round must point to the previous
            // leader or carry a no-vote certificate (2f+1 processes whose
            // vertex skips it, so nobody can have committed it directly).
            let my_id = self.environment.my_node.id;
            if self.leader_of(self.round) != my_id {
                return true;
            }
            if !self.no_votes.get(&prev_round).map_or(false, |v| v.contains_key(&my_id)) {
                let signature = self.sign(&no_vote_signing_bytes(prev_round));
                self.no_votes.entry(prev_round).or_default().insert(my_id, signature);
            }
            if self.no_votes[&prev_round].len() >= quorum {
                return true;
            }
            debug!(
                "[Node {}] Round {} leader waiting for a no-vote certificate for round {}",
                my_id, self.round, prev_round
            );
            return false;
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

        // Any hash-committed hash at round < r-1 not reachable through the
        // chain, within the GC window (the vote rule rejects older ones).
        let gc_depth = self.gc_depth();
        let mut weak: Vec<VertexHash> = self.hash_committed.iter()
            .filter(|((r, _), h)| {
                *r + 1 < round
                    && *r > 0
                    && *r + gc_depth >= round
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
        // A leader that skips the previous leader carries the no-vote
        // certificate it waited for in may_advance_round.
        let source = self.environment.my_node.id;
        let nvc = (self.leader_of(round) == source && !self.has_leader_hash_committed(prev_round))
            .then(|| NoVoteCertificate {
                round: prev_round,
                signatures: self.no_votes.get(&prev_round).cloned().unwrap_or_default(),
            });

        let mut v = Vertex {
            hash: vec![],
            round,
            source,
            block,
            edges,
            weak_edges,
            signed_round: vec![],
            sample_proof: vec![],
            tc,
            nvc,
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
        self.certified_slot.insert(hash.clone(), (round, source));
        self.cert_wanted.remove(&hash);
        // Proposals that were waiting for this parent can be checked again.
        if let Some(children) = self.parent_waiters.remove(&hash) {
            for child in children {
                if let Some(pending) = self.parked_on_parents.remove(&child) {
                    self.released_proposals.push(pending);
                }
            }
        }

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
        } else if let Some((_, full_vertex, _)) = self.parked_on_parents.remove(&hash) {
            // Vertex and batch are here; we were only holding back our vote
            // until its parents were certified. A certified vertex needs none.
            self.on_execution_ready(hash.clone(), full_vertex, dispatcher_tx).await;
        } else if source != self.environment.my_node.id {
            // Hash-quorum before local payload. Arm a recovery state machine;
            // on_execution_ready cancels it the moment the propose/batch lands,
            // which is the common case. Escalation to the wire is rare.
            self.payload_lag_count += 1;
            let vote_list: Vec<NodeId> = votes.keys().cloned().collect();
            // If the vertex is already here, parked until its batch arrives,
            // only the batch is missing.
            let parked_digest = self
                .pending_on_batch
                .iter()
                .find(|(_, waiters)| waiters.iter().any(|(_, v, _)| v.hash == hash))
                .map(|(digest, _)| digest.clone());
            self.start_recovery(round, hash.clone(), vote_list, parked_digest);
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
            self.retire_batch(&hash);
        }
    }

    /// Move an executed vertex's batch from the batch store to the retention
    /// store, where it stays fetchable for retention_rounds rounds.
    fn retire_batch(&mut self, hash: &VertexHash) {
        let Some((round, digest)) = self.dag.vertices.get(hash).map(|v| (v.round, v.block.clone()))
        else {
            return;
        };
        if let Some(payload) = self.batch_store.remove(&digest) {
            if self.retention_rounds > 0 {
                self.retained_batches.insert(round, digest, payload);
            }
        }
    }

    // ── Commit logic ──────────────────────────────────────────────────────────

    /// Sailfish commit rule. The latest leader with 2f+1 certified round-(r+1)
    /// vertices pointing to it is committed directly: the anchor. Walking back
    /// from it, each earlier leader with a strong path from the last leader
    /// kept is ordered before it; any other leader is skipped. A leader
    /// committed directly anywhere has a strong path from every later leader
    /// (quorum intersection, and for the very next leader the no-vote rule),
    /// so every correct process orders the same leaders, and a crashed leader
    /// no longer stops ordering.
    fn try_committing_prbc(&mut self) {
        let start_round = self.round.saturating_sub(1);
        let end_round = self.last_ordered_round;

        let mut anchor = None;
        for r in ((end_round + 1)..=start_round).rev() {
            let Some(leader_hash) = self.hash_committed.get(&(r, self.leader_of(r))).cloned()
            else {
                continue;
            };
            if self.direct_support(r, &leader_hash) >= self.quorum() {
                anchor = Some((r, leader_hash));
                break;
            }
        }
        let Some((anchor_round, anchor_hash)) = anchor else {
            return;
        };

        // Never order with a gap: every vertex the anchor's unordered history
        // reaches must be certified here and its edges known.
        if !self.history_complete(&anchor_hash) {
            return;
        }

        let mut chain = vec![anchor_hash.clone()];
        let mut current = anchor_hash;
        for r in ((end_round + 1)..anchor_round).rev() {
            let Some(leader_hash) = self.hash_committed.get(&(r, self.leader_of(r))).cloned()
            else {
                continue;
            };
            if self.strong_path(&current, &leader_hash, r) {
                chain.push(leader_hash.clone());
                current = leader_hash;
            }
        }
        self.leaders_skipped += (anchor_round - end_round) as usize - chain.len();

        for leader_hash in chain.into_iter().rev() {
            self.commit_causal_history_prbc(leader_hash);
        }
        self.last_ordered_round = anchor_round;
        let pruned = self.dag.prune_ordered(
            self.last_ordered_round.saturating_sub(DAG_PRUNE_DEPTH),
            &self.already_ordered,
        );
        if self.retention_rounds > 0 {
            for vertex in pruned {
                // Skeletons (payload never arrived) cannot
                // answer a recovery request.
                if self.execution_ready.contains(&vertex.hash) {
                    self.retained_vertices
                        .insert(vertex.round, vertex.hash.clone(), vertex);
                }
            }
        }
        self.prune_prbc_caches();
    }

    /// Certified round-(r+1) vertices whose strong edges include the leader of r.
    fn direct_support(&self, round: u64, leader_hash: &VertexHash) -> usize {
        let next_round = round + 1;
        self.hash_committed_by_round
            .get(&next_round)
            .map_or(0, |sources| {
                sources.iter().filter(|&&src| {
                    self.hash_committed
                        .get(&(next_round, src))
                        .and_then(|h| self.known_edges.get(h))
                        .map_or(false, |edges| edges.contains(leader_hash))
                }).count()
            })
    }

    /// True if every vertex in the unordered causal history of `anchor` is
    /// certified here and its edges are known. Asks for the certificate of
    /// any hash not certified here; a certified vertex whose body is missing
    /// is already being recovered (armed in on_hash_quorum).
    fn history_complete(&mut self, anchor: &VertexHash) -> bool {
        let mut complete = true;
        let mut seen: HashSet<VertexHash> = HashSet::new();
        // (hash, slot of the vertex that referenced it)
        let mut stack: Vec<(VertexHash, Option<(u64, NodeId)>)> = vec![(anchor.clone(), None)];
        let mut wanted: Vec<(VertexHash, u64, NodeId)> = Vec::new();
        while let Some((hash, child)) = stack.pop() {
            if self.already_ordered.contains(&hash) || !seen.insert(hash.clone()) {
                continue;
            }
            let Some(&slot) = self.certified_slot.get(&hash) else {
                complete = false;
                if let Some((round, source)) = child {
                    wanted.push((hash, round, source));
                }
                continue;
            };
            let Some(edges) = self.vertex_edges.get(&hash) else {
                complete = false;
                continue;
            };
            for parent in edges.strong.iter().chain(edges.weak.iter()) {
                stack.push((parent.clone(), Some(slot)));
            }
        }
        for (hash, round, source) in wanted {
            self.want_certificate(hash, round, vec![source]);
        }
        complete
    }

    /// Is there a path from `from` down to `to` (a vertex of round `to_round`)
    /// along strong edges only?
    fn strong_path(&self, from: &VertexHash, to: &VertexHash, to_round: u64) -> bool {
        let mut seen: HashSet<&VertexHash> = HashSet::new();
        let mut stack = vec![from];
        while let Some(hash) = stack.pop() {
            if hash == to {
                return true;
            }
            if !seen.insert(hash) {
                continue;
            }
            let Some(edges) = self.vertex_edges.get(hash) else {
                continue;
            };
            if edges.round > to_round + 1 {
                stack.extend(edges.strong.iter());
            } else if edges.round == to_round + 1 && edges.strong.contains(to) {
                return true;
            }
        }
        false
    }

    /// Prune payload and vote caches for rounds that are too old to need recovery.
    fn prune_prbc_caches(&mut self) {
        // Pre-quorum vertices, votes and timeouts are small; keep 128 rounds.
        let cutoff = self.last_ordered_round.saturating_sub(VOTE_RECORD_ROUNDS);
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
        self.vertex_edges.retain(|_, edges| edges.round >= cutoff);
        self.no_votes.retain(|round, _| *round >= cutoff);

        // Retention window. Nothing older can still be served by a correct
        // peer, so recovery for it is dropped: a process that far behind
        // needs state transfer, which is out of scope.
        let horizon = self.last_ordered_round.saturating_sub(self.gc_depth());
        self.retained_vertices.prune_below(horizon);
        self.retained_batches.prune_below(horizon);
        let before = self.recovery_state.len();
        self.recovery_state.retain(|_, state| state.round >= horizon);
        self.recoveries_abandoned += before - self.recovery_state.len();
        self.cert_wanted.retain(|_, want| want.child_round >= horizon);
        self.parked_on_parents.retain(|_, (_, vertex, _)| vertex.round >= horizon);
        let parked = &self.parked_on_parents;
        self.parent_waiters.retain(|_, children| {
            children.retain(|child| parked.contains_key(child));
            !children.is_empty()
        });
    }

    /// Order the unordered causal history of `leader_hash` (strong and weak
    /// edges), sorted by (round, source) so every process orders it the same.
    fn commit_causal_history_prbc(&mut self, leader_hash: VertexHash) {
        let mut history: Vec<(u64, NodeId, VertexHash)> = Vec::new();
        let mut seen: HashSet<VertexHash> = HashSet::new();
        let mut stack = vec![leader_hash];
        while let Some(h) = stack.pop() {
            if self.already_ordered.contains(&h) || !seen.insert(h.clone()) {
                continue;
            }
            // history_complete checked that every vertex here is certified
            // and its edges known.
            let Some(&(round, source)) = self.certified_slot.get(&h) else {
                continue;
            };
            if let Some(edges) = self.vertex_edges.get(&h) {
                stack.extend(edges.strong.iter().cloned());
                stack.extend(edges.weak.iter().cloned());
            }
            history.push((round, source, h));
        }
        history.sort();

        for (_, _, h) in history {
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
                self.retire_batch(&h);
            } else {
                self.execution_pending.insert(h);
            }
        }
    }

    // ── PRBC message handlers ─────────────────────────────────────────────────

    /// `signature` is the source's signature over the vertex, checked on the
    /// reader task when signatures are on; it is forwarded on S1→S2 relays.
    async fn handle_prbc_propose(
        &mut self,
        sender: NodeId,
        vertex: Vertex,
        signature: Vec<u8>,
        dispatcher_tx: &MessageDispatcher,
    ) {
        let hash = vertex.hash.clone();
        // Extract Copy scalars before vertex is moved.
        let v_round = vertex.round;
        let v_source = vertex.source;

        // Payload already stored or fully execution-ready — nothing to do.
        if self.prbc_payloads.contains_key(&hash)
            || self.execution_ready.contains(&hash)
            || self.parked_on_parents.contains_key(&hash)
        {
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
        // The hash covers the edges, so they are authentic for this hash
        // whether or not this process ever votes for it.
        self.record_vertex_edges(&vertex);
        let digest = vertex.block.clone();
        if !self.batch_store.contains(&digest) {
            // If this vertex was being recovered, only its batch is missing now.
            let wait = Duration::from_millis(self.recovery_timeout_ms as u64);
            if let Some(state) = self.recovery_state.get_mut(&hash) {
                if state.target == RecoveryTarget::Vertex {
                    state.switch_to_batch(digest.clone(), wait);
                }
            }
            let waiters = self.pending_on_batch.entry(digest).or_default();
            if !waiters.iter().any(|(_, pending, _)| pending.hash == hash) {
                waiters.push((sender, vertex, signature));
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

            self.payload_post_quorum_count += 1;
            self.on_execution_ready(hash, vertex, dispatcher_tx).await;
            return;
        }

        // Vote only for a well-formed vertex whose parents are all certified
        // here. Then every certified vertex has f+1 correct voters holding
        // its parents' certificates, so any process can fetch them.
        match self.check_parents(&vertex) {
            ParentCheck::Ready => {}
            ParentCheck::Invalid(reason) => {
                self.invalid_vertices += 1;
                warn!(
                    "[Node {}] PRBCPropose round={} source={}: {}, not voting",
                    self.environment.my_node.id, v_round, v_source, reason
                );
                return;
            }
            ParentCheck::Missing(parents) => {
                self.parent_waits += 1;
                let mut hints = vec![sender];
                if v_source != sender {
                    hints.push(v_source);
                }
                for parent in parents {
                    self.parent_waiters.entry(parent.clone()).or_default().push(hash.clone());
                    self.want_certificate(parent, v_round, hints.clone());
                }
                self.parked_on_parents.insert(hash, (sender, vertex, signature));
                return;
            }
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
                    PRBCMessage::PRBCPropose(PRBCProposeMessage { vertex: fwd, signature }),
                ))
                .await;
        }

        // Broadcast vote. When sign_votes is on, include an Ed25519 sig over
        // the hash bound to its slot.
        let my_sig = self.sign(&vote_signing_bytes(v_round, v_source, &hash));
        // Byz5 withholds its votes from the highest-ID nodes as well.
        let vote_target = if self.environment.my_node.behavior == NodeBehavior::Byz5 {
            DispatchTarget::Many(self.lowest_peers())
        } else {
            DispatchTarget::All
        };
        let _ = dispatcher_tx
            .send((
                vote_target,
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
        self.store_batch(batch, true, dispatcher_tx).await;
    }

    /// Store a verified batch, relay it if `relay` and this process is in S1,
    /// and release any vertices that were waiting for it.
    async fn store_batch(
        &mut self,
        batch: PRBCBatchMessage,
        relay: bool,
        dispatcher_tx: &MessageDispatcher,
    ) {
        let digest = batch.digest.clone();
        let my_id = self.environment.my_node.id;
        let targets = if relay
            && self.sample_verification(&digest)
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
            for (sender, vertex, signature) in waiters {
                self.handle_prbc_propose(sender, vertex, signature, dispatcher_tx).await;
            }
        }
    }

    async fn handle_prbc_vote(
        &mut self,
        sender: NodeId,
        vote: PRBCVoteMessage,
        dispatcher_tx: &MessageDispatcher,
    ) {
        // When signing is on, the Ed25519 signature was already verified on the
        // peer's reader task (handle_connection), so msg.voter is the identity.
        // When off, fall back to the TCP-authenticated sender.
        let voter = if self.sign_votes { vote.voter } else { sender };

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
        if self.environment.my_node.behavior == NodeBehavior::Byz4 {
            return;
        }

        // Answer with the full vertex if we hold it. No vote check: the
        // requester only asks for hashes it already holds 2f+1 votes for, and
        // checks the vertex against that hash itself. A skeleton (hash
        // committed, vertex never arrived) is not a full vertex and is not sent.
        let vertex = self
            .prbc_payloads
            .get(&msg.hash)
            .or_else(|| {
                self.execution_ready
                    .contains(&msg.hash)
                    .then(|| self.dag.vertices.get(&msg.hash))
                    .flatten()
            })
            .or_else(|| self.retained_vertices.get(&msg.hash))
            .cloned();
        if let Some(vertex) = vertex {
            let _ = dispatcher_tx
                .send((
                    DispatchTarget::One(sender),
                    PRBCMessage::PRBCRecoveryResp(PRBCRecoveryRespMessage { vertex }),
                ))
                .await;
            self.recovery_responses_served += 1;
        }
    }

    async fn handle_prbc_recovery_resp(
        &mut self,
        sender: NodeId,
        msg: PRBCRecoveryRespMessage,
        dispatcher_tx: &MessageDispatcher,
    ) {
        let hash = msg.vertex.hash.clone();

        // Only answers to an open vertex request, from a voter we asked. A late
        // answer from an earlier candidate is as good as one from the current.
        match self.recovery_state.get(&hash) {
            Some(state)
                if state.target == RecoveryTarget::Vertex && state.asked.contains(&sender) => {}
            _ => return,
        }
        if self.execution_ready.contains(&hash) {
            return;
        }

        // We hold 2f+1 votes for this hash (recovery is only armed on a hash
        // quorum), so the vertex needs no certificate of its own: it only has
        // to hash to h and name one batch digest.
        if hash != msg.vertex.calculate_hash() || msg.vertex.block.len() != 32 {
            warn!(
                "[Node {}] Recovery resp from {}: invalid vertex, trying next node",
                self.environment.my_node.id, sender
            );
            self.force_recovery_retry(&hash, sender);
            return;
        }

        self.recovery_responses_ok += 1;
        self.record_vertex_edges(&msg.vertex);

        let digest = msg.vertex.block.clone();
        if !self.batch_store.contains(&digest) {
            // Vertex recovered, batch not here. Park the vertex as a propose
            // would be, and ask the same voters for the batch. It is
            // certified, so it is never voted on and needs no signature.
            let wait = Duration::from_millis(self.recovery_timeout_ms as u64);
            if let Some(state) = self.recovery_state.get_mut(&hash) {
                state.switch_to_batch(digest.clone(), wait);
            }
            let waiters = self.pending_on_batch.entry(digest).or_default();
            if !waiters.iter().any(|(_, pending, _)| pending.hash == hash) {
                waiters.push((sender, msg.vertex, vec![]));
            }
            return;
        }
        self.on_execution_ready(hash, msg.vertex, dispatcher_tx).await;
    }

    async fn handle_batch_request(
        &mut self,
        sender: NodeId,
        msg: PRBCBatchRequestMessage,
        dispatcher_tx: &MessageDispatcher,
    ) {
        // Same anti-reflection rule as vertex recovery.
        if msg.requester != sender {
            warn!(
                "[Node {}] Batch request sender/requester mismatch: {} != {}",
                self.environment.my_node.id, sender, msg.requester
            );
            return;
        }
        if self.environment.my_node.behavior == NodeBehavior::Byz4 {
            return;
        }

        let payload = self
            .batch_store
            .get(&msg.digest)
            .or_else(|| self.retained_batches.get(&msg.digest))
            .cloned();
        if let Some(payload) = payload {
            let _ = dispatcher_tx
                .send((
                    DispatchTarget::One(sender),
                    PRBCMessage::BatchResp(PRBCBatchMessage { digest: msg.digest, payload }),
                ))
                .await;
            self.batch_responses_served += 1;
        }
    }

    async fn handle_batch_resp(
        &mut self,
        sender: NodeId,
        batch: PRBCBatchMessage,
        dispatcher_tx: &MessageDispatcher,
    ) {
        // Only answers to an open batch request, from a voter we asked.
        let target = RecoveryTarget::Batch(batch.digest.clone());
        let awaiting: Vec<VertexHash> = self
            .recovery_state
            .iter()
            .filter(|(_, state)| state.target == target && state.asked.contains(&sender))
            .map(|(hash, _)| hash.clone())
            .collect();
        if awaiting.is_empty() || self.seen_batches.contains(&batch.digest) {
            return;
        }

        // The digest comes from a vertex with 2f+1 votes, so a batch that
        // hashes to it is the right batch, whoever sent it.
        if batch_digest(&batch.payload) != batch.digest {
            warn!(
                "[Node {}] Batch resp from {}: digest mismatch, trying next node",
                self.environment.my_node.id, sender
            );
            for hash in awaiting {
                self.force_recovery_retry(&hash, sender);
            }
            return;
        }

        self.batch_responses_ok += 1;
        self.seen_batches.insert(batch.digest.clone());
        // A fetched batch is a repair, not dissemination: store it, do not relay it.
        self.store_batch(batch, false, dispatcher_tx).await;
    }

    /// An asked voter sent an invalid answer. If it is the one we are waiting
    /// on, move to the next candidate now instead of waiting out the timeout.
    fn force_recovery_retry(&mut self, hash: &VertexHash, sender: NodeId) {
        if let Some(state) = self.recovery_state.get_mut(hash) {
            if state.requested_from == Some(sender) {
                state.next_request_at = Instant::now();
                state.requested_from = None;
            }
        }
    }

    // ── Vote rule, certificate fetch, no-votes ────────────────────────────────

    fn record_vertex_edges(&mut self, vertex: &Vertex) {
        if !self.vertex_edges.contains_key(&vertex.hash) {
            self.vertex_edges.insert(
                vertex.hash.clone(),
                VertexEdges {
                    round: vertex.round,
                    strong: vertex.edges.clone(),
                    weak: vertex.weak_edges.clone(),
                },
            );
        }
    }

    /// The vote rule. A correct process votes for a vertex only if it is well
    /// formed and every parent is certified here:
    /// - round 1: its one strong edge is genesis;
    /// - later rounds: at least 2f+1 strong edges, each a certified vertex of
    ///   the previous round from a distinct source;
    /// - weak edges: certified vertices more than one round below, within the
    ///   GC window;
    /// - the round's leader points to the previous leader or carries a valid
    ///   no-vote certificate for it (Sailfish).
    fn check_parents(&self, vertex: &Vertex) -> ParentCheck {
        let round = vertex.round;
        if round == 0 {
            return ParentCheck::Invalid("round 0 is genesis");
        }
        // Our record of votes that old is pruned, so a vote there could be a
        // second vote for the slot. Never vote that far back.
        if round < self.last_ordered_round.saturating_sub(VOTE_RECORD_ROUNDS) {
            return ParentCheck::Invalid("too old: the vote record for its round is pruned");
        }
        if round == 1 {
            let genesis = vec![0u8; 32];
            return if vertex.edges == [genesis] && vertex.weak_edges.is_empty() {
                ParentCheck::Ready
            } else {
                ParentCheck::Invalid("a round-1 vertex must point to genesis only")
            };
        }
        let distinct: HashSet<&VertexHash> =
            vertex.edges.iter().chain(vertex.weak_edges.iter()).collect();
        if distinct.len() != vertex.edges.len() + vertex.weak_edges.len() {
            return ParentCheck::Invalid("repeated edge");
        }
        if vertex.edges.len() < self.quorum() {
            return ParentCheck::Invalid("fewer than a quorum of strong edges");
        }

        let mut missing = Vec::new();
        let mut sources = HashSet::new();
        let prev_leader = self.leader_of(round - 1);
        let mut points_to_prev_leader = false;
        for edge in &vertex.edges {
            match self.certified_slot.get(edge) {
                Some(&(r, s)) if r == round - 1 && sources.insert(s) => {
                    points_to_prev_leader |= s == prev_leader;
                }
                Some(_) => {
                    return ParentCheck::Invalid("strong edge is not a distinct previous-round vertex")
                }
                None => missing.push(edge.clone()),
            }
        }
        let gc_depth = self.gc_depth();
        for edge in &vertex.weak_edges {
            match self.certified_slot.get(edge) {
                Some(&(r, _)) if r > 0 && r + 1 < round && r + gc_depth >= round => {}
                Some(_) => return ParentCheck::Invalid("weak edge outside its window"),
                None => missing.push(edge.clone()),
            }
        }
        if !missing.is_empty() {
            return ParentCheck::Missing(missing);
        }

        if vertex.source == self.leader_of(round)
            && !points_to_prev_leader
            && !self.valid_nvc(vertex.nvc.as_ref(), round - 1)
        {
            return ParentCheck::Invalid(
                "leader skips the previous leader without a no-vote certificate",
            );
        }
        ParentCheck::Ready
    }

    /// 2f+1 distinct processes signed that their vertex after `round` does not
    /// point to the leader of `round`.
    fn valid_nvc(&self, nvc: Option<&NoVoteCertificate>, round: u64) -> bool {
        let Some(nvc) = nvc else {
            return false;
        };
        if nvc.round != round || nvc.signatures.len() < self.quorum() {
            return false;
        }
        let bytes = no_vote_signing_bytes(round);
        nvc.signatures.iter().all(|(node, sig)| {
            self.public_keys.get(node).map_or(false, |pk| {
                !self.sign_votes
                    || Signature::from_bytes(sig)
                        .map_or(false, |sig| pk.verify(&bytes, &sig).is_ok())
            })
        })
    }

    /// Note a hash seen as a parent that is not certified here; tick_certificates
    /// asks for its certificate if the votes do not arrive on their own.
    fn want_certificate(&mut self, hash: VertexHash, child_round: u64, hints: Vec<NodeId>) {
        if self.certified_slot.contains_key(&hash) {
            return;
        }
        let first_request = Instant::now() + Duration::from_millis(self.recovery_timeout_ms as u64);
        let want = self.cert_wanted.entry(hash).or_insert_with(|| CertWant {
            child_round,
            hints: Vec::new(),
            attempts: 0,
            next_request_at: first_request,
        });
        want.child_round = want.child_round.max(child_round);
        for hint in hints {
            if !want.hints.contains(&hint) {
                want.hints.push(hint);
            }
        }
    }

    /// Driven from the main loop's tick, like tick_recovery. The first request
    /// goes to one process that referenced the hash; later ones go to
    /// everyone, since at least f+1 correct voters of any certified child
    /// hold the certificate.
    async fn tick_certificates(&mut self, dispatcher_tx: &MessageDispatcher) {
        let my_id = self.environment.my_node.id;
        let now = Instant::now();
        let mut requests = Vec::new();
        for (hash, want) in self.cert_wanted.iter_mut() {
            if now < want.next_request_at {
                continue;
            }
            let targets: Vec<NodeId> = if want.attempts == 0 {
                want.hints.iter().copied().filter(|&node| node != my_id).take(1).collect()
            } else {
                self.environment.nodes.iter().map(|node| node.id).filter(|&node| node != my_id).collect()
            };
            want.attempts += 1;
            let wait_ms = (self.recovery_timeout_ms as u64)
                << want.attempts.min(MAX_RECOVERY_BACKOFF_SHIFT);
            want.next_request_at = now + Duration::from_millis(wait_ms);
            if !targets.is_empty() {
                requests.push((hash.clone(), targets));
            }
        }
        for (hash, targets) in requests {
            self.cert_requests_sent += targets.len();
            let request = PRBCCertRequestMessage { hash, requester: my_id };
            let _ = dispatcher_tx
                .send((DispatchTarget::Many(targets), PRBCMessage::CertRequest(request)))
                .await;
        }
    }

    async fn handle_cert_request(
        &mut self,
        sender: NodeId,
        msg: PRBCCertRequestMessage,
        dispatcher_tx: &MessageDispatcher,
    ) {
        // Same anti-reflection rule as vertex recovery.
        if msg.requester != sender {
            return;
        }
        if self.environment.my_node.behavior == NodeBehavior::Byz4 {
            return;
        }
        let Some(&(round, source)) = self.certified_slot.get(&msg.hash) else {
            return;
        };
        let Some(votes) = self.prbc_votes.get(&(round, source, msg.hash.clone())) else {
            return;
        };
        if votes.len() < self.quorum() {
            return;
        }
        let certificate = PRBCCertificateMessage {
            round,
            source,
            hash: msg.hash,
            votes: votes.clone(),
        };
        let _ = dispatcher_tx
            .send((DispatchTarget::One(sender), PRBCMessage::Certificate(certificate)))
            .await;
        self.cert_responses_served += 1;
    }

    async fn handle_certificate(
        &mut self,
        msg: PRBCCertificateMessage,
        dispatcher_tx: &MessageDispatcher,
    ) {
        if !self.cert_wanted.contains_key(&msg.hash) || self.certified_slot.contains_key(&msg.hash) {
            return;
        }
        // Each vote's signature over (round, source, hash) was checked on the
        // reader task and invalid ones dropped, so who forwarded it is irrelevant.
        if msg.votes.len() < self.quorum()
            || !msg.votes.keys().all(|voter| self.public_keys.contains_key(voter))
        {
            warn!(
                "[Node {}] Certificate round={} source={}: fewer than a quorum of valid votes",
                self.environment.my_node.id, msg.round, msg.source
            );
            return;
        }
        if let Some(existing) = self.hash_committed.get(&(msg.round, msg.source)) {
            if existing != &msg.hash {
                warn!(
                    "[Node {}] Certificate round={} source={}: conflicts with the one held",
                    self.environment.my_node.id, msg.round, msg.source
                );
            }
            return;
        }
        self.cert_responses_ok += 1;
        self.prbc_votes
            .insert((msg.round, msg.source, msg.hash.clone()), msg.votes.clone());
        self.on_hash_quorum(msg.round, msg.source, msg.hash, msg.votes, dispatcher_tx)
            .await;
    }

    fn handle_no_vote(&mut self, sender: NodeId, msg: PRBCNoVoteMessage) {
        // The signature (checked on the reader task) lets the leader put the
        // no-vote in a certificate; the sender must be the voter itself.
        if msg.voter != sender {
            return;
        }
        self.no_votes.entry(msg.round).or_default().insert(msg.voter, msg.signature);
    }

    /// Re-run proposals whose missing parents have since been certified. Run
    /// from the event loop rather than from on_hash_quorum, which would recurse.
    async fn drain_released_proposals(&mut self, dispatcher_tx: &MessageDispatcher) {
        while let Some((sender, vertex, signature)) = self.released_proposals.pop() {
            self.handle_prbc_propose(sender, vertex, signature, dispatcher_tx).await;
        }
    }

    // ── Phase 3 recovery state machine ────────────────────────────────────────

    fn start_recovery(
        &mut self,
        round: u64,
        hash: VertexHash,
        mut vote_list: Vec<NodeId>,
        parked_digest: Option<BatchDigest>,
    ) {
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

        // A missing vertex is requested on the next tick. A missing batch is
        // normally still in flight on the dissemination plane, so it gets
        // RECOVERY_TIMEOUT_MS to arrive before the first request.
        let now = Instant::now();
        let (target, next_request_at) = match parked_digest {
            None => (RecoveryTarget::Vertex, now),
            Some(digest) => (
                RecoveryTarget::Batch(digest),
                now + Duration::from_millis(self.recovery_timeout_ms as u64),
            ),
        };
        self.recovery_state.insert(
            hash,
            RecoveryState {
                round,
                target,
                vote_list,
                next_idx: 0,
                passes: 0,
                next_request_at,
                requested_from: None,
                asked: HashSet::new(),
            },
        );
    }

    /// Driven from the main event loop's 50 ms tick. Sends or retries recovery
    /// requests without spawning extra tasks. Never gives up inside the
    /// retention window: after a full pass over the voters with no valid
    /// answer it starts over, waiting longer between requests.
    async fn tick_recovery(&mut self, dispatcher_tx: &MessageDispatcher) {
        let my_id = self.environment.my_node.id;
        let now = Instant::now();

        let due: Vec<VertexHash> = self
            .recovery_state
            .iter()
            .filter(|(hash, state)| {
                now >= state.next_request_at && !self.execution_ready.contains(*hash)
            })
            .map(|(hash, _)| hash.clone())
            .collect();

        for hash in due {
            let state = self.recovery_state.get_mut(&hash).unwrap();
            let mut target = state.next_candidate(my_id);
            let mut restarted = false;
            if target.is_none() {
                // A full pass and no valid answer. At least f+1 voters are
                // correct and keep the data for the retention window, so
                // start over, waiting longer between requests.
                state.next_idx = 0;
                state.passes += 1;
                restarted = true;
                target = state.next_candidate(my_id);
            }
            let passes = state.passes;
            let wait_ms = (self.recovery_timeout_ms as u64)
                << passes.min(MAX_RECOVERY_BACKOFF_SHIFT);
            state.next_request_at = now + Duration::from_millis(wait_ms);
            state.requested_from = target;
            let message = target.map(|node| {
                state.asked.insert(node);
                match &state.target {
                    RecoveryTarget::Vertex => PRBCMessage::PRBCRecovery(PRBCRecoveryMessage {
                        hash: hash.clone(),
                        requester: my_id,
                    }),
                    RecoveryTarget::Batch(digest) => {
                        PRBCMessage::BatchRequest(PRBCBatchRequestMessage {
                            digest: digest.clone(),
                            requester: my_id,
                        })
                    }
                }
            });

            if restarted {
                self.recovery_restarts += 1;
                warn!(
                    "[Node {}] Recovery: no valid answer from any voter for hash {:?}, \
                     starting pass {}",
                    my_id,
                    &hash[..4.min(hash.len())],
                    passes + 1
                );
                // If an unrecovered leader suspended the timeout, resume the
                // timeout path so the protocol can still make progress.
                if passes == 1 {
                    if let Some(vertex) = self.dag.vertices.get(&hash) {
                        let leader =
                            (vertex.round % self.environment.nodes.len() as u64) as NodeId;
                        if vertex.source == leader {
                            self.timeout_suspended.remove(&vertex.round);
                        }
                    }
                }
            }

            let (Some(node), Some(message)) = (target, message) else {
                continue;
            };
            match &message {
                PRBCMessage::PRBCRecovery(_) => self.recovery_requests_sent += 1,
                _ => self.batch_requests_sent += 1,
            }
            debug!(
                "[Node {}] Recovery: request for hash {:?} sent to Node {}",
                my_id,
                &hash[..4.min(hash.len())],
                node
            );
            let _ = dispatcher_tx.send((DispatchTarget::One(node), message)).await;
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
        self.certified_slot.insert(genesis_hash.clone(), (0, 0));
        self.record_vertex_edges(&genesis);
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

        // Byz3: send each batch to only 2f+1 peers (the lowest IDs), the batch
        // counterpart of Byz1. Everything else, including its own S1 relay and
        // its proposals, stays correct.
        let batch_peers: Option<Vec<NodeId>> =
            (self.environment.my_node.behavior == NodeBehavior::Byz3).then(|| {
                let peers: Vec<NodeId> = node_ids
                    .iter()
                    .copied()
                    .filter(|&id| id != source)
                    .take(2 * self.f + 1)
                    .collect();
                warn!("[Node {}] BYZ3: batches go to only {}/{} peers",
                    source, peers.len(), node_ids.len() - 1);
                peers
            });

        // Resolve the effective per-tick batch size and interval once, up
        // front, so print_dag_stats() and the CONFIG printout can both report
        // the actual configuration the generator task below will use. When
        // MAX_BATCH_DELAY_MS is unset (the default), this reproduces today's
        // exact pacing: effective_interval_us == natural_interval_us and
        // effective_n_tx == n_tx, unconditionally.
        let (effective_interval_us, effective_n_tx): (u64, usize) = if input_rate > 0 {
            let per_node_rate = (input_rate / n_nodes).max(1);
            let natural_interval_us = ((n_tx as u64 * 1_000_000) / per_node_rate).max(1);
            let eff_interval = match self.max_batch_delay_ms.map(|ms| ms.saturating_mul(1000)) {
                Some(cap) => natural_interval_us.min(cap).max(1),
                None => natural_interval_us,
            };
            let eff_n_tx = if eff_interval == natural_interval_us {
                n_tx
            } else {
                let ideal = (n_tx as u128 * eff_interval as u128) / natural_interval_us as u128;
                if ideal < 1 {
                    warn!(
                        "[Node {}] MAX_BATCH_DELAY_MS cap forces batch size below 1 tx; \
                         configured aggregate rate cannot be preserved exactly for this \
                         n_tx/rate/committee combination",
                        self.environment.my_node.id
                    );
                }
                ideal.max(1) as usize
            };
            (eff_interval, eff_n_tx)
        } else {
            (0, n_tx)
        };
        self.effective_n_tx = effective_n_tx;

        let (batch_tx, batch_rx) =
            tokio::sync::mpsc::channel::<(PRBCBatchMessage, Instant)>(64);
        self.batch_receiver = Some(batch_rx);
        let batch_dispatcher = dispatcher_tx.clone();
        tokio::spawn(async move {
            async fn disseminate_then_enqueue(
                source: NodeId,
                payload: Vec<u8>,
                created_at: Instant,
                node_ids: &[NodeId],
                batch_peers: &Option<Vec<NodeId>>,
                dispatcher: &MessageDispatcher,
                batch_tx: &Sender<(PRBCBatchMessage, Instant)>,
            ) -> bool {
                let digest = batch_digest(&payload);
                let batch = PRBCBatchMessage {
                    digest,
                    payload,
                };

                // The generator first broadcasts the complete batch to every
                // other process, independently of consensus (Byz3: to 2f+1).
                let direct = match batch_peers {
                    Some(peers) => DispatchTarget::Many(peers.clone()),
                    None => DispatchTarget::All,
                };
                if dispatcher
                    .send((direct, PRBCMessage::Batch(batch.clone())))
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
                let mut gen = TransactionGenerator::new(tx_size, effective_n_tx);
                let mut ticker = tokio::time::interval(Duration::from_micros(effective_interval_us));
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
                        &batch_peers,
                        &batch_dispatcher,
                        &batch_tx,
                    ).await {
                        break;
                    }
                }
            } else {
                let mut gen = TransactionGenerator::new(tx_size, n_tx);
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
                        &batch_peers,
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
        self.resource_meter = Some(ResourceMeter::start());

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
            self.tick_certificates(&dispatcher_tx).await;
            self.process_work_loop(&dispatcher_tx).await;
            self.drain_released_proposals(&dispatcher_tx).await;

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
                self.handle_prbc_propose(sender, propose.vertex, propose.signature, dispatcher_tx)
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
            PRBCMessage::BatchRequest(request) => {
                self.handle_batch_request(sender, request, dispatcher_tx).await
            }
            PRBCMessage::BatchResp(batch) => {
                self.handle_batch_resp(sender, batch, dispatcher_tx).await
            }
            PRBCMessage::CertRequest(request) => {
                self.handle_cert_request(sender, request, dispatcher_tx).await
            }
            PRBCMessage::Certificate(certificate) => {
                self.handle_certificate(certificate, dispatcher_tx).await
            }
            PRBCMessage::NoVote(no_vote) => self.handle_no_vote(sender, no_vote),
        }
        self.drain_released_proposals(dispatcher_tx).await;
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

        // Keys for checking vote signatures on the reader tasks; None when
        // PRBC_SIGS=off.
        let vote_keys = self.sign_votes.then(|| Arc::new(self.public_keys.clone()));

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
                            let vote_keys = vote_keys.clone();
                            tokio::spawn(async move {
                                Self::handle_connection(
                                    stream,
                                    msg_sender,
                                    my_id,
                                    claimed_id,
                                    plane,
                                    network_traffic,
                                    vote_keys,
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
        vote_keys: Option<Arc<HashMap<NodeId, PublicKey>>>,
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
            if let Ok(mut message) = deserialize::<PRBCMessage>(&buffer) {
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
                // Check signatures here, one reader task per peer, so the
                // checks run in parallel instead of one at a time in the
                // consensus loop. An invalid message is dropped.
                if let Some(keys) = &vote_keys {
                    if !verify_signatures(&mut message, keys) {
                        warn!("[Node {}] PRBC: invalid signature on a message from node {}",
                            my_id, peer_id);
                        continue;
                    }
                }
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
        // Actual per-batch tx count the generator task is using (may be
        // smaller than environment.n_transactions if MAX_BATCH_DELAY_MS
        // engaged) — throughput/CONFIG reporting must use this, not the
        // originally-configured count, or every TPS number below would be
        // silently inflated whenever the cap shrinks the real batch size.
        let n_tx           = self.effective_n_tx;
        let n_tx_configured = self.environment.n_transactions;
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

        // "checked on readers" marks builds that verify vote signatures on the
        // per-connection reader tasks rather than in the consensus loop.
        let sigs_label  = if self.sign_votes { "on, checked on readers" } else { "off" };
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

        let quorum_label = if self.reduced_quorum {
            format!("f+1 = {}", self.quorum())
        } else {
            format!("n-f = {}", self.quorum())
        };
        let max_batch_delay_label = match self.max_batch_delay_ms {
            None => "disabled".to_string(),
            Some(ms) => {
                if self.environment.input_rate == 0 {
                    format!("{} ms (not engaged - input rate unlimited)", ms)
                } else {
                    let per_node_rate = (self.environment.input_rate / n as u64).max(1);
                    let natural_us = ((n_tx_configured as u64 * 1_000_000) / per_node_rate).max(1);
                    if ms.saturating_mul(1000) < natural_us {
                        format!("{} ms (engaged - natural batch interval was {} ms)", ms, natural_us / 1000)
                    } else {
                        format!("{} ms (not engaged - natural interval already <= cap)", ms)
                    }
                }
            }
        };
        println!("\n+ CONFIG:");
        println!("  Protocol:             PRBC-Sailfish (vote sigs: {}, quorum: {})", sigs_label, quorum_label);
        println!("  Mempool:              decoupled (batch digests)");
        println!("  Faults:               {} node(s)", f_actual);
        println!("  Fault tolerance:      {} node(s)", f_tolerance);
        println!("  Committee size:       {} node(s)", n);
        println!("  Sample C:             {:.2}", prbc_c());
        println!("  Sample size:          {} node(s)", ((n as f64).sqrt() * prbc_c()).ceil() as usize);
        println!("  Input rate:           {}", rate_label);
        println!("  Max batch delay:      {}", max_batch_delay_label);
        println!("  Recovery timeout:     {} ms", self.recovery_timeout_ms);
        println!("  Retention window:     {} rounds", self.retention_rounds);
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
        println!("  Payload-lag events:   {}", self.payload_lag_count);
        println!("  Payload post-quorum:  {}", self.payload_post_quorum_count);
        println!("  Network recoveries:   {}", self.recovery_requests_sent);
        println!("  Recovery resp OK:     {}", self.recovery_responses_ok);
        println!("  Recovery resp served:  {}", self.recovery_responses_served);
        println!("  Batch requests sent:  {}", self.batch_requests_sent);
        println!("  Batch resp OK:        {}", self.batch_responses_ok);
        println!("  Batch resp served:    {}", self.batch_responses_served);
        println!("  Recovery restarts:    {}", self.recovery_restarts);
        println!("  Recovery abandoned:   {}", self.recoveries_abandoned);
        println!("  Recovery pending:     {}", self.recovery_state.len());
        println!("  Batches cached:       {}", self.batch_store.len());
        println!("  Batches retained:     {}", self.retained_batches.len());
        println!("  Vertices retained:    {}", self.retained_vertices.len());
        println!("  Leaders skipped:      {}", self.leaders_skipped);
        println!("  No-votes sent:        {}", self.no_votes_sent);
        println!("  Parent waits:         {}", self.parent_waits);
        println!("  Cert requests sent:   {}", self.cert_requests_sent);
        println!("  Cert resp OK:         {}", self.cert_responses_ok);
        println!("  Cert resp served:     {}", self.cert_responses_served);
        println!("  Invalid vertices:     {}", self.invalid_vertices);
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

        match self.resource_meter.as_ref().map(|m| m.report()) {
            Some(r) if r.available => {
                println!("  Process CPU 1core %:  {:.1}", r.cpu_pct_one_core);
                println!("  Process CPU machine %:  {:.1}", r.cpu_pct_machine);
                println!("  CPU sample window s:  {:.1}", r.wall_secs);
                println!("  Process user CPU s:   {:.2}", r.user_cpu_secs);
                println!("  Process sys CPU s:    {:.2}", r.sys_cpu_secs);
                println!("  Process peak RSS MB:  {:.0}", r.peak_rss_mb);
                println!("  Machine cores:        {}", r.n_cores);
            }
            _ => println!("  Process CPU:          n/a (no /proc)"),
        }
    }
}

#[cfg(test)]
mod recovery_state_tests {
    use super::*;

    fn state(vote_list: Vec<NodeId>) -> RecoveryState {
        RecoveryState {
            round: 1,
            target: RecoveryTarget::Vertex,
            vote_list,
            next_idx: 0,
            passes: 0,
            next_request_at: Instant::now(),
            requested_from: None,
            asked: HashSet::new(),
        }
    }

    #[test]
    fn candidates_skip_self_and_end_after_one_pass() {
        let mut s = state(vec![3, 1, 2]);
        assert_eq!(s.next_candidate(1), Some(3));
        assert_eq!(s.next_candidate(1), Some(2));
        assert_eq!(s.next_candidate(1), None);
        // tick_recovery starts the next pass by resetting the index.
        s.next_idx = 0;
        assert_eq!(s.next_candidate(1), Some(3));
    }

    #[test]
    fn switching_to_batch_starts_a_fresh_pass() {
        let mut s = state(vec![3, 1, 2]);
        s.next_candidate(1);
        s.asked.insert(3);
        s.passes = 2;
        s.switch_to_batch(vec![7; 32], Duration::from_millis(50));
        assert_eq!(s.target, RecoveryTarget::Batch(vec![7; 32]));
        assert_eq!((s.next_idx, s.passes), (0, 0));
        assert!(s.asked.is_empty() && s.requested_from.is_none());
        assert!(s.next_request_at > Instant::now());
    }
}
