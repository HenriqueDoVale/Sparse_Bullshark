//! Decoupled mempool (data plane) — Narwhal-style separation of *what* is
//! ordered (transaction batches) from *how* it is ordered (the DAG of vertices).
//!
//! Three modes, selected via `MEMPOOL_MODE`:
//!   - `inline`    : legacy — the full payload rides inside the vertex.
//!   - `decoupled` : phase 1 — the vertex carries ONE batch digest; the payload
//!                   is disseminated once and cached; availability via pull-repair.
//!   - `workers`   : phase 2 — Narwhal-style. Several parallel worker tasks batch
//!                   transactions (by count or delay), disseminate them, and a
//!                   QuorumWaiter certifies each batch once 2f+1 authorities have
//!                   acknowledged storing it. The proposer then packs ALL certified
//!                   digests into a single vertex.
//!
//! The worker + QuorumWaiter here are protocol-agnostic (they know nothing of the
//! Sailfish/PRBC wire format): the caller broadcasts each `SealedBatch` and feeds
//! acknowledgements back in by `NodeId`. This is what makes the module reusable by
//! PRBC-Sailfish later.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use sha2::{Digest as _, Sha256};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::time::{sleep, Duration, Instant};

use shared::domain::transaction::Transaction;
use crate::types::vertex::{NodeId, VertexHash};

/// A batch digest is a SHA-256 over the serialized batch payload.
pub type BatchDigest = VertexHash;

/// SHA-256 of a serialized batch payload.
pub fn batch_digest(payload: &[u8]) -> BatchDigest {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    hasher.finalize().to_vec()
}

/// Mempool operating mode, chosen once at startup via `MEMPOOL_MODE`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MempoolMode {
    Inline,
    Decoupled,
    Workers,
}

impl MempoolMode {
    pub fn from_env() -> Self {
        match std::env::var("MEMPOOL_MODE").ok().as_deref() {
            Some(v) if v.eq_ignore_ascii_case("workers")   => MempoolMode::Workers,
            Some(v) if v.eq_ignore_ascii_case("decoupled") => MempoolMode::Decoupled,
            _ => MempoolMode::Inline,
        }
    }
    /// True when vertices carry digests rather than the raw payload.
    pub fn uses_digests(self) -> bool {
        self != MempoolMode::Inline
    }
    pub fn label(self) -> &'static str {
        match self {
            MempoolMode::Inline    => "inline (payload)",
            MempoolMode::Decoupled => "decoupled (1 digest)",
            MempoolMode::Workers   => "workers (multi-digest, 2f+1 certs)",
        }
    }
}

/// Local content-addressed store of batch payloads, keyed by digest.
///
/// Thread-safe and cheaply cloneable (an `Arc` handle) so the consensus loop and
/// the worker / QuorumWaiter tasks can share one store. Each entry keeps the batch
/// payload and its transaction count (so committed throughput can be measured
/// exactly when batches have variable size).
#[derive(Clone, Default)]
pub struct BatchStore {
    inner: Arc<Mutex<HashMap<BatchDigest, (Vec<u8>, usize)>>>,
}

impl BatchStore {
    pub fn new() -> Self {
        Self { inner: Arc::new(Mutex::new(HashMap::new())) }
    }
    pub fn insert(&self, digest: BatchDigest, payload: Vec<u8>, tx_count: usize) {
        self.inner.lock().unwrap().insert(digest, (payload, tx_count));
    }
    pub fn contains(&self, digest: &[u8]) -> bool {
        self.inner.lock().unwrap().contains_key(digest)
    }
    /// Returns an owned copy of the payload (avoids holding the lock).
    pub fn get_payload(&self, digest: &[u8]) -> Option<Vec<u8>> {
        self.inner.lock().unwrap().get(digest).map(|(p, _)| p.clone())
    }
    /// Transaction count of a stored batch (0 if unknown).
    pub fn tx_count(&self, digest: &[u8]) -> usize {
        self.inner.lock().unwrap().get(digest).map(|(_, c)| *c).unwrap_or(0)
    }
    /// Drop a batch once it is no longer needed (its vertex has been committed
    /// and pruned). Bounds memory — without this the store grows unbounded.
    pub fn remove(&self, digest: &[u8]) -> bool {
        self.inner.lock().unwrap().remove(digest).is_some()
    }
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }
}

/// Encode a vertex's `block` field: the list of batch digests it references.
pub fn encode_digests(digests: &[BatchDigest]) -> Vec<u8> {
    bincode::serialize(&digests.to_vec()).expect("digest list serialize failed")
}

/// Decode the digest list from a vertex's `block`. Returns an empty vector for
/// blocks that do not hold a digest list (e.g. genesis, or an inline payload).
pub fn decode_digests(block: &[u8]) -> Vec<BatchDigest> {
    bincode::deserialize::<Vec<BatchDigest>>(block).unwrap_or_default()
}

/// A batch a worker has sealed and stored locally, ready to be disseminated and
/// certified. The caller broadcasts it and registers `digest` with the QuorumWaiter.
pub struct SealedBatch {
    pub digest:   BatchDigest,
    pub payload:  Vec<u8>,
    pub tx_count: usize,
}

/// Spawn a Narwhal-style worker task.
///
/// It accumulates incoming transactions into a batch and **seals** it when the
/// batch reaches `max_batch_txs` transactions, or when `max_batch_delay_ms`
/// elapses with a non-empty batch. Each sealed batch is stored locally and
/// emitted on `tx_sealed` for dissemination + certification.
pub fn spawn_worker(
    mut rx_tx: Receiver<Transaction>,
    store: BatchStore,
    tx_sealed: Sender<SealedBatch>,
    max_batch_txs: usize,
    max_batch_delay_ms: u64,
) {
    tokio::spawn(async move {
        let mut current: Vec<Transaction> = Vec::with_capacity(max_batch_txs);
        let timer = sleep(Duration::from_millis(max_batch_delay_ms));
        tokio::pin!(timer);

        loop {
            tokio::select! {
                maybe = rx_tx.recv() => {
                    match maybe {
                        Some(tx) => {
                            current.push(tx);
                            if current.len() >= max_batch_txs {
                                seal(&mut current, &store, &tx_sealed).await;
                                timer.as_mut().reset(Instant::now() + Duration::from_millis(max_batch_delay_ms));
                            }
                        }
                        None => break, // transaction source closed
                    }
                }
                () = &mut timer => {
                    if !current.is_empty() {
                        seal(&mut current, &store, &tx_sealed).await;
                    }
                    timer.as_mut().reset(Instant::now() + Duration::from_millis(max_batch_delay_ms));
                }
            }
        }
    });
}

async fn seal(current: &mut Vec<Transaction>, store: &BatchStore, tx_sealed: &Sender<SealedBatch>) {
    let batch: Vec<Transaction> = std::mem::take(current);
    let tx_count = batch.len();
    let payload = bincode::serialize(&batch).expect("batch serialize failed");
    let digest = batch_digest(&payload);
    store.insert(digest.clone(), payload.clone(), tx_count);
    let _ = tx_sealed.send(SealedBatch { digest, payload, tx_count }).await;
}

/// Spawn the Narwhal-style QuorumWaiter task.
///
/// A locally-sealed batch's digest is `register`ed here. Once `quorum` (= 2f+1)
/// distinct authorities — self plus peers who returned an ack — have acknowledged
/// storing it, the digest is emitted on `tx_certified`, meaning "safe to propose:
/// at least f+1 honest nodes hold this batch". This is the availability guarantee
/// that phase-1 pull-repair lacked.
pub fn spawn_quorum_waiter(
    self_id: NodeId,
    quorum: usize,
    mut rx_register: Receiver<BatchDigest>,
    mut rx_ack: Receiver<(BatchDigest, NodeId)>,
    tx_certified: Sender<BatchDigest>,
) {
    tokio::spawn(async move {
        let mut acks: HashMap<BatchDigest, HashSet<NodeId>> = HashMap::new();
        let mut registered: HashSet<BatchDigest> = HashSet::new();
        let mut emitted: HashSet<BatchDigest> = HashSet::new();

        loop {
            tokio::select! {
                Some(digest) = rx_register.recv() => {
                    registered.insert(digest.clone());
                    acks.entry(digest.clone()).or_default().insert(self_id);
                    try_certify(&digest, &acks, &registered, &mut emitted, quorum, &tx_certified).await;
                }
                Some((digest, voter)) = rx_ack.recv() => {
                    acks.entry(digest.clone()).or_default().insert(voter);
                    try_certify(&digest, &acks, &registered, &mut emitted, quorum, &tx_certified).await;
                }
                else => break,
            }
        }
    });
}

async fn try_certify(
    digest: &BatchDigest,
    acks: &HashMap<BatchDigest, HashSet<NodeId>>,
    registered: &HashSet<BatchDigest>,
    emitted: &mut HashSet<BatchDigest>,
    quorum: usize,
    tx_certified: &Sender<BatchDigest>,
) {
    if emitted.contains(digest) || !registered.contains(digest) {
        return;
    }
    if acks.get(digest).map_or(0, |s| s.len()) >= quorum {
        emitted.insert(digest.clone());
        let _ = tx_certified.send(digest.clone()).await;
    }
}
