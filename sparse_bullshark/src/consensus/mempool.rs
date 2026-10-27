//! Decoupled mempool (data plane) — Narwhal-style separation of *what* is
//! ordered (transaction batches) from *how* it is ordered (the DAG of vertices).
//!
//! In the legacy ("inline") design every vertex carries its full transaction
//! payload in `Vertex.block`, so the payload is re-forwarded on the RBC critical
//! path with every echo / vote / ready — O(n²) payload traffic. Here the vertex
//! carries only fixed-size batch *digests*; the payload is disseminated once,
//! off the critical path, via `SparseMessage::Batch`, and cached in a local
//! `BatchStore` keyed by digest. This is the throughput lever Narwhal exploits.
//!
//! Enabled per-run behind the `MEMPOOL_MODE=decoupled` env var; when unset the
//! node keeps the exact inline behavior, so the two can be benchmarked from the
//! same binary.

use std::collections::{BTreeMap, HashMap};
use sha2::{Digest, Sha256};

use crate::types::vertex::VertexHash;

/// A batch digest is a SHA-256 over the serialized batch payload, reusing the
/// same byte-vector type as vertex hashes for uniformity on the wire.
pub type BatchDigest = VertexHash;

/// SHA-256 of a serialized batch payload.
pub fn batch_digest(payload: &[u8]) -> BatchDigest {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    hasher.finalize().to_vec()
}

/// Local content-addressed store of batch payloads (digest → serialized batch).
///
/// Intentionally minimal for phase 1: an in-memory map with no eviction. The
/// DAG is pruned with a safety window, so a follow-up phase can prune the store
/// against `last_ordered_round` to bound memory.
#[derive(Default)]
pub struct BatchStore {
    batches: HashMap<BatchDigest, Vec<u8>>,
}

impl BatchStore {
    pub fn new() -> Self {
        Self { batches: HashMap::new() }
    }

    pub fn insert(&mut self, digest: BatchDigest, payload: Vec<u8>) {
        self.batches.insert(digest, payload);
    }

    pub fn contains(&self, digest: &[u8]) -> bool {
        self.batches.contains_key(digest)
    }

    pub fn get(&self, digest: &[u8]) -> Option<&Vec<u8>> {
        self.batches.get(digest)
    }

    pub fn remove(&mut self, digest: &[u8]) -> Option<Vec<u8>> {
        self.batches.remove(digest)
    }

    pub fn len(&self) -> usize {
        self.batches.len()
    }
}

/// Delivered items (batches or vertices) kept for a bounded number of rounds
/// so that peers that missed them can still fetch them. Plays the role of
/// Narwhal's `gc_depth`. Indexed by round so pruning is a range split.
pub struct RetentionStore<V> {
    items: HashMap<Vec<u8>, V>,
    by_round: BTreeMap<u64, Vec<Vec<u8>>>,
}

impl<V> RetentionStore<V> {
    pub fn new() -> Self {
        Self { items: HashMap::new(), by_round: BTreeMap::new() }
    }

    pub fn insert(&mut self, round: u64, key: Vec<u8>, value: V) {
        if self.items.insert(key.clone(), value).is_none() {
            self.by_round.entry(round).or_default().push(key);
        }
    }

    pub fn get(&self, key: &[u8]) -> Option<&V> {
        self.items.get(key)
    }

    /// Drop everything retained for rounds below `round`.
    pub fn prune_below(&mut self, round: u64) {
        let keep = self.by_round.split_off(&round);
        for (_, keys) in std::mem::replace(&mut self.by_round, keep) {
            for key in keys {
                self.items.remove(&key);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }
}

#[cfg(test)]
mod retention_tests {
    use super::RetentionStore;

    #[test]
    fn prunes_only_rounds_below_the_cutoff() {
        let mut store = RetentionStore::new();
        store.insert(3, vec![3], "a");
        store.insert(5, vec![5], "b");
        store.insert(5, vec![6], "c");
        store.prune_below(5);
        assert!(store.get(&[3]).is_none());
        assert_eq!(store.get(&[5]), Some(&"b"));
        assert_eq!(store.get(&[6]), Some(&"c"));
        assert_eq!(store.len(), 2);
    }
}

/// Encode a vertex's `block` field for decoupled mode: the list of batch
/// digests the vertex references (phase 1 = exactly one).
pub fn encode_digests(digests: &[BatchDigest]) -> Vec<u8> {
    bincode::serialize(&digests.to_vec()).expect("digest list serialize failed")
}

/// Decode the digest list from a vertex's `block`. Returns an empty vector for
/// blocks that do not hold a digest list (e.g. the genesis vertex, whose block
/// is empty), so callers can treat "no digests" and "genesis" uniformly.
pub fn decode_digests(block: &[u8]) -> Vec<BatchDigest> {
    bincode::deserialize::<Vec<BatchDigest>>(block).unwrap_or_default()
}
