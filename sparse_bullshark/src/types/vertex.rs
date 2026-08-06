use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
pub type NodeId = u32;
pub type VertexHash = Vec<u8>;
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq, Hash)]
pub struct Vertex {
    pub hash: VertexHash,
    pub round: u64,
    pub source: NodeId,
    pub block: Vec<u8>,
    pub edges: Vec<VertexHash>,
    /// Weak edges: hashes of vertices at rounds < r-1 that are in the local DAG
    /// but not reachable through the strong-edge (round r-1) causal chain.
    /// Ensures orphaned vertices are eventually included in a commit's causal history.
    pub weak_edges: Vec<VertexHash>,
    pub signed_round: Vec<u8>,
    pub sample_proof: Vec<u8>,
    pub tc: Option<TimeoutCertificate>,
    pub nvc: Option<NoVoteCertificate>,
}
impl Vertex {
    fn hash_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }

    pub fn calculate_hash(&self) -> VertexHash {
        let mut hasher = Sha256::new();
        hasher.update(self.round.to_be_bytes());
        hasher.update(self.source.to_be_bytes());
        Self::hash_len_prefixed(&mut hasher, &self.block);
        hasher.update((self.edges.len() as u64).to_be_bytes());
        for edge in &self.edges {
            Self::hash_len_prefixed(&mut hasher, edge);
        }
        // Weak edges are sorted before hashing so the hash is deterministic
        // regardless of the order they were discovered during the BFS.
        let mut sorted_weak = self.weak_edges.clone();
        sorted_weak.sort();
        hasher.update((sorted_weak.len() as u64).to_be_bytes());
        for edge in &sorted_weak {
            Self::hash_len_prefixed(&mut hasher, edge);
        }
        Self::hash_len_prefixed(&mut hasher, &self.signed_round);
        Self::hash_len_prefixed(&mut hasher, &self.sample_proof);
        let tc_bytes = bincode::serialize(&self.tc)
            .expect("timeout certificate serialization should not fail");
        Self::hash_len_prefixed(&mut hasher, &tc_bytes);
        let nvc_bytes = bincode::serialize(&self.nvc)
            .expect("no-vote certificate serialization should not fail");
        Self::hash_len_prefixed(&mut hasher, &nvc_bytes);
        hasher.finalize().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::Vertex;

    fn vertex(block: Vec<u8>, edges: Vec<Vec<u8>>) -> Vertex {
        Vertex {
            hash: Vec::new(),
            round: 1,
            source: 0,
            block,
            edges,
            weak_edges: Vec::new(),
            signed_round: Vec::new(),
            sample_proof: Vec::new(),
            tc: None,
            nvc: None,
        }
    }

    #[test]
    fn hash_distinguishes_variable_length_field_boundaries() {
        let block_then_edge = vertex(vec![1], vec![vec![2]]);
        let longer_block = vertex(vec![1, 2], Vec::new());

        assert_ne!(
            block_then_edge.calculate_hash(),
            longer_block.calculate_hash()
        );
    }
}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq, Hash)]
pub struct TimeoutCertificate {
    pub round: u64,
    pub signatures: BTreeMap<NodeId, Vec<u8>>, // NodeId -> Signature
}

// A proof that the previous leader got NO votes (optional, for advanced logic)
// For the basic implementation, we can often rely just on the TimeoutCertificate.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq, Hash)]
pub struct NoVoteCertificate {
    pub round: u64,
    pub signatures: BTreeMap<NodeId, Vec<u8>>,
}
