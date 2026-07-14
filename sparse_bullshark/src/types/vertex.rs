use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use std::collections::BTreeMap;
pub type NodeId = u32;
pub type VertexHash = Vec<u8>;
#[derive(Clone, Debug,serde::Deserialize, serde::Serialize, PartialEq, Eq, Hash)]
pub struct Vertex{
    pub hash: VertexHash,
    pub round: u64,
    pub source : NodeId,
    pub block : Vec<u8>,
    pub edges : Vec<VertexHash>,
    /// Weak edges: hashes of vertices at rounds < r-1 that are in the local DAG
    /// but not reachable through the strong-edge (round r-1) causal chain.
    /// Ensures orphaned vertices are eventually included in a commit's causal history.
    pub weak_edges: Vec<VertexHash>,
    pub signed_round : Vec<u8>,
    pub sample_proof: Vec<u8>,
    pub tc: Option<TimeoutCertificate>,
    pub nvc: Option<NoVoteCertificate>,
}
impl Vertex {
    pub fn calculate_hash(&self) -> VertexHash{
        let mut hasher = Sha256::new();
        hasher.update(&self.round.to_be_bytes());
        hasher.update(&self.source.to_be_bytes());
        hasher.update(&self.block);
        for edge in &self.edges {
            hasher.update(edge);
        }
        // Weak edges are sorted before hashing so the hash is deterministic
        // regardless of the order they were discovered during the BFS.
        let mut sorted_weak = self.weak_edges.clone();
        sorted_weak.sort();
        for edge in &sorted_weak {
            hasher.update(edge);
        }
        hasher.update(&self.signed_round);
        hasher.update(&self.sample_proof);
        if let Ok(tc_bytes) = bincode::serialize(&self.tc) {
            hasher.update(&tc_bytes);
        }

        if let Ok(nvc_bytes) = bincode::serialize(&self.nvc) {
            hasher.update(&nvc_bytes);
        }
        hasher.finalize().to_vec()
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