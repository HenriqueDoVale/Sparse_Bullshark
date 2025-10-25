use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
pub type NodeId = u32;
pub type VertexHash = Vec<u8>;
#[derive(Clone, Debug,serde::Deserialize, serde::Serialize, PartialEq, Eq, Hash)]
pub struct Vertex{
    pub hash: VertexHash,
    pub round: u64,
    pub source : NodeId,
    pub block : Vec<u8>,
    pub edges : Vec<VertexHash>,
    pub signed_round : Vec<u8>,
    pub sample_proof: Vec<u8>,
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
        hasher.update(&self.signed_round);
        hasher.update(&self.sample_proof);
        hasher.finalize().to_vec()
    }
}