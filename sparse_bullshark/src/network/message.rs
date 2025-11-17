use serde::{Serialize, Deserialize};
use crate::types::vertex::Vertex;
use crate::types::vertex::NodeId;
use crate::types::vertex::VertexHash;

/// Message carrying a DAG vertex from one node to others.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VertexMessage {
    pub sender: NodeId,
    pub vertex: Vertex,
} 

/// Notification that certain vertices were finalized / committed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitMessage {
    pub round: u64,
    pub committed_vertices: Vec<Vertex>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EchoMessage {
    pub vertex_hash : VertexHash,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReadyMessage {
    pub vertex_hash : VertexHash,
}

/// Unified network message type for Sparse Bullshark.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SparseMessage {
    Vertex(VertexMessage),
    RBC_Echo(EchoMessage),
    RBC_Ready(ReadyMessage),
    Commit(CommitMessage),
}
