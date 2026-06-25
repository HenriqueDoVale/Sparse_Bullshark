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
    pub vertex_hash: VertexHash,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReadyMessage {
    pub vertex_hash: VertexHash,
    pub vertex: Option<Vertex>,
}
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TimeoutMessage {
    pub round: u64,
    pub signature: Vec<u8>,
}

// ── Signed-Vote RBC messages ──────────────────────────────────────────────────

/// Vote message for the Signed-Vote RBC.
/// Carries the full vertex so that nodes which missed the Propose can recover
/// the block body from any vote they receive.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RBCVoteMessage {
    pub vertex:    Vertex,
    pub voter:     NodeId,
    pub signature: Vec<u8>,  // Ed25519 sign(vertex.hash) with voter's private key
}

/// Commit certificate: one copy of the vertex body + n-f voter signatures.
/// Forwarded by any node that collects n-f valid votes, allowing late nodes
/// to deliver without having collected the votes themselves.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RBCCommitMessage {
    pub vertex: Vertex,
    pub votes:  std::collections::BTreeMap<NodeId, Vec<u8>>, // voter → signature
}

/// Unified network message type for Sparse Bullshark.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SparseMessage {
    Vertex(VertexMessage),
    RBCEcho(EchoMessage),          // Bracha RBC
    RBCReady(ReadyMessage),        // Bracha RBC
    RBCVote(RBCVoteMessage),       // Signed-Vote RBC
    RBCCommit(RBCCommitMessage),   // Signed-Vote RBC
    Timeout(TimeoutMessage),
    Commit(CommitMessage),
}
