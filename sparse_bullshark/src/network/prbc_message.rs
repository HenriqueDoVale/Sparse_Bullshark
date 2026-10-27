use serde::{Deserialize, Serialize};
use crate::types::vertex::{NodeId, Vertex, VertexHash};
use crate::network::message::TimeoutMessage;

/// A serialized transaction batch disseminated independently of its vertex.
/// Its digest alone determines the batch's S1 and per-member S2 relay sets.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PRBCBatchMessage {
    pub digest: VertexHash,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PRBCProposeMessage {
    pub vertex: Vertex,
}

/// Phase 2: a vote over hash(v) broadcast by every node after receiving a propose.
/// When PRBC_SIGS=on, each vote carries an Ed25519 signature over the vertex hash.
/// When PRBC_SIGS is unset/off, signature is an empty Vec and TCP-layer identity is used.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PRBCVoteMessage {
    pub round: u64,
    pub source: NodeId,        // the proposer of the vertex being voted on
    pub hash: VertexHash,      // hash of the vertex
    pub voter: NodeId,         // who is casting this vote
    pub signature: Vec<u8>,    // Ed25519 sign(hash) when enabled; empty otherwise
}

/// Phase 3: a targeted request for a vertex that arrived via hash quorum only.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PRBCRecoveryMessage {
    pub hash: VertexHash,
    pub requester: NodeId,
}

/// Phase 3 response: the vertex alone. The requester already holds 2f+1 votes
/// for its hash (recovery is only armed on a hash quorum), so it checks
/// hash(vertex) against that hash and needs no certificate from the responder.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PRBCRecoveryRespMessage {
    pub vertex: Vertex,
}

/// Phase 3, second step: a targeted request for the batch named by a
/// certified vertex's digest. Answered with `BatchResp`, which the requester
/// checks against the digest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PRBCBatchRequestMessage {
    pub digest: VertexHash,
    pub requester: NodeId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PRBCMessage {
    /// Best-effort dissemination of a serialized transaction batch. Vertices
    /// refer to this payload only by `digest`.
    Batch(PRBCBatchMessage),
    PRBCPropose(PRBCProposeMessage),
    PRBCVote(PRBCVoteMessage),
    PRBCRecovery(PRBCRecoveryMessage),
    PRBCRecoveryResp(PRBCRecoveryRespMessage),
    Timeout(TimeoutMessage),
    /// Request for a missing batch, sent once its vertex is certified and known.
    BatchRequest(PRBCBatchRequestMessage),
    /// Unicast answer to a `BatchRequest`. Unlike `Batch`, it is never relayed.
    BatchResp(PRBCBatchMessage),
}
