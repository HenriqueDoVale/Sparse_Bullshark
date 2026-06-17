use serde::{Deserialize, Serialize};
use crate::types::vertex::{NodeId, Vertex, VertexHash};
use crate::network::message::TimeoutMessage;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PRBCProposeMessage {
    pub vertex: Vertex,
}

/// Phase 2: a vote over hash(v) broadcast by every node after receiving a propose.
/// Authentication relies on the transport-layer TCP handshake — no per-message sig needed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PRBCVoteMessage {
    pub round: u64,
    pub source: NodeId,   // the proposer of the vertex being voted on
    pub hash: VertexHash, // hash of the vertex
}

/// Phase 3: a targeted request for a payload that arrived via hash quorum only.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PRBCRecoveryMessage {
    pub hash: VertexHash,
    pub requester: NodeId,
}

/// Phase 3 response: payload + the voter IDs that formed the quorum.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PRBCRecoveryRespMessage {
    pub vertex: Vertex,
    pub voters: Vec<NodeId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PRBCMessage {
    PRBCPropose(PRBCProposeMessage),
    PRBCVote(PRBCVoteMessage),
    PRBCRecovery(PRBCRecoveryMessage),
    PRBCRecoveryResp(PRBCRecoveryRespMessage),
    Timeout(TimeoutMessage),
}
