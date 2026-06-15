use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use crate::types::vertex::{NodeId, Vertex, VertexHash};
use crate::network::message::TimeoutMessage;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PRBCProposeMessage {
    pub vertex: Vertex,
}

/// Phase 2: a vote over hash(v) broadcast by every node after receiving a propose.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PRBCVoteMessage {
    pub round: u64,
    pub source: NodeId,          // the proposer of the vertex being voted on
    pub hash: VertexHash,        // hash of the vertex
    pub voter: NodeId,
    pub signature: Vec<u8>,      // sign(hash || round.to_be_bytes())
}

/// Phase 3: a targeted request for a payload that arrived via hash quorum only.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PRBCRecoveryMessage {
    pub hash: VertexHash,
    pub requester: NodeId,
}

/// Phase 3 response: payload + the 2f+1 votes that prove it was committed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PRBCRecoveryRespMessage {
    pub vertex: Vertex,
    pub votes: BTreeMap<NodeId, Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PRBCMessage {
    PRBCPropose(PRBCProposeMessage),
    PRBCVote(PRBCVoteMessage),
    PRBCRecovery(PRBCRecoveryMessage),
    PRBCRecoveryResp(PRBCRecoveryRespMessage),
    Timeout(TimeoutMessage),
}
