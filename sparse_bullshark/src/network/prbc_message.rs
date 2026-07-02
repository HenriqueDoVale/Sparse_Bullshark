use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};
use crate::types::vertex::{NodeId, Vertex, VertexHash};
use crate::network::message::TimeoutMessage;

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

/// Phase 3: a targeted request for a payload that arrived via hash quorum only.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PRBCRecoveryMessage {
    pub hash: VertexHash,
    pub requester: NodeId,
}

/// Phase 3 response: payload + the full vote certificate (voter → Ed25519 sig).
/// When PRBC_SIGS=on the receiver verifies each signature independently.
/// When PRBC_SIGS=off signatures are empty vecs and TCP-auth cross-reference is used.
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
