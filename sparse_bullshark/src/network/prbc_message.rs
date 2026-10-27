use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};
use crate::types::vertex::{NodeId, Vertex, VertexHash};
use crate::network::message::TimeoutMessage;

// ── Signed byte strings ──────────────────────────────────────────────────────
// Each kind of signature covers its own tagged byte string, so a signature made
// for one purpose can never be presented as another.

/// What a vote signs: the vertex hash bound to its slot (round, source). Signing
/// the hash alone would let a faulty node relabel an honest vote for one slot as
/// a vote for another.
pub fn vote_signing_bytes(round: u64, source: NodeId, hash: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(9 + 8 + 4 + hash.len());
    bytes.extend_from_slice(b"prbc-vote");
    bytes.extend_from_slice(&round.to_be_bytes());
    bytes.extend_from_slice(&source.to_be_bytes());
    bytes.extend_from_slice(hash);
    bytes
}

/// What a proposer signs. The vertex hash covers its round, source, digest and
/// edges, so only the source can fill its own slot.
pub fn propose_signing_bytes(hash: &[u8]) -> Vec<u8> {
    [b"prbc-vertex".as_ref(), hash].concat()
}

/// What a no-vote signs: "my round-(round+1) vertex does not point to the
/// leader of `round`".
pub fn no_vote_signing_bytes(round: u64) -> Vec<u8> {
    [b"prbc-no-vote".as_ref(), &round.to_be_bytes()].concat()
}

/// A serialized transaction batch disseminated independently of its vertex.
/// Its digest alone determines the batch's S1 and per-member S2 relay sets.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PRBCBatchMessage {
    pub digest: VertexHash,
    pub payload: Vec<u8>,
}

/// Phase 1: a vertex and its source's signature over `propose_signing_bytes`.
/// S1→S2 relays forward the source's signature unchanged.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PRBCProposeMessage {
    pub vertex: Vertex,
    pub signature: Vec<u8>,    // empty when PRBC_SIGS=off
}

/// Phase 2: a vote over hash(v) broadcast by every node after receiving a propose.
/// When PRBC_SIGS=on (default), each vote carries an Ed25519 signature over
/// `vote_signing_bytes(round, source, hash)`. When off, signature is empty and
/// TCP-layer identity is used.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PRBCVoteMessage {
    pub round: u64,
    pub source: NodeId,        // the proposer of the vertex being voted on
    pub hash: VertexHash,      // hash of the vertex
    pub voter: NodeId,         // who is casting this vote
    pub signature: Vec<u8>,    // Ed25519 over vote_signing_bytes when enabled; empty otherwise
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

/// A request for the certificate (2f+1 signed votes) of a hash this process
/// saw referenced as a parent but has not certified itself.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PRBCCertRequestMessage {
    pub hash: VertexHash,
    pub requester: NodeId,
}

/// A vertex certificate: 2f+1 votes for (round, source, hash). Each vote is
/// checked against `vote_signing_bytes`, so it is valid whoever forwards it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PRBCCertificateMessage {
    pub round: u64,
    pub source: NodeId,
    pub hash: VertexHash,
    pub votes: BTreeMap<NodeId, Vec<u8>>,
}

/// Sent to the leader of round+1 by a process whose round-(round+1) vertex
/// does not point to the leader of `round`. 2f+1 of them form the no-vote
/// certificate that lets that leader skip the previous one (Sailfish).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PRBCNoVoteMessage {
    pub round: u64,
    pub voter: NodeId,
    pub signature: Vec<u8>,    // Ed25519 over no_vote_signing_bytes when enabled
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
    /// Request for a missing parent's certificate.
    CertRequest(PRBCCertRequestMessage),
    /// Answer to a `CertRequest`.
    Certificate(PRBCCertificateMessage),
    NoVote(PRBCNoVoteMessage),
}

#[cfg(test)]
mod signing_tests {
    use super::*;

    #[test]
    fn a_vote_signature_is_bound_to_its_slot() {
        let hash = vec![9; 32];
        assert_ne!(vote_signing_bytes(1, 0, &hash), vote_signing_bytes(1, 1, &hash));
        assert_ne!(vote_signing_bytes(1, 0, &hash), vote_signing_bytes(2, 0, &hash));
    }

    #[test]
    fn signature_purposes_never_overlap() {
        let hash = vec![9; 32];
        let vote = vote_signing_bytes(1, 0, &hash);
        let propose = propose_signing_bytes(&hash);
        let no_vote = no_vote_signing_bytes(1);
        assert_ne!(vote, propose);
        assert_ne!(vote, no_vote);
        assert_ne!(propose, no_vote);
    }
}
