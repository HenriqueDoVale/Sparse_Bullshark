//! Signed-Vote RBC — currently used only by Sailfish
//! (RBC_MODE=signed_vote), but now fully decoupled and reusable as-is by
//! Bullshark/SparseBullshark if needed in the future.

use std::{collections::HashMap, collections::HashSet, collections::BTreeMap, sync::Arc};

use async_trait::async_trait;
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
use log::{debug, warn};

use crate::{
    network::message::{RBCCommitMessage, RBCVoteMessage, SparseMessage},
    types::vertex::{NodeId, Vertex, VertexHash},
};

use super::{ReliableBroadcast, RbcBroadcaster};

pub struct SignedVoteRbc {
    my_id: NodeId,
    f: usize,
    private_key: Arc<Keypair>,
    public_keys: HashMap<NodeId, PublicKey>,

    votes: HashMap<VertexHash, BTreeMap<NodeId, Vec<u8>>>, // maps voter → signature
    vertex_store: HashMap<VertexHash, Vertex>,              // vertex body from Propose or Vote
    commit_sent: HashSet<VertexHash>,                        // deduplication: strictly one Commit per hash
    delivered: HashSet<VertexHash>,
}

impl SignedVoteRbc {
    pub fn new(
        my_id: NodeId,
        f: usize,
        private_key: Arc<Keypair>,
        public_keys: HashMap<NodeId, PublicKey>,
    ) -> Self {
        Self {
            my_id,
            f,
            private_key,
            public_keys,
            votes: HashMap::new(),
            vertex_store: HashMap::new(),
            commit_sent: HashSet::new(),
            delivered: HashSet::new(),
        }
    }

    /// Common delivery path, shared by both the Vote and Commit execution flows.
    fn deliver(&mut self, vertex: Vertex) -> Option<Vertex> {
        let hash = vertex.hash.clone();
        if self.delivered.contains(&hash) {
            return None;
        }
        self.delivered.insert(hash.clone());
        self.votes.remove(&hash);
        self.vertex_store.remove(&hash);

        debug!(
            "[Node {}] SV: delivered vertex from {} round {}",
            self.my_id, vertex.source, vertex.round
        );
        Some(vertex)
    }

    /// Once the Byzantine quorum (2f+1 votes) is gathered, delivers the vertex 
    /// and broadcasts a Commit certificate.
    async fn check_threshold(&mut self, hash: VertexHash, out: &dyn RbcBroadcaster) -> Option<Vertex> {
        let threshold = 2 * self.f + 1;

        let vote_count = self.votes.get(&hash).map(|m| m.len()).unwrap_or(0);
        if vote_count < threshold || self.delivered.contains(&hash) {
            return None;
        }

        if let Some(vertex) = self.vertex_store.get(&hash).cloned() {
            // Broadcasts the Commit certificate BEFORE calling deliver(), because 
            // deliver() clears the votes and vertex_store for this specific hash.
            if !self.commit_sent.contains(&hash) {
                self.commit_sent.insert(hash.clone());
                let votes = self.votes.get(&hash).cloned().unwrap_or_default();
                let commit_msg = SparseMessage::RBCCommit(RBCCommitMessage {
                    vertex: vertex.clone(),
                    votes,
                });
                out.broadcast(commit_msg).await;
            }
            self.deliver(vertex)
        } else {
            // Quorum threshold reached but the vertex payload is not yet available locally.
            // Delivery will occur upon the next incoming Vote/Commit that provides the body.
            debug!(
                "[Node {}] SV: threshold reached but body not yet available for hash {:?}",
                self.my_id,
                &hash[..4.min(hash.len())]
            );
            None
        }
    }
}

#[async_trait]
impl ReliableBroadcast for SignedVoteRbc {
    /// The leader sends a Propose (reusing the Vertex message). Upon receipt:
    /// stores the payload body, signs the hash, and broadcasts a Vote carrying the full body.
    async fn on_val(
        &mut self,
        _sender: NodeId,
        vertex: Vertex,
        out: &dyn RbcBroadcaster,
    ) -> Option<Vertex> {
        let hash = vertex.hash.clone();
        if self.delivered.contains(&hash) {
            return None;
        }

        // Stores the body (first come, first served logic — via Propose or any Vote).
        self.vertex_store.entry(hash.clone()).or_insert_with(|| vertex.clone());

        let my_id = self.my_id;
        let signature = self.private_key.sign(&hash).to_bytes().to_vec();

        let vote_msg = SparseMessage::RBCVote(RBCVoteMessage {
            vertex: vertex.clone(),
            voter: my_id,
            signature: signature.clone(),
        });
        out.broadcast(vote_msg).await;

        // Records our own vote.
        self.votes.entry(hash.clone()).or_default().insert(my_id, signature);
        self.check_threshold(hash, out).await
    }

    /// Invoked for each incoming Vote (including those relayed by peers).
    async fn on_vote(&mut self, msg: RBCVoteMessage, out: &dyn RbcBroadcaster) -> Option<Vertex> {
        let hash = msg.vertex.hash.clone();
        if self.delivered.contains(&hash) {
            return None;
        }

        // Cryptographic verification: ensures the voter signed the vertex hash with their private key.
        match self.public_keys.get(&msg.voter) {
            Some(pk) => match Signature::from_bytes(&msg.signature) {
                Ok(sig) => {
                    if pk.verify(&hash, &sig).is_err() {
                        warn!("[Node {}] SV: invalid vote signature from node {}", self.my_id, msg.voter);
                        return None;
                    }
                }
                Err(_) => {
                    warn!("[Node {}] SV: malformed signature from node {}", self.my_id, msg.voter);
                    return None;
                }
            },
            None => {
                warn!("[Node {}] SV: unknown voter {}", self.my_id, msg.voter);
                return None;
            }
        }

        // Stores the payload body if not already held (mitigates Byzantine leaders skipping the Propose phase).
        self.vertex_store.entry(hash.clone()).or_insert_with(|| msg.vertex.clone());
        self.votes.entry(hash.clone()).or_default().insert(msg.voter, msg.signature);

        self.check_threshold(hash, out).await
    }

    /// Incoming Commit certificate: verifies 2f+1 valid signatures, then processes delivery.
    async fn on_commit(&mut self, msg: RBCCommitMessage, _out: &dyn RbcBroadcaster) -> Option<Vertex> {
        let hash = msg.vertex.hash.clone();
        if self.delivered.contains(&hash) {
            return None;
        }

        let threshold = 2 * self.f + 1;
        if msg.votes.len() < threshold {
            warn!(
                "[Node {}] SV: Commit certificate for {:?} has only {} votes (need {})",
                self.my_id, &hash[..4.min(hash.len())], msg.votes.len(), threshold
            );
            return None;
        }

        let mut valid = 0usize;
        for (voter, sig_bytes) in &msg.votes {
            if let Some(pk) = self.public_keys.get(voter) {
                if let Ok(sig) = Signature::from_bytes(sig_bytes) {
                    if pk.verify(&hash, &sig).is_ok() {
                        valid += 1;
                    }
                }
            }
        }
        if valid < threshold {
            warn!(
                "[Node {}] SV: Commit certificate only had {}/{} valid sigs",
                self.my_id, valid, threshold
            );
            return None;
        }

        self.vertex_store.entry(hash.clone()).or_insert_with(|| msg.vertex.clone());
        self.deliver(msg.vertex)
    }

    fn name(&self) -> &'static str {
        "Signed-Vote"
    }
}