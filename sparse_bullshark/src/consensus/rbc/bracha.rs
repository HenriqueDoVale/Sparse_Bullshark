//! Bracha RBC — shared plugin for Sailfish, Bullshark, and SparseBullshark.
//!
//! Fusion of 3 nearly identical implementations found in sailfish.rs, bullshark.rs,
//! and sparse_bullshark.rs. The version from sailfish.rs was the most complete
//! (including Byz2 detection in on_ready) and was therefore retained. Consequently,
//! Bullshark and SparseBullshark inherit the Byz2 simulation (fake payload body). See the note "⚠️ BEHAVIOR CHANGE"
//! in the accompanying documentation.

use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use log::{debug, warn};
use shared::domain::node::NodeBehavior;

use crate::{
    network::message::{EchoMessage, ReadyMessage, SparseMessage},
    types::vertex::{NodeId, Vertex, VertexHash},
};

use super::{ReliableBroadcast, RbcBroadcaster};

pub struct BrachaRbc {
    my_id: NodeId,
    f: usize,
    behavior: NodeBehavior, // Used to simulate the Byz2 attack (fake body in READY)

    echo_counts: HashMap<VertexHash, HashSet<NodeId>>,
    ready_counts: HashMap<VertexHash, HashSet<NodeId>>,
    pending_vertices: HashMap<VertexHash, Vertex>,
    delivered: HashSet<VertexHash>,
}

impl BrachaRbc {
    pub fn new(my_id: NodeId, f: usize, behavior: NodeBehavior) -> Self {
        Self {
            my_id,
            f,
            behavior,
            echo_counts: HashMap::new(),
            ready_counts: HashMap::new(),
            pending_vertices: HashMap::new(),
            delivered: HashSet::new(),
        }
    }

    async fn try_send_ready(&mut self, hash: VertexHash, out: &dyn RbcBroadcaster) {
        let my_id = self.my_id;
        let votes = self.ready_counts.entry(hash.clone()).or_default();

        if !votes.contains(&my_id) {
            votes.insert(my_id);
            let body = if self.behavior == NodeBehavior::Byz2 {
                // Byz2: Include a fake body that will not match the hash —
                // receivers will detect this discrepancy (see on_ready below).
                self.pending_vertices.get(&hash).map(|real| {
                    let mut fake = real.clone();
                    fake.block = b"byz2_fake_payload".to_vec();
                    warn!(
                        "[Node {}] BYZ2: sending fake body in READY for hash {:?}",
                        my_id,
                        &hash[..4.min(hash.len())]
                    );
                    fake
                })
            } else {
                self.pending_vertices.get(&hash).cloned()
            };
            let ready_msg = SparseMessage::RBCReady(ReadyMessage {
                vertex_hash: hash,
                vertex: body,
            });
            out.broadcast(ready_msg).await;
        }
    }
}

#[async_trait]
impl ReliableBroadcast for BrachaRbc {
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

        // Stores the vertex body if not already present (might have arrived via READY before VAL).
        if !self.pending_vertices.contains_key(&hash) {
            self.pending_vertices.insert(hash.clone(), vertex.clone());
        }

        // Broadcasts ECHO exactly once per hash.
        let my_id = self.my_id;
        if !self.echo_counts.entry(hash.clone()).or_default().contains(&my_id) {
            self.echo_counts.get_mut(&hash).unwrap().insert(my_id);
            let echo_msg = SparseMessage::RBCEcho(EchoMessage {
                vertex_hash: hash.clone(),
            });
            out.broadcast(echo_msg).await;

            let ready_count = self.ready_counts.get(&hash).map(|s| s.len()).unwrap_or(0);
            let delivery_threshold = 2 * self.f + 1;

            if ready_count >= delivery_threshold {
                debug!(
                    "[Node {}] RBC LATE DELIVERY: Body arrived after consensus for round {}",
                    my_id, vertex.round
                );

                self.delivered.insert(hash.clone());
                self.echo_counts.remove(&hash);
                self.ready_counts.remove(&hash);
                self.pending_vertices.remove(&hash);

                return Some(vertex);
            }
        }
        None
    }

    async fn on_echo(
        &mut self,
        sender: NodeId,
        hash: VertexHash,
        out: &dyn RbcBroadcaster,
    ) -> Option<Vertex> {
        if self.delivered.contains(&hash) {
            return None;
        }

        let votes = self.echo_counts.entry(hash.clone()).or_default();
        votes.insert(sender);

        let threshold = 2 * self.f + 1;
        if votes.len() >= threshold {
            self.try_send_ready(hash, out).await;
        }
        None
    }

    async fn on_ready(
        &mut self,
        sender: NodeId,
        ready: ReadyMessage,
        out: &dyn RbcBroadcaster,
    ) -> Option<Vertex> {
        let hash = ready.vertex_hash.clone();

        // Stores the vertex body from READY if VAL was missed (fault tolerance mechanism).
        if let Some(vertex) = ready.vertex {
            if vertex.hash == hash {
                if !self.pending_vertices.contains_key(&hash) {
                    self.pending_vertices.insert(hash.clone(), vertex);
                }
            } else {
                warn!(
                    "[Node {}] BYZ2 DETECTED: READY from Node {} has body hash {:?} but claimed {:?}",
                    self.my_id,
                    sender,
                    &vertex.hash[..4.min(vertex.hash.len())],
                    &hash[..4.min(hash.len())]
                );
            }
        }

        let votes = self.ready_counts.entry(hash.clone()).or_default();
        votes.insert(sender);
        let ready_count = votes.len();

        if ready_count >= self.f + 1 {
            self.try_send_ready(hash.clone(), out).await;
        }

        let delivery_threshold = 2 * self.f + 1;
        if ready_count >= delivery_threshold && !self.delivered.contains(&hash) {
            if let Some(vertex) = self.pending_vertices.remove(&hash) {
                debug!(
                    "[Node {}] RBC DELIVERED vertex from Node {} in round {}",
                    self.my_id, vertex.source, vertex.round
                );
                self.echo_counts.remove(&hash);
                self.ready_counts.remove(&hash);
                self.delivered.insert(hash);
                return Some(vertex);
            } else {
                warn!(
                    "[Node {}] RBC ready to deliver but missing vertex body for hash {:?}",
                    self.my_id, hash
                );
            }
        }
        None
    }

    fn name(&self) -> &'static str {
        "Bracha"
    }
}