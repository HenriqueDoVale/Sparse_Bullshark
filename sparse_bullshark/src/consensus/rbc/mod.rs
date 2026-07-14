//! Modular RBC layer — each variant (Bracha, Signed-Vote, ...) implements
//! the `ReliableBroadcast` trait and becomes an interchangeable plugin.
//!
//! Sailfish / Bullshark / SparseBullshark no longer interact with Bracha or
//! SignedVote directly: they hold a `Box<dyn ReliableBroadcast>` and
//! delegate all RBC messages to it, much like a Java interface injected
//! into a constructor.
pub mod bracha;
pub mod signed_vote;

use async_trait::async_trait;
use tokio::sync::mpsc::Sender;

use crate::{
    network::message::{RBCCommitMessage, RBCVoteMessage, ReadyMessage, SparseMessage},
    types::vertex::{NodeId, Vertex, VertexHash},
};

/// Abstraction over message broadcasting — necessary because the underlying
/// legacy protocols use two different channel signatures:
///   - Sailfish / PRBCSailfish: `Sender<(Option<NodeId>, SparseMessage)>`
///     (broadcast if None, unicast otherwise — used for the Byz1 attack simulation)
///   - Bullshark / SparseBullshark: `Sender<SparseMessage>` (pure broadcast)
///
/// No RBC handler (Bracha or SignedVote) requires unicast functionality;
/// therefore, this abstraction intentionally exposes a SINGLE method.
#[async_trait]
pub trait RbcBroadcaster: Send + Sync {
    async fn broadcast(&self, msg: SparseMessage);
}

/// Adapter for Sailfish / PRBCSailfish (tuple-based channel with routing).
pub struct TupleDispatcher<'a>(pub &'a Sender<(Option<NodeId>, SparseMessage)>);

#[async_trait]
impl<'a> RbcBroadcaster for TupleDispatcher<'a> {
    async fn broadcast(&self, msg: SparseMessage) {
        let _ = self.0.send((None, msg)).await;
    }
}

/// Adapter for Bullshark / SparseBullshark ("broadcast only" channel).
pub struct PlainDispatcher<'a>(pub &'a Sender<SparseMessage>);

#[async_trait]
impl<'a> RbcBroadcaster for PlainDispatcher<'a> {
    async fn broadcast(&self, msg: SparseMessage) {
        let _ = self.0.send(msg).await;
    }
}

/// The contract that every RBC implementation must satisfy.
///
/// Each method returns `Some(vertex)` precisely when RBC-delivery occurs
/// (allowing the caller to insert the vertex into the DAG), and `None` otherwise.
/// Unimplemented or irrelevant methods retain their default no-op behavior —
/// for instance, Bracha does not use `on_vote`/`on_commit`, while SignedVote
/// does not use `on_echo`/`on_ready`.
#[async_trait]
pub trait ReliableBroadcast: Send {
    /// Invoked both for our own proposal (sender == my_id) and
    /// for the VAL/Propose message received from a peer; this serves as a unified entry point.
    async fn on_val(
        &mut self,
        sender: NodeId,
        vertex: Vertex,
        out: &dyn RbcBroadcaster,
    ) -> Option<Vertex>;

    async fn on_echo(
        &mut self,
        _sender: NodeId,
        _hash: VertexHash,
        _out: &dyn RbcBroadcaster,
    ) -> Option<Vertex> {
        None
    }

    async fn on_ready(
        &mut self,
        _sender: NodeId,
        _msg: ReadyMessage,
        _out: &dyn RbcBroadcaster,
    ) -> Option<Vertex> {
        None
    }

    async fn on_vote(
        &mut self,
        _msg: RBCVoteMessage,
        _out: &dyn RbcBroadcaster,
    ) -> Option<Vertex> {
        None
    }

    async fn on_commit(
        &mut self,
        _msg: RBCCommitMessage,
        _out: &dyn RbcBroadcaster,
    ) -> Option<Vertex> {
        None
    }

    /// Used for logging/displaying statistics in print_dag_stats().
    fn name(&self) -> &'static str;
}