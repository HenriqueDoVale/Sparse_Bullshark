use std::{collections::{HashMap, HashSet, BTreeMap}, sync::Arc};
use bincode::{deserialize};
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
use log::{error, info, warn, debug};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc::{self, Sender},
    time::{sleep, timeout, Duration, Instant}, // Added timeout
};
use shared::{domain::{environment::Environment, node::NodeBehavior}, transaction_generator::TransactionGenerator};
use crate::{
    consensus::dag::DAG,
    consensus::rbc::{ReliableBroadcast, TupleDispatcher, bracha::BrachaRbc, signed_vote::SignedVoteRbc},
    network::{broadcast::generate_nonce, message::{
        SparseMessage, VertexMessage, TimeoutMessage,
    }},
    types::vertex::{NodeId, Vertex, VertexHash, TimeoutCertificate},
};

const NONCE_BYTES_LENGTH: usize = 32;
const SIGNATURE_BYTES_LENGTH: usize = 64;
const MESSAGE_CHANNEL_SIZE: usize = 1024;
const SOCKET_BINDING_DELAY: u64 = 2;
const MESSAGE_BYTES_LENGTH: usize = 4;
const EXECUTION_DURATION: u64 = 60;

// Dispatcher channel: None = broadcast to all; Some(id) = unicast to that peer.
type SailDispatch = (Option<NodeId>, SparseMessage);

pub struct Sailfish {
    pub environment: Environment,
    pub dag: DAG,
    pub f: usize,
    pub public_keys: HashMap<NodeId, PublicKey>,
    batch_receiver: Option<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    private_key: Arc<Keypair>,

    // Which RBC implementation is active (Bracha or Signed-Vote, chosen via
    // RBC_MODE at construction). All RBC-specific state now lives inside it.
    rbc: Box<dyn ReliableBroadcast>,

    // --- Sailfish Specific State ---
    round: u64,
    round_start_time: Instant,
    timeout_sent: bool,

    // Store timeout votes: Round -> { SenderID -> Signature }
    timeout_store: HashMap<u64, BTreeMap<NodeId, Vec<u8>>>,

    // The TC we formed for the PREVIOUS round (round - 1).
    current_round_tc: Option<TimeoutCertificate>,

    // --- Standard Fields ---
    pub last_ordered_round: u64,
    pub finalized_block_count: usize,
    pub pending_vertices: HashMap<u64, Vec<(NodeId, VertexMessage)>>,
    pub already_ordered: HashSet<VertexHash>,
    pub total_bytes_created: u64,

    // Latency tracking
    vertex_timestamps: HashMap<VertexHash, Instant>,
    total_commit_latency_us: u128,
    committed_vertex_count: u64,

    // Configurable round timeout (ms), read from ROUND_TIMEOUT_MS env var
    round_timeout_ms: u128,
}

impl Sailfish {
    pub fn new(environment: Environment, public_keys: HashMap<NodeId, PublicKey>, private_key: Keypair) -> Self {
        println!("Sailfish");
        let n = environment.nodes.len();
        let f = (n.saturating_sub(1)) / 3;
        let my_id = environment.my_node.id;
        let private_key = Arc::new(private_key);

        // Choice of the rbc plugin - Only place that still knows Bracha and Signed Vote 
        let rbc: Box<dyn ReliableBroadcast> = match std::env::var("RBC_MODE").as_deref() {
            Ok("signed_vote") => Box::new(SignedVoteRbc::new(
                my_id, f, private_key.clone(), public_keys.clone(),
            )),
            _ => Box::new(BrachaRbc::new(my_id, f, environment.my_node.behavior.clone())),
        };

        let mut node = Sailfish {
            environment,
            dag: DAG::new(),
            f,
            public_keys,
            batch_receiver: None,
            private_key,
            rbc,
            
            // Sailfish Init
            round: 1,
            round_start_time: Instant::now(),
            timeout_sent: false,
            timeout_store: HashMap::new(),
            current_round_tc: None,

            // Standard Init
            last_ordered_round: 0,
            finalized_block_count: 0,
            pending_vertices: HashMap::new(),
            already_ordered: HashSet::new(),
            total_bytes_created: 0,

            vertex_timestamps: HashMap::new(),
            total_commit_latency_us: 0,
            committed_vertex_count: 0,

            round_timeout_ms: std::env::var("ROUND_TIMEOUT_MS")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(500),
        };
        node.add_genesis_block();
        node
    }

    // --- MAIN WORK LOOP ---
    async fn process_work_loop(&mut self, dispatcher_tx: &Sender<SailDispatch>){
        let mut progress = true;
        while progress {
            progress = false;

            // 1. Try to advance round 
            // Sailfish Rule: Must check Leader OR TC for (round-1)
            if self.may_advance_round(dispatcher_tx).await {
                progress = true;
                let my_id = self.environment.my_node.id;

                if self.environment.my_node.behavior == NodeBehavior::Silent {
                    // Silent: advance round state but never create or send a vertex.
                    self.round += 1;
                    self.round_start_time = Instant::now();
                    self.timeout_sent = false;
                    self.current_round_tc = None;
                    warn!("[Node {}] SILENT: skipped vertex for round {}", my_id, self.round - 1);
                } else {
                    let block = self.next_batch().await;
                    let new_vertex = self.create_new_vertex(self.round, block);
                    self.vertex_timestamps.entry(new_vertex.hash.clone()).or_insert_with(Instant::now);
                    self.dag.insert(new_vertex.clone());
                    self.round += 1;
                    self.round_start_time = Instant::now();
                    self.timeout_sent = false;
                    self.current_round_tc = None;

                    if self.environment.my_node.behavior == NodeBehavior::Byz1 {
                        // Byz1: unicast VAL to only 2f+1 peers instead of broadcasting.
                        let quorum = 2 * self.f + 1;
                        let peers: Vec<NodeId> = self.environment.nodes.iter()
                            .map(|n| n.id)
                            .filter(|&id| id != my_id)
                            .take(quorum)
                            .collect();
                        warn!("[Node {}] BYZ1: sending VAL to only {}/{} peers",
                            my_id, peers.len(), self.environment.nodes.len() - 1);
                        for target in peers {
                            self.unicast(target, SparseMessage::Vertex(VertexMessage {
                                sender: my_id, vertex: new_vertex.clone(),
                            }), dispatcher_tx).await;
                        }
                    } else {
                        // Ok / Byz2: broadcast normally (byz2 attack fires later, inside BrachaRbc::try_send_ready).
                        let vertex_message = SparseMessage::Vertex(VertexMessage {
                            sender: my_id,
                            vertex: new_vertex.clone(),
                        });
                        if dispatcher_tx.send((None, vertex_message)).await.is_err() {
                            error!("Channel closed");
                        }
                    }

                    if let Some(vertex) = self.rbc.on_val(my_id, new_vertex.clone(), &TupleDispatcher(dispatcher_tx)).await {
                        self.handle_new_vertex_message(vertex.source, VertexMessage { sender: vertex.source, vertex }).await;
                    }
                }
            }

            // 2. Process Pending Vertices (Standard)
            let rounds_to_check: [u64; 2] = [self.round.saturating_sub(1), self.round];
            for r in &rounds_to_check {
                if let Some(pending) = self.pending_vertices.remove(r) {
                    let mut still_pending = Vec::new();
                    for (sender_id, vm) in pending {
                        // Attempt to validate now that we might have parents/TCs
                        if self.validate_vertex(&vm.vertex, vm.vertex.round, sender_id) {
                            progress = true;
                            debug!("[Node {}] Un-buffered vertex from Node {} in round {}", self.environment.my_node.id, sender_id, vm.vertex.round);
                            self.vertex_timestamps.entry(vm.vertex.hash.clone()).or_insert_with(Instant::now);
                            self.dag.insert(vm.vertex.clone());
                            self.try_committing_sailfish(); // Check commit rule
                        } else {
                            still_pending.push((sender_id, vm));
                        }
                    }
                    if !still_pending.is_empty() {
                        self.pending_vertices.insert(*r, still_pending);
                    }
                }
            }
        }
    }

    // --- SAILFISH CORE LOGIC ---

    // The "Traffic Light" of the protocol
    async fn may_advance_round(&mut self, dispatcher_tx: &Sender<SailDispatch>) -> bool {
        if self.round == 1 { return true; } // Always advance from 0 to 1 (Genesis)

        let prev_round = self.round - 1;

        // 1. Quorum Parents check (Standard DAG Requirement)
        let parents_count = self.dag.get_round(prev_round).map_or(0, |v| v.len());
        let quorum = 2 * self.f + 1;
        
        if parents_count < quorum {
            debug!("[Node {}] 🛑 STUCK Round {}: Need {} parents, have {}", 
        self.environment.my_node.id, self.round, quorum, parents_count);
            return false; 
        }

        // 2. Sailfish Check: Do we have the Leader of (round-1)?
        // "Waits to receive... round r-1 leader vertex"
        let has_leader = self.has_leader_vertex(prev_round);
        
        // 3. Sailfish Check: Do we have a Timeout Certificate for (round-1)?
        // "Upon receiving 2f+1 timeout messages... Pi can enter round r"
        let has_tc = self.current_round_tc.is_some();

        // GREEN LIGHT
        if has_leader || has_tc {
            return true;
        }
        debug!("[Node {}] 🚦 WAITING Round {}: HasLeader={}, HasTC={}. TimeoutSent={}", 
    self.environment.my_node.id, self.round, has_leader, has_tc, self.timeout_sent);
        // RED LIGHT: We are stuck waiting for leader of prev_round. Check if we should timeout.
        if !self.timeout_sent {
            let elapsed = self.round_start_time.elapsed().as_millis();
            if elapsed > self.round_timeout_ms {
                warn!("[Node {}] Timeout waiting for Leader in Round {}. Broadcasting TIMEOUT.", self.environment.my_node.id, prev_round);
                
                // Create Timeout Signature for prev_round
                let payload = prev_round.to_be_bytes();
                let signature = self.private_key.sign(&payload).to_bytes().to_vec();
                
                // Create Message
                let msg = SparseMessage::Timeout(TimeoutMessage {
                    round: prev_round,
                    signature: signature.clone(),
                });

                // Count our own vote
                self.handle_timeout_vote(self.environment.my_node.id, prev_round, signature).await;

                // Broadcast
                let _ = dispatcher_tx.send((None, msg)).await;
                self.timeout_sent = true;
            }
        }

        false
    }

    fn has_leader_vertex(&self, round: u64) -> bool {
        // Deterministic Leader: Round % N
        let leader_id = (round % self.environment.nodes.len() as u64) as u32;
        debug!("[Node {}] Checking for Leader {} in Round {}", self.environment.my_node.id, leader_id, round);
        if let Some(round_vertices) = self.dag.get_round(round) {
        let found = round_vertices.iter().any(|v| v.source == leader_id);
        if found {
            // ADD THIS:
            debug!("[Node {}] ✅ FOUND Leader {} for Round {}", self.environment.my_node.id, leader_id, round);
        }
        return found;
    }
    false
    }

    async fn handle_timeout_vote(&mut self, sender: NodeId, round: u64, signature: Vec<u8>) {
        if round < self.round.saturating_sub(1) { return; } 

        let votes = self.timeout_store.entry(round).or_default();
        votes.insert(sender, signature);
        let quorum = 2 * self.f + 1;
        debug!("[Node {}] 📩 TIMEOUT VOTE from {} for Round {}. Total: {}/{}", 
        self.environment.my_node.id, sender, round, votes.len(), quorum);

        if votes.len() >= quorum {
            // We have enough votes to form a Certificate!
            // We only care if this is for the round we are currently stuck on (self.round - 1)
            if self.current_round_tc.is_none() && round == self.round.saturating_sub(1) {
                debug!("[Node {}] Generated Timeout Certificate for Round {}!", self.environment.my_node.id, round);
                
                // Store the TC. 
                // The next call to 'may_advance_round' will see this and return true.
                self.current_round_tc = Some(TimeoutCertificate {
                    round,
                    signatures: votes.clone(),
                });
            }
        }
    }

    /// BFS from the strong-edge parents through all edges (strong + weak).
    /// Returns hashes of any DAG vertex at round < r-1 that is not reachable
    /// through that traversal — these become the weak edges of the new vertex.
    fn compute_weak_edges(&self, round: u64, strong_edges: &[VertexHash]) -> Vec<VertexHash> {
        use std::collections::VecDeque;
        let mut reachable: HashSet<VertexHash> = HashSet::new();
        let mut queue: VecDeque<VertexHash> = VecDeque::new();

        for h in strong_edges {
            if reachable.insert(h.clone()) {
                queue.push_back(h.clone());
            }
        }

        while let Some(h) = queue.pop_front() {
            if let Some(v) = self.dag.vertices.get(&h) {
                for ph in v.edges.iter().chain(v.weak_edges.iter()) {
                    if reachable.insert(ph.clone()) {
                        queue.push_back(ph.clone());
                    }
                }
            }
        }

        // Any vertex in the DAG at a round strictly older than r-1 that wasn't reached.
        let mut weak: Vec<VertexHash> = self.dag.vertices.values()
            .filter(|v| v.round > 0 && v.round + 1 < round && !reachable.contains(&v.hash))
            .map(|v| v.hash.clone())
            .collect();
        weak.sort(); // deterministic order (must match calculate_hash sort)
        weak
    }

    fn create_new_vertex(&mut self, round: u64, block: Vec<u8>) -> Vertex {
        let prev_round = round - 1;
        let candidates = self.dag.get_round(prev_round).cloned().unwrap_or_default();

        // Strong edges: all round-(r-1) vertices in the local DAG.
        let edges: Vec<VertexHash> = candidates.iter().map(|v| v.hash.clone()).collect();

        // Weak edges: vertices at rounds < r-1 not reachable through the strong chain.
        let weak_edges = if round > 1 { self.compute_weak_edges(round, &edges) } else { vec![] };

        // SAILFISH RULE: include TC when the previous-round leader is absent.
        let tc = if !self.has_leader_vertex(prev_round) {
            self.current_round_tc.clone()
        } else {
            None
        };

        let mut v = Vertex {
            hash: vec![],
            round,
            source: self.environment.my_node.id,
            block,
            edges,
            weak_edges,
            signed_round: vec![],
            sample_proof: vec![],
            tc,
            nvc: None,
        };
        v.hash = v.calculate_hash();
        
        if let Ok(bytes) = bincode::serialize(&v) {
            self.total_bytes_created += bytes.len() as u64;
        }
        v
    }

    fn validate_vertex(&self, v: &Vertex, round: u64, source: u32) -> bool {
        if v.round == 1 { return true; }
        if v.source != source || v.round != round { return false; }

        let prev_round = round - 1;
        let quorum = 2 * self.f + 1;

        // 1. Quorum Parents
        if v.edges.len() < quorum {
            return false;
        }

        // 2. PARENT EXISTENCE CHECK
        if let Some(parents) = self.dag.get_round(prev_round) {
            for edge in &v.edges {
                if !parents.iter().any(|p| p.hash == *edge) { return false; }
            }
        } else {
            return false; 
        }

        // 3. SAILFISH RULE: Link to Leader OR Valid TC
        let leader_id = (prev_round % self.environment.nodes.len() as u64) as u32;
        
        let links_leader = if let Some(parents) = self.dag.get_round(prev_round) {
            if let Some(leader_v) = parents.iter().find(|p| p.source == leader_id) {
                v.edges.contains(&leader_v.hash)
            } else {
                false // We locally don't have the leader
            }
        } else {
            false
        };

        if !links_leader {
            if let Some(tc) = &v.tc {
                if tc.round != prev_round || tc.signatures.len() < quorum {
                    // ADD THIS:
                    warn!("[Node {}] ❌ REJECTED from {}: Bad TC (Round {}, Sigs {})", 
                        self.environment.my_node.id, source, tc.round, tc.signatures.len());
                    return false;
                }
            } else {
                // ADD THIS:
                warn!("[Node {}] ❌ REJECTED from {}: Skipped Leader {} without TC!", 
                    self.environment.my_node.id, source, leader_id);
                return false;
            }
        }

        // 4. WEAK EDGE VALIDATION: each must be in the DAG at a round strictly < r-1.
        for weak_hash in &v.weak_edges {
            match self.dag.vertices.get(weak_hash) {
                Some(wv) if wv.round < prev_round => {}
                _ => return false,
            }
        }

        if v.hash != v.calculate_hash() { return false; }
        true
    }

    // --- COMMIT LOGIC (Fast Path: 1 Round + 1 Delta) ---
    // Replace your current try_committing_sailfish with this:
    fn try_committing_sailfish(&mut self) {
        let start_round = self.round.saturating_sub(1);
        let end_round = self.last_ordered_round;

        // Iterate FORWARD from the last ordered round
        for r in (end_round + 1)..=start_round {
            let leader_id = (r % self.environment.nodes.len() as u64) as u32;
            
            // 1. Find the Leader
            if let Some(round_vertices) = self.dag.get_round(r) {
                if let Some(leader) = round_vertices.iter().find(|v| v.source == leader_id) {
                    
                    // 2. Check for 2f+1 votes in the NEXT round
                    if let Some(next_round_vertices) = self.dag.get_round(r + 1) {
                        let votes = next_round_vertices.iter()
                            .filter(|child| child.edges.contains(&leader.hash))
                            .count();
                        
                        if votes >= 2 * self.f + 1 {
                            // 3. COMMIT THE CAUSAL HISTORY
                            if !self.already_ordered.contains(&leader.hash) {
                                // info!("[Node {}] ⚓ COMMIT Round {} Leader {}", self.environment.my_node.id, r, leader_id);

                                // Perform BFS to count ALL blocks this leader pulls in
                                let committed_count = self.commit_causal_history(leader.clone());

                                self.finalized_block_count += committed_count;
                                self.last_ordered_round = r;
                                self.dag.prune(self.last_ordered_round.saturating_sub(4));
                            }
                        } else {
                            // Not enough votes yet. Check if more can still arrive.
                            let r1_size = self.dag.get_round(r + 1).map_or(0, |v| v.len());
                            let n = self.environment.nodes.len();
                            let max_possible = votes + n.saturating_sub(r1_size);
                            if max_possible < 2 * self.f + 1 {
                                // Even if every missing node votes, threshold unreachable.
                                // Byzantine timing attack — skip this leader.
                                warn!("[Node {}] Skipping stuck leader at round {} (leader={}, votes={}/{}, r+1 DAG={}/{})",
                                    self.environment.my_node.id, r, leader_id, votes, 2 * self.f + 1, r1_size, n);
                                self.last_ordered_round = r;
                                self.dag.prune(self.last_ordered_round.saturating_sub(4));
                                // continue to next round
                            } else {
                                break; // More votes may still arrive
                            }
                        }
                    } else {
                        break; // Waiting for next round
                    }
                } else {
                    continue; // TC round — no leader vertex, skip this round's commit
                }
            } else {
                break;
            }
        }
    }

    // ✅ NEW HELPER FUNCTION: Traverses graph to count all blocks
    fn commit_causal_history(&mut self, leader: Vertex) -> usize {
        let mut stack = vec![leader];
        let mut count = 0;

        while let Some(v) = stack.pop() {
            if self.already_ordered.contains(&v.hash) {
                continue;
            }

            // Mark as ordered
            self.already_ordered.insert(v.hash.clone());
            count += 1;
            if let Some(ts) = self.vertex_timestamps.remove(&v.hash) {
                self.total_commit_latency_us += ts.elapsed().as_micros();
                self.committed_vertex_count += 1;
            }

            // Traverse both strong edges (round r-1) and weak edges (rounds < r-1).
            if v.round > 0 {
                for parent_hash in v.edges.iter().chain(v.weak_edges.iter()) {
                    if !self.already_ordered.contains(parent_hash) {
                        if let Some(parent) = self.dag.vertices.get(parent_hash) {
                            stack.push(parent.clone());
                        }
                    }
                }
            }
        }
        count
    }

    // --- STANDARD BOILERPLATE (Network & RBC) ---
    
    async fn next_batch(&mut self) -> Vec<u8> {
        if let Some(rx) = &mut self.batch_receiver {
            match rx.try_recv() {
                Ok(b) => return b,
                Err(_) => if let Some(b) = rx.recv().await { return b; },
            }
        }
        vec![]
    }

    pub async fn start(mut self) {
        // Spawn parallel transaction generator
        let tx_size    = self.environment.transaction_size;
        let n_tx       = self.environment.n_transactions;
        let n_nodes    = self.environment.nodes.len() as u64;
        let input_rate = self.environment.input_rate;
        let (batch_tx, batch_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
        self.batch_receiver = Some(batch_rx);

        tokio::spawn(async move {
            let mut gen = TransactionGenerator::new(tx_size, n_tx);
            if input_rate > 0 {
                let per_node_rate = input_rate / n_nodes;
                let interval_us = (n_tx as u64 * 1_000_000) / per_node_rate;
                let mut ticker = tokio::time::interval(Duration::from_micros(interval_us));
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    ticker.tick().await;
                    let batch = bincode::serialize(&gen.generate()).expect("batch serialize failed");
                    if batch_tx.send(batch).await.is_err() { break; }
                }
            } else {
                loop {
                    let batch = bincode::serialize(&gen.generate()).expect("batch serialize failed");
                    if batch_tx.send(batch).await.is_err() { break; }
                }
            }
        });

        let address = format!("{}:{}", self.environment.my_node.host, self.environment.my_node.port);
        let listener = TcpListener::bind(&address).await.expect("Failed to bind");
        let (message_tx, mut message_rx) = mpsc::channel(MESSAGE_CHANNEL_SIZE);
        let (dispatcher_tx, dispatcher_rx) = mpsc::channel(MESSAGE_CHANNEL_SIZE);

        sleep(Duration::from_secs(SOCKET_BINDING_DELAY)).await;
        let connections = self.connect(message_tx.clone(), &listener).await;
        self.start_message_dispatcher(dispatcher_rx, connections);

        let start_time = Instant::now();
        let duration = Duration::from_secs(EXECUTION_DURATION);

        // Initial Kick
        self.process_work_loop(&dispatcher_tx).await;

        loop {
            if start_time.elapsed() > duration { break; }

            // Wake up every 50ms to check for Timeouts even if no msg arrives
            let res = timeout(Duration::from_millis(50), message_rx.recv()).await;

            match res {
                Ok(Some((sender, msg))) => {
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                       // Clone if needed
                    }));
                    
                    let delivered = match msg {
                        SparseMessage::Vertex(v)    => self.rbc.on_val(sender, v.vertex, &TupleDispatcher(&dispatcher_tx)).await,
                        SparseMessage::RBCEcho(e)   => self.rbc.on_echo(sender, e.vertex_hash, &TupleDispatcher(&dispatcher_tx)).await,
                        SparseMessage::RBCReady(r)  => self.rbc.on_ready(sender, r, &TupleDispatcher(&dispatcher_tx)).await,
                        SparseMessage::RBCVote(v)   => self.rbc.on_vote(v, &TupleDispatcher(&dispatcher_tx)).await,
                        SparseMessage::RBCCommit(c) => self.rbc.on_commit(c, &TupleDispatcher(&dispatcher_tx)).await,
                        SparseMessage::Timeout(t)   => { self.handle_timeout_vote(sender, t.round, t.signature).await; None }
                        SparseMessage::Commit(_)    => None,
                    };
                    if let Some(vertex) = delivered {
                        self.handle_new_vertex_message(vertex.source, VertexMessage { sender: vertex.source, vertex }).await;
                    }
                },
                Ok(None) => break,
                Err(_) => {} // Timeout elapsed, just loop to check protocol timeout
            }
            
            self.process_work_loop(&dispatcher_tx).await;
        }
        
        self.print_dag_stats();
        std::process::exit(0);
    }

    // --- HELPERS (Copied from Bullshark/SparseBullshark) ---
    
    async fn handle_new_vertex_message(&mut self, sender: NodeId, vm: VertexMessage) {
         if self.validate_vertex(&vm.vertex, vm.vertex.round, sender) {
            self.vertex_timestamps.entry(vm.vertex.hash.clone()).or_insert_with(Instant::now);
            self.dag.insert(vm.vertex.clone());
            self.try_committing_sailfish();
         } else {
             // Buffer if it's from the future
             if vm.vertex.round >= self.round.saturating_sub(1) {
                 self.pending_vertices.entry(vm.vertex.round).or_default().push((sender, vm));
             }
         }
    }
    

    async fn unicast(&self, target: NodeId, msg: SparseMessage, dispatcher_tx: &Sender<SailDispatch>){
        if let Err(_) = dispatcher_tx.send((Some(target), msg)).await{
           error!("[Node {}] Failed to unicast to {}: channel closed", self.environment.my_node.id, target);
        }
    }

    fn add_genesis_block(&mut self) {
        let genesis_vertex = Vertex {
            hash: vec![0; 32],
            round: 0,
            source: 0,
            block: vec![],
            edges: vec![],
            weak_edges: vec![],
            signed_round: vec![],
            sample_proof: vec![],
            tc: None,
            nvc: None,
        };
        self.dag.insert(genesis_vertex);
    }
    
    // Connection helpers (Standard)
    async fn connect(&self, message_sender: Sender<(NodeId, SparseMessage)>, listener: &TcpListener) -> Vec<Option<TcpStream>> {
        let n_nodes = self.environment.nodes.len();
        let my_id = self.environment.my_node.id;
        
        let mut connections = Vec::with_capacity(n_nodes);
        for _ in 0..n_nodes { connections.push(None); }

        // 1. OUTGOING Connections (Background Retry Loop)
        let mut outgoing_tasks = Vec::new();
        for node in &self.environment.nodes {
            if node.id == my_id { continue; }
            let target_id = node.id;
            let address = format!("{}:{}", node.host, node.port);
            let my_id = my_id;
            let private_key = self.private_key.clone();

            let task = tokio::spawn(async move {
                loop {
                    if let Ok(mut stream) = TcpStream::connect(&address).await {
                        let nonce = generate_nonce();
                        let signature = private_key.sign(&nonce);
                        
                        if stream.write_all(&my_id.to_be_bytes()).await.is_err() { 
                            sleep(Duration::from_millis(500)).await; continue; 
                        }
                        if stream.write_all(&nonce).await.is_err() { 
                            sleep(Duration::from_millis(500)).await; continue; 
                        }
                        if stream.write_all(signature.as_ref()).await.is_err() { 
                            sleep(Duration::from_millis(500)).await; continue; 
                        }
                        return (target_id, Some(stream));
                    }
                    sleep(Duration::from_millis(500)).await;
                }
            });
            outgoing_tasks.push(task);
        }

        // 2. INCOMING Connections (Main Thread)
        let mut accepted = 0;
        let expected_peers = n_nodes - 1;
        info!("[Node {}] Waiting for {} connections...", my_id, expected_peers);

        while accepted < expected_peers {
            if let Ok((mut stream, addr)) = listener.accept().await {
                let mut id_buf = [0u8; 4];
                if stream.read_exact(&mut id_buf).await.is_err() { 
                    warn!("[Node {}] Handshake failed: could not read ID from {}. Dropping.", my_id, addr);
                    continue; 
                }
                let claimed_id = u32::from_be_bytes(id_buf);
                
                let mut nonce = vec![0u8; NONCE_BYTES_LENGTH];
                if stream.read_exact(&mut nonce).await.is_err() { 
                    warn!("[Node {}] Handshake failed: could not read nonce from Node {}. Dropping.", my_id, claimed_id);
                    continue; 
                }
                let mut sig_bytes = vec![0u8; SIGNATURE_BYTES_LENGTH];
                if stream.read_exact(&mut sig_bytes).await.is_err() { 
                    warn!("[Node {}] Handshake failed: could not read signature from Node {}. Dropping.", my_id, claimed_id);
                    continue; 
                }

                if let Some(key) = self.public_keys.get(&claimed_id) {
                    if let Ok(signature) = Signature::from_bytes(&sig_bytes) {
                        if key.verify(&nonce, &signature).is_ok() {
                            let msg_sender = message_sender.clone();
                            let pks = self.public_keys.clone();
                            let my_id = self.environment.my_node.id;
                            let test_flag = self.environment.test_flag;
                            tokio::spawn(async move {
                                Self::handle_connection(stream, msg_sender, my_id, claimed_id, pks, test_flag).await;
                            });
                            accepted += 1;
                            info!("[Node {}] Accepted connection from Node {} ({}/{})", my_id, claimed_id, accepted, expected_peers);
                        } else {
                            warn!("[Node {}] Handshake failed: INVALID SIGNATURE from Node {}. Dropping.", my_id, claimed_id);
                        }
                    } else {
                        warn!("[Node {}] Handshake failed: Malformed signature bytes from Node {}.", my_id, claimed_id);
                    }
                } else {
                    warn!("[Node {}] Handshake failed: Unknown Node ID {} (Not in public keys). Dropping.", my_id, claimed_id);
                }
            }
        }

        for task in outgoing_tasks {
            let (id, stream) = task.await.unwrap();
            connections[id as usize] = stream;
        }
        connections
    }

    async fn handle_connection(mut stream: TcpStream, 
        message_sender: Sender<(NodeId, SparseMessage)>, 
        my_id: NodeId, peer_id: NodeId, 
        public_keys: HashMap<NodeId, PublicKey>, 
        test_flag: bool
    ) {
        info!("[Node {}] Listening for messages from Node {}", my_id, peer_id);
        loop {
            let mut length_bytes = [0u8; MESSAGE_BYTES_LENGTH];
            if stream.read_exact(&mut length_bytes).await.is_err() {
                error!("[Node {}] Connection dropped by Node {}", my_id, peer_id);
                return;
            }
            let length = u32::from_be_bytes(length_bytes);
            if length == 0 || length > 10 * 1024 * 1024 { return; }
            let mut buffer = vec![0; length as usize];
            if stream.read_exact(&mut buffer).await.is_err() { return; }
            let mut verified = test_flag;
            let mut sig_bytes = [0u8; 64];
            if stream.read_exact(&mut sig_bytes).await.is_err() { return; }
            if !test_flag {
                if let Some(pubkey) = public_keys.get(&peer_id){
                    if let Ok(sig) = Signature::from_bytes(&sig_bytes) {
                        if pubkey.verify(&buffer, &sig).is_ok() {
                            verified = true;
                        }
                    }
                }
            }
            if verified {
                if let Ok(message) = deserialize(&buffer) {
                    if message_sender.send((peer_id, message)).await.is_err() {
                        return;
                    }
                }
            }
        }
     }


     // ✅ UPDATED: Parallel Sender
    fn start_message_dispatcher(&self, mut dispatcher_receiver: mpsc::Receiver<SailDispatch>, connections: Vec<Option<TcpStream>>) {
        let private_key = self.private_key.clone();
        let test_flag = self.environment.test_flag;

        // 1. Create a channel for each active connection
        let mut peer_senders = Vec::new();

        for (_id, stream_option) in connections.into_iter().enumerate() {
            if let Some(mut stream) = stream_option {
                let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1000);
                peer_senders.push(Some(tx));

                tokio::spawn(async move {
                    while let Some(data) = rx.recv().await {
                        if stream.write_all(&data).await.is_err() {
                            break; 
                        }
                    }
                });
            } else {
                peer_senders.push(None);
            }
        }

        // 2. Main Dispatcher Loop
        tokio::spawn(async move {
            while let Some((target, message)) = dispatcher_receiver.recv().await {
                if let Ok(payload) = bincode::serialize(&message) {

                    let signature = if !test_flag {
                        private_key.sign(&payload)
                    } else {
                        Signature::from_bytes(&[0u8; 64]).unwrap()
                    };

                    let length_bytes = (payload.len() as u32).to_be_bytes();

                    let mut frame = Vec::with_capacity(4 + payload.len() + 64);
                    frame.extend_from_slice(&length_bytes);
                    frame.extend_from_slice(&payload);
                    frame.extend_from_slice(signature.as_ref());

                    match target {
                        None => {
                            // Broadcast to all peers
                            for tx in peer_senders.iter() {
                                if let Some(sender) = tx {
                                    let _ = sender.send(frame.clone()).await;
                                }
                            }
                        }
                        Some(peer_id) => {
                            // Unicast to specific peer
                            if let Some(Some(tx)) = peer_senders.get(peer_id as usize) {
                                let _ = tx.send(frame.clone()).await;
                            }
                        }
                    }
                }
            }
        });
    }

    fn print_dag_stats(&self) {
        let n             = self.environment.nodes.len();
        let f_tolerance   = self.f;
        let f_actual      = self.environment.nodes.iter()
                                .filter(|node| node.behavior != NodeBehavior::Ok)
                                .count();
        let tx_size    = self.environment.transaction_size;
        let n_tx       = self.environment.n_transactions;
        let exec_secs  = EXECUTION_DURATION as f64;

        let total_tx    = self.finalized_block_count * n_tx;
        let total_bytes = total_tx * tx_size;
        let tps         = total_tx as f64 / exec_secs;
        let bps         = total_bytes as f64 / exec_secs;
        let rps         = self.last_ordered_round as f64 / exec_secs;

        let input_rate = self.environment.input_rate;
        let rate_label = if input_rate == 0 {
            "unlimited".to_string()
        } else {
            format!("{} tx/s", input_rate)
        };

        let rbc_label = self.rbc.name();

        println!("\n+ CONFIG:");
        println!("  Protocol:             Sailfish ({} RBC)", rbc_label);
        println!("  Faults:               {} node(s)", f_actual);
        println!("  Fault tolerance:      {} node(s)", f_tolerance);
        println!("  Committee size:       {} node(s)", n);
        println!("  Input rate:           {}", rate_label);
        println!("  Transaction size:     {} B", tx_size);
        println!("  Transactions/block:   {}", n_tx);
        println!("  Block size:           {} B", n_tx * tx_size);
        println!("  Execution time:       {} s", EXECUTION_DURATION);
        let avg_latency_ms = if self.committed_vertex_count > 0 {
            (self.total_commit_latency_us as f64 / self.committed_vertex_count as f64) / 1000.0
        } else { 0.0 };

        println!("\n+ RESULTS:");
        println!("  Ordered rounds:       {}", self.last_ordered_round);
        println!("  Blocks finalized:     {}", self.finalized_block_count);
        println!("  Rounds/s:             {:.1}", rps);
        println!("  Consensus TPS:        {:.0} tx/s", tps);
        println!("  Consensus BPS:        {:.0} B/s", bps);
        println!("  Consensus latency:    {:.1} ms", avg_latency_ms);
    }
}