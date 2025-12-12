use std::{collections::{HashMap, HashSet, BTreeMap}, sync::Arc};
use bincode::{deserialize, serialize};
use ed25519_dalek::{ed25519::signature, Keypair, PublicKey, Signature, Signer, Verifier};
use log::{error, info, warn, debug};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc::{self, Sender},
    time::{sleep, timeout, Duration, Instant}, // Added timeout
};
use shared::{domain::environment::Environment, transaction_generator::TransactionGenerator};
use crate::{
    consensus::dag::DAG,
    network::{broadcast::generate_nonce, message::{SparseMessage, VertexMessage, TimeoutMessage}},
    types::vertex::{NodeId, Vertex, VertexHash, TimeoutCertificate}, // Updated imports
};

const NONCE_BYTES_LENGTH: usize = 32;
const SIGNATURE_BYTES_LENGTH: usize = 64;
const MESSAGE_CHANNEL_SIZE: usize = 1024;
const SOCKET_BINDING_DELAY: u64 = 2;
const MESSAGE_BYTES_LENGTH: usize = 4;
const EXECUTION_DURATION: u64 = 120;

// SAILFISH CONSTANT: "Wait for leader until a timeout occurs"
const ROUND_TIMEOUT_MS: u128 = 2000; 

pub struct Sailfish {
    pub environment: Environment,
    pub dag: DAG,
    pub f: usize,
    pub public_keys: HashMap<NodeId, PublicKey>,
    transaction_generator: TransactionGenerator,
    private_key: Arc<Keypair>,
    
    // --- Sailfish Specific State ---
    round: u64,
    round_start_time: Instant, 
    timeout_sent: bool,        
    
    // Store timeout votes: Round -> { SenderID -> Signature }
    timeout_store: HashMap<u64, BTreeMap<NodeId, Vec<u8>>>, 
    
    // The TC we formed for the PREVIOUS round (round - 1).
    // Used to justify creating a vertex for the CURRENT round.
    current_round_tc: Option<TimeoutCertificate>,

    // --- Standard Fields ---
    pub last_ordered_round: u64,
    pub finalized_block_count: usize,
    pub pending_vertices : HashMap<u64, Vec<(NodeId, VertexMessage)>>,
    pub already_ordered: HashSet<VertexHash>,
    pub total_bytes_created: u64,
    pub echo_counts : HashMap<VertexHash, HashSet<NodeId>>,
    pub ready_counts : HashMap<VertexHash, HashSet<NodeId>>,
    pub delivered_vertices: HashSet<VertexHash>,
    pub pending_rbc_vertices: HashMap<VertexHash, Vertex>,
}

impl Sailfish {
    pub fn new(environment: Environment, public_keys: HashMap<NodeId, PublicKey>, private_key: Keypair) -> Self {
        let n = environment.nodes.len();
        let f = (n.saturating_sub(1)) / 3;
        let transaction_size = environment.transaction_size;
        let n_transactions = environment.n_transactions;
        
        let mut node = Sailfish {
            environment,
            dag: DAG::new(),
            f,
            public_keys,
            transaction_generator: TransactionGenerator::new(transaction_size, n_transactions),
            private_key: Arc::new(private_key),
            
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
            already_ordered : HashSet::new(),
            total_bytes_created: 0,
            echo_counts : HashMap::new(),
            ready_counts : HashMap::new(),
            delivered_vertices : HashSet::new(),
            pending_rbc_vertices : HashMap::new(),
        };
        node.add_genesis_block();
        node
    }

    // --- MAIN WORK LOOP ---
    async fn process_work_loop(&mut self, dispatcher_tx: &Sender<SparseMessage>){
        let mut progress = true;
        while progress {
            progress = false;

            // 1. Try to advance round 
            // Sailfish Rule: Must check Leader OR TC for (round-1)
            if self.may_advance_round(dispatcher_tx).await {
                progress = true;
                debug!("[Node {}] Advancing to round {}", self.environment.my_node.id, self.round + 1);
                
                // Create vertex for CURRENT round (using info from round-1)
                let new_vertex = self.create_new_vertex(self.round);
                let my_id = self.environment.my_node.id;
                
                self.dag.insert(new_vertex.clone());
                
                // Update State
                self.round += 1;
                self.round_start_time = Instant::now();
                self.timeout_sent = false;
                self.current_round_tc = None; 

                // Broadcast
                let vertex_message = SparseMessage::Vertex(VertexMessage {
                    sender: my_id,
                    vertex: new_vertex.clone(),
                });
                
                if dispatcher_tx.send(vertex_message).await.is_err() {
                    error!("Channel closed");
                }
                
                // Treat our own vertex as received via RBC
                self.handle_rbc_val(my_id, new_vertex.clone(), dispatcher_tx).await;
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
    async fn may_advance_round(&mut self, dispatcher_tx: &Sender<SparseMessage>) -> bool {
        if self.round == 1 { return true; } // Always advance from 0 to 1 (Genesis)

        let prev_round = self.round - 1;

        // 1. Quorum Parents check (Standard DAG Requirement)
        let parents_count = self.dag.get_round(prev_round).map_or(0, |v| v.len());
        let quorum = 2 * self.f + 1;
        
        if parents_count < quorum {
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

        // RED LIGHT: We are stuck waiting for leader of prev_round. Check if we should timeout.
        if !self.timeout_sent {
            let elapsed = self.round_start_time.elapsed().as_millis();
            if elapsed > ROUND_TIMEOUT_MS {
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
                let _ = dispatcher_tx.send(msg).await;
                self.timeout_sent = true;
            }
        }

        false
    }

    fn has_leader_vertex(&self, round: u64) -> bool {
        // Deterministic Leader: Round % N
        let leader_id = (round % self.environment.nodes.len() as u64) as u32;
        if let Some(round_vertices) = self.dag.get_round(round) {
            return round_vertices.iter().any(|v| v.source == leader_id);
        }
        false
    }

    async fn handle_timeout_vote(&mut self, sender: NodeId, round: u64, signature: Vec<u8>) {
        if round < self.round.saturating_sub(1) { return; } 

        let votes = self.timeout_store.entry(round).or_default();
        votes.insert(sender, signature);

        let quorum = 2 * self.f + 1;
        if votes.len() >= quorum {
            // We have enough votes to form a Certificate!
            // We only care if this is for the round we are currently stuck on (self.round - 1)
            if self.current_round_tc.is_none() && round == self.round.saturating_sub(1) {
                info!("[Node {}] Generated Timeout Certificate for Round {}!", self.environment.my_node.id, round);
                
                // Store the TC. 
                // The next call to 'may_advance_round' will see this and return true.
                self.current_round_tc = Some(TimeoutCertificate {
                    round,
                    signatures: votes.clone(),
                });
            }
        }
    }

    fn create_new_vertex(&mut self, round: u64) -> Vertex {
        let prev_round = round - 1;
        let candidates = self.dag.get_round(prev_round).cloned().unwrap_or_default();
        
        // Link to parents (Dense style - link to all visible)
        let mut edges: Vec<VertexHash> = candidates.iter().map(|v| v.hash.clone()).collect();

        // SAILFISH RULE:
        // "We require a round r vertex to either have a strong path to the round r-1 leader vertex OR include TC"
        let tc = if !self.has_leader_vertex(prev_round) {
            // This unwrap is safe because may_advance_round only lets us here if we have Leader OR TC.
            // If we don't have leader, we MUST have TC.
            self.current_round_tc.clone() 
        } else {
            None
        };

        let mut v = Vertex {
            hash: vec![],
            round,
            source: self.environment.my_node.id,
            block: bincode::serialize(&self.transaction_generator.generate()).expect("Block gen failed"),
            edges,
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
            // If they skipped the leader, they MUST have a TC
            if let Some(tc) = &v.tc {
                if tc.round != prev_round || tc.signatures.len() < quorum {
                    warn!("Invalid TC from Node {}", source);
                    return false;
                }
            } else {
                warn!("Invalid Vertex from Node {}: Skipped leader without TC", source);
                return false;
            }
        }

        if v.hash != v.calculate_hash() { return false; }
        true
    }

    // --- COMMIT LOGIC (Fast Path: 1 Round + 1 Delta) ---
    fn try_committing_sailfish(&mut self) {
        // Logic:
        // 1. Look at round R-1 (Potential Leader)
        // 2. Count children in round R that link to it
        // 3. If >= 2f+1 children, Commit Leader(R-1)
        
        let current_r = self.round.saturating_sub(1);
        if current_r <= self.last_ordered_round { return; }

        let leader_id = (current_r % self.environment.nodes.len() as u64) as u32;
        
        // Do we have the leader vertex?
        if let Some(round_v) = self.dag.get_round(current_r) {
            if let Some(leader) = round_v.iter().find(|v| v.source == leader_id) {
                
                // Do we have the voting round (current_r + 1)?
                if let Some(next_round_v) = self.dag.get_round(current_r + 1) {
                    let votes = next_round_v.iter()
                        .filter(|child| child.edges.contains(&leader.hash))
                        .count();
                    
                    // Commit Rule: 2f+1 votes
                    if votes >= 2 * self.f + 1 {
                        if !self.already_ordered.contains(&leader.hash) {
                            debug!("[Node {}] ⚓ Committing Leader Round {}", self.environment.my_node.id, current_r);
                            self.last_ordered_round = current_r;
                            self.finalized_block_count += 1;
                            self.already_ordered.insert(leader.hash.clone());
                            // Note: In full implementation, invoke ordering_bullshark logic here to order causal history
                        }
                    }
                }
            }
        }
    }

    // --- STANDARD BOILERPLATE (Network & RBC) ---
    
    pub async fn start(mut self) {
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
                    
                    match msg {
                        SparseMessage::Vertex(v) => self.handle_rbc_val(sender, v.vertex, &dispatcher_tx).await,
                        SparseMessage::RBC_Echo(e) => self.handle_rbc_echo(sender, e.vertex_hash, &dispatcher_tx).await,
                        SparseMessage::RBC_Ready(r) => self.handle_rbc_ready(sender, r.vertex_hash, &dispatcher_tx).await,
                        
                        // Handle Timeout Vote
                        SparseMessage::Timeout(t) => self.handle_timeout_vote(sender, t.round, t.signature).await,
                        
                        _ => {}
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
    
    async fn handle_new_vertex_message(&mut self, sender: NodeId, vm: VertexMessage, dispatcher_tx: &Sender<SparseMessage>) {
         if self.validate_vertex(&vm.vertex, vm.vertex.round, sender) {
            self.dag.insert(vm.vertex.clone());
            self.try_committing_sailfish();
         } else {
             // Buffer if it's from the future
             if vm.vertex.round >= self.round.saturating_sub(1) {
                 self.pending_vertices.entry(vm.vertex.round).or_default().push((sender, vm));
             }
         }
    }
    
    async fn handle_rbc_val(&mut self, sender: NodeId, vertex: Vertex, dispatcher_tx: &Sender<SparseMessage>) {
        let hash = vertex.hash.clone();
        if self.delivered_vertices.contains(&hash) { return; }
        if !self.pending_rbc_vertices.contains_key(&hash) {
            self.pending_rbc_vertices.insert(hash.clone(), vertex.clone());
            let echo = SparseMessage::RBC_Echo(crate::network::message::EchoMessage { vertex_hash: hash.clone() });
            self.broadcast(echo, dispatcher_tx).await;
            
            let ready_count = self.ready_counts.get(&hash).map(|s| s.len()).unwrap_or(0);
            if ready_count >= 2 * self.f + 1 {
                self.delivered_vertices.insert(hash.clone());
                self.pending_rbc_vertices.remove(&hash);
                self.handle_new_vertex_message(vertex.source, VertexMessage{sender: vertex.source, vertex}, dispatcher_tx).await;
            }
        }
    }
    
    async fn handle_rbc_echo(&mut self, s: NodeId, h: VertexHash, d: &Sender<SparseMessage>) {
        if self.delivered_vertices.contains(&h) { return; }
        let votes = self.echo_counts.entry(h.clone()).or_default();
        votes.insert(s);
        if votes.len() >= 2*self.f + 1 { self.try_send_ready(h, d).await; }
    }

    async fn handle_rbc_ready(&mut self, s: NodeId, h: VertexHash, d: &Sender<SparseMessage>) {
        // Fix: Scope the borrow of self.ready_counts
        let count = {
            let votes = self.ready_counts.entry(h.clone()).or_default();
            votes.insert(s);
            votes.len()
        };

        if count >= self.f + 1 { 
            self.try_send_ready(h.clone(), d).await; 
        }
        
        if count >= 2*self.f + 1 && !self.delivered_vertices.contains(&h) {
            if let Some(v) = self.pending_rbc_vertices.remove(&h) {
                self.delivered_vertices.insert(h.clone());
                self.handle_new_vertex_message(v.source, VertexMessage{sender: v.source, vertex: v}, d).await;
            }
        }
    }

    async fn try_send_ready(&mut self, h: VertexHash, d: &Sender<SparseMessage>) {
        let my_id = self.environment.my_node.id;
        let votes = self.ready_counts.entry(h.clone()).or_default();
        if !votes.contains(&my_id) {
            votes.insert(my_id);
            let msg = SparseMessage::RBC_Ready(crate::network::message::ReadyMessage{vertex_hash: h});
            self.broadcast(msg, d).await;
        }
    }

    async fn broadcast(&self, msg: SparseMessage, tx: &Sender<SparseMessage>) {
        let _ = tx.send(msg).await;
    }

    fn add_genesis_block(&mut self) {
        let genesis_vertex = Vertex {
            hash: vec![0; 32],
            round: 0,
            source: 0,
            block: vec![],
            edges: vec![],
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
                        let _ = stream.write_all(&my_id.to_be_bytes()).await;
                        let _ = stream.write_all(&nonce).await;
                        let _ = stream.write_all(signature.as_ref()).await;
                        return (target_id, Some(stream));
                    }
                    sleep(Duration::from_millis(500)).await;
                }
            });
            outgoing_tasks.push(task);
        }

        let mut accepted = 0;
        while accepted < n_nodes - 1 {
            if let Ok((mut stream, _)) = listener.accept().await {
                // Handshake logic omitted for brevity
                let mut id_buf = [0u8; 4];
                if stream.read_exact(&mut id_buf).await.is_ok() {
                    let claimed_id = u32::from_be_bytes(id_buf);
                    let msg_sender = message_sender.clone();
                    let pks = self.public_keys.clone();
                    let test_flag = self.environment.test_flag;
                    tokio::spawn(async move {
                        Self::handle_connection(stream, msg_sender, my_id, claimed_id, pks, test_flag).await;
                    });
                    accepted += 1;
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
        loop {
            let mut length_bytes = [0u8; MESSAGE_BYTES_LENGTH];
            if stream.read_exact(&mut length_bytes).await.is_err() { return; }
            let length = u32::from_be_bytes(length_bytes);
            if length == 0 || length > 10 * 1024 * 1024 { return; }
            
            let mut buffer = vec![0; length as usize];
            if stream.read_exact(&mut buffer).await.is_err() { return; }
            
            // Signature verification placeholder
            let mut sig_bytes = [0u8; 64];
            let _ = stream.read_exact(&mut sig_bytes).await; 

            if let Ok(message) = deserialize(&buffer) {
                if message_sender.send((peer_id, message)).await.is_err() { return; }
            }
        }
     }

    fn start_message_dispatcher(&self, mut dispatcher_receiver: mpsc::Receiver<SparseMessage>, mut connections: Vec<Option<TcpStream>>) {
        let private_key = self.private_key.clone();
        let test_flag = self.environment.test_flag;
        let mut peer_senders = Vec::new();

        for (id, stream_option) in connections.into_iter().enumerate() {
            if let Some(mut stream) = stream_option {
                let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1000);
                peer_senders.push(Some(tx));
                tokio::spawn(async move {
                    while let Some(data) = rx.recv().await {
                        if stream.write_all(&data).await.is_err() { break; }
                    }
                });
            } else {
                peer_senders.push(None);
            }
        }

        tokio::spawn(async move {
            while let Some(message) = dispatcher_receiver.recv().await {
                if let Ok(payload) = bincode::serialize(&message) {
                    let signature = if !test_flag { private_key.sign(&payload) } else { Signature::from_bytes(&[0u8; 64]).unwrap() };
                    let length_bytes = (payload.len() as u32).to_be_bytes();
                    let mut frame = Vec::with_capacity(4 + payload.len() + 64);
                    frame.extend_from_slice(&length_bytes);
                    frame.extend_from_slice(&payload);
                    frame.extend_from_slice(signature.as_ref());

                    for tx in peer_senders.iter() {
                        if let Some(sender) = tx { let _ = sender.send(frame.clone()).await; }
                    }
                }
            }
        });
    }

    fn print_dag_stats(&self) {
        println!("[Node {}] Final ordered round: {}", self.environment.my_node.id, self.last_ordered_round);
        println!("Blocks finalized: {}", self.finalized_block_count);
    }
}