use std::{collections::HashMap, collections::HashSet, sync::Arc};
use bincode::{deserialize, serialize};
use ed25519_dalek::{ed25519::signature, Keypair, PublicKey, Signature, Signer, Verifier};
use log::{error, info, warn};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc::{self, Sender},
    time::{sleep, Duration, Instant},
};
use shared::{domain::environment::Environment, transaction_generator::TransactionGenerator};
use crate::{
    consensus::dag::DAG,
    crypto::multisig::*,
    network::{broadcast::generate_nonce, message::{SparseMessage, VertexMessage}},
    types::vertex::{NodeId, Vertex, VertexHash},
    utils::random::random_sample,
};

const NONCE_BYTES_LENGTH: usize = 32;
const SIGNATURE_BYTES_LENGTH: usize = 64;
const MESSAGE_CHANNEL_SIZE: usize = 1024;
const SOCKET_BINDING_DELAY: u64 = 2;
const MESSAGE_BYTES_LENGTH: usize = 4;
const EXECUTION_DURATION: u64 = 120;

pub struct SparseBullshark {
    pub environment: Environment,
    pub dag: DAG,
    pub f: usize,
    pub d: usize,
    pub public_keys: HashMap<NodeId, PublicKey>,
    transaction_generator: TransactionGenerator,
    private_key: Arc<Keypair>,
    round: u64,
    pub last_ordered_round: u64,
    pub ordered_anchors_stack: Vec<Vertex>,
    pub finalized_block_count: usize,
    pub pending_vertices : HashMap<u64, Vec<(NodeId, VertexMessage)>>,
    pub already_ordered: HashSet<VertexHash>,
    pub total_bytes_created: u64,
}

impl SparseBullshark {
    pub fn new(environment: Environment, public_keys: HashMap<NodeId, PublicKey>, private_key: Keypair) -> Self {
        let n = environment.nodes.len();
        let f = (n.saturating_sub(1)) / 3;
        let d = 4; //sparse number
        let transaction_size = environment.transaction_size;
        let n_transactions = environment.n_transactions;
        let mut node = SparseBullshark {
            environment,
            dag: DAG::new(),
            f,
            d,
            public_keys,
            transaction_generator: TransactionGenerator::new(
            transaction_size,
            n_transactions,
            ),
            private_key: Arc::new(private_key),
            round: 1,
            last_ordered_round: 0,
            ordered_anchors_stack: Vec::new(),
            finalized_block_count: 0,
            pending_vertices: HashMap::new(),
            already_ordered : HashSet::new(),
            total_bytes_created: 0,
            
        };
        node.add_genesis_block();
        node
    }

    async fn process_work_loop(&mut self, dispatcher_tx: &Sender<SparseMessage>){
        let mut progress = true;
        while progress {
            progress = false;

            // --- 1. Try to advance the round ---
            if self.may_advance_round() {
                progress = true; // We are making progress
                info!("[Node {}] Advancing to round {}", self.environment.my_node.id, self.round);
                let new_vertex = self.create_new_vertex(self.round);
                let my_id = self.environment.my_node.id;
                
                self.dag.insert(new_vertex.clone());
                self.round += 1;
                
                let vertex_message = SparseMessage::Vertex(VertexMessage {
                    sender: my_id,
                    vertex: new_vertex.clone(),
                });
                
                if dispatcher_tx.send(vertex_message).await.is_err() {
                    error!("[Node {}] Failed to send vertex to dispatcher.", self.environment.my_node.id);
                }
                
                // Since we just created a vertex, try committing it (for anchors)
                self.try_committing(new_vertex);
            }

            // --- 2. Try to process pending vertices ---
            // We check the *previous* round (which we may have just completed)
            // and the *current* round (which we may have just received vertices for).
            let rounds_to_check: [u64; 2] = [self.round.saturating_sub(1), self.round];

            for r in &rounds_to_check {
                if let Some(pending) = self.pending_vertices.remove(r) {
                    let mut still_pending = Vec::new();
                    for (sender_id, vm) in pending {
                        if self.validate_vertex(&vm.vertex, vm.vertex.round, sender_id) {
                            progress = true; // We are making progress
                            info!("[Node {}] Pending vertex from Node {} in round {} is now VALID", self.environment.my_node.id, sender_id, vm.vertex.round);
                            self.dag.insert(vm.vertex.clone());
                            self.try_committing(vm.vertex.clone());
                        } else {
                            // Still not valid, put it back
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

    fn add_genesis_block(&mut self) {
        let genesis_vertex = Vertex {
            hash: vec![0; 32],
            round: 0,
            source: 0,
            block: vec![],
            edges: vec![],
            signed_round: vec![],
            sample_proof: vec![],
        };
        self.dag.insert(genesis_vertex);
    }

    pub async fn start(mut self) {
        let address = format!("{}:{}", self.environment.my_node.host, self.environment.my_node.port);
        let listener = TcpListener::bind(&address).await.expect("Failed to bind local port");

        info!("[Node {}] Listening on {}", self.environment.my_node.id, &address);
        let (message_tx, mut message_rx) = mpsc::channel(MESSAGE_CHANNEL_SIZE);
        let (dispatcher_tx, dispatcher_rx) = mpsc::channel(MESSAGE_CHANNEL_SIZE);

        info!("[Node {}] Waiting for all nodes to connect...", self.environment.my_node.id);
        sleep(Duration::from_secs(SOCKET_BINDING_DELAY)).await;

        let connections = self.connect(message_tx.clone(), &listener).await;
        info!("[Node {}] All nodes connected. Starting protocol.", self.environment.my_node.id);

        self.start_message_dispatcher(dispatcher_rx, connections);

        let execution_duration = Duration::from_secs(EXECUTION_DURATION);
        let start_time = Instant::now();
        
        // --- START OF CORRECTIONS ---

        self.process_work_loop(&dispatcher_tx).await;

        // Now we start the main loop, listening for messages from peers.
        while start_time.elapsed() < execution_duration {
            if let Some((sender_id, message)) = message_rx.recv().await {
                
                // CATCH PANIC: This check is still good.
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    match message {
                        SparseMessage::Vertex(vm) => {
                            // We will process this vertex
                            return Some((sender_id, vm));
                        },
                        SparseMessage::Commit(_) => {}
                    }
                    None
                }));

                if result.is_err() {
                     error!("[Node {}] FATAL: PANIC during message validation from Node {}. This is the bug.", self.environment.my_node.id, sender_id);
                     continue;
                }

                if let Ok(Some((s_id, vm))) = result {
                     // ✅ PROCESS: Handle the vertex and trigger the work loop
                    self.handle_new_vertex_message(s_id, vm, &dispatcher_tx).await;
                }

            } else {
                // Channel is closed, which means the simulation is ending.
                break;
            }
        }
        
        // --- END OF CORRECTIONS ---

        info!("[Node {}] Execution finished after {} seconds.", self.environment.my_node.id, start_time.elapsed().as_secs());
        // You can add logic here to print final statistics, e.g., total blocks ordered.
        self.print_dag_stats();
        println!("[Node {}] Final ordered round: {}", self.environment.my_node.id, self.last_ordered_round);
        println!("Blocks finalized: {}", self.finalized_block_count);
        print!("Total data created: {} MB", self.total_bytes_created/(1024*1024));
        // Allow some time for final messages to flush
        tokio::time::sleep(Duration::from_secs(2)).await;
        
        // Explicitly exit the process
        std::process::exit(0);
    }

    async fn connect(&self, message_sender: Sender<(NodeId, SparseMessage)>, listener: &TcpListener) -> Vec<Option<TcpStream>> {
        let mut connections = Vec::with_capacity(self.environment.nodes.len());
        for _ in 0..self.environment.nodes.len() {
            connections.push(None);
        }

        for node in &self.environment.nodes {
            if node.id == self.environment.my_node.id {
                continue;
            }
            let address = format!("{}:{}", node.host, node.port);
            if let Ok(mut stream) = TcpStream::connect(&address).await {
                let nonce = generate_nonce();
                let signature = self.private_key.sign(&nonce);
                stream.write_all(&self.environment.my_node.id.to_be_bytes()).await.unwrap();
                stream.write_all(&nonce).await.unwrap();
                stream.write_all(signature.as_ref()).await.unwrap();
                stream.flush().await.unwrap();
                connections[node.id as usize] = Some(stream);
            }
        }

        let mut accepted = 0;
        while accepted < self.environment.nodes.len() - 1 {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut id_buf = [0u8; 4];
                if stream.read_exact(&mut id_buf).await.is_err() { continue; }
                let claimed_id = u32::from_be_bytes(id_buf);
                let mut nonce = vec![0u8; NONCE_BYTES_LENGTH];
                if stream.read_exact(&mut nonce).await.is_err() { continue; }
                let mut sig_bytes = vec![0u8; SIGNATURE_BYTES_LENGTH];
                if stream.read_exact(&mut sig_bytes).await.is_err() { continue; }

                if let Some(key) = self.public_keys.get(&claimed_id) {
                    if let Ok(signature) = Signature::from_bytes(&sig_bytes) {
                        if key.verify(&nonce, &signature).is_ok() {
                            let msg_sender = message_sender.clone();
                            let pks = self.public_keys.clone();
                            let my_id = self.environment.my_node.id;
                            let test_flag = self.environment.test_flag;
                            tokio::spawn(async move {
                                Self::handle_connection(stream, msg_sender, my_id, claimed_id, pks,test_flag).await;
                            });
                            accepted += 1;
                        }
                    }
                }
            }
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

    fn start_message_dispatcher(&self, mut dispatcher_receiver: mpsc::Receiver<SparseMessage>, mut connections: Vec<Option<TcpStream>>) {
        let private_key = self.private_key.clone();
        let test_flag = self.environment.test_flag;
        tokio::spawn(async move {
            while let Some(message) = dispatcher_receiver.recv().await {
                if let Ok(payload) = bincode::serialize(&message) {
                    let signature = if !test_flag {
                        private_key.sign(&payload)
                    }else{
                        Signature::from_bytes(&[0u8; 64]).unwrap()
                    };
                    let length_bytes = (payload.len() as u32).to_be_bytes();
                    
                    for stream_option in connections.iter_mut() {
                        if let Some(stream) = stream_option {
                            if stream.write_all(&length_bytes).await.is_err() { continue; }
                            if stream.write_all(&payload).await.is_err() { continue; }
                            if stream.write_all(signature.as_ref()).await.is_err() { continue; }
                        }
                    }
                }
            }
        });
    }
    // ✅ ADD THIS ENTIRE FUNCTION
    /// Handles a newly received vertex message.
    /// If valid, it's processed. If invalid due to missing parents, it's buffered.
    async fn handle_new_vertex_message(&mut self, sender_id: NodeId, vm: VertexMessage, dispatcher_tx: &Sender<SparseMessage>) {
        
        // Try to validate the vertex
        if self.validate_vertex(&vm.vertex, vm.vertex.round, sender_id) {
            // It's valid: insert, commit, and then try to advance the protocol
            info!("[Node {}] Vertex from Node {} in round {} is VALID", self.environment.my_node.id, sender_id, vm.vertex.round);
            self.dag.insert(vm.vertex.clone());
            self.try_committing(vm.vertex.clone());
            
            // Now, try to process any work this vertex may have unblocked
            self.process_work_loop(dispatcher_tx).await;

        } else {
            // It's invalid. Check if it's just from the future or from our own round.
            if vm.vertex.round >= self.round.saturating_sub(1) {
                // Buffer it for later processing.
                info!("[Node {}] Buffering vertex from Node {} in round {} (parents missing).", self.environment.my_node.id, sender_id, vm.vertex.round);
                self.pending_vertices.entry(vm.vertex.round).or_default().push((sender_id, vm));
            } else {
                // It's from the past and still invalid, so it's truly bad.
                warn!("[Node {}] Discarding INVALID vertex from Node {} in round {}.", self.environment.my_node.id, sender_id, vm.vertex.round);
            }
        }
    }
    fn may_advance_round(&self) -> bool {
        //todo add timer see paper
        if self.round == 1 { return true; }
        let quorum_threshold = 2 * self.f + 1;
        self.dag.get_round(self.round - 1).map_or(0, |v| v.len()) >= quorum_threshold
    }

    pub fn get_anchor(&self, r: u64) -> Option<&Vertex> {
        if r % 2 == 1 { return None; }
        let leader_id = (r / 2) % self.environment.nodes.len() as u64;
        self.dag.get_round(r).and_then(|round_vertices| {
            round_vertices.iter().find(|v| v.source as u64 == leader_id)
        })
    }

    fn create_new_vertex(&mut self, round: u64) -> Vertex {
        let candidates = self.dag.get_round(round - 1).cloned().unwrap_or_default();
        let signatures: Vec<Signature> = candidates.iter().filter_map(|v| Signature::from_bytes(&v.signed_round).ok()).collect();
        let signers: Vec<NodeId> = candidates.iter().filter(|v| !v.signed_round.is_empty()).map(|v| v.source).collect();
        let sample_proof = aggregate(signatures, signers);
        let seed = Sha256::digest(&sample_proof).to_vec();
        let sampled_parents: Vec<Vertex> = random_sample(&candidates, self.d, &seed);
        let mut edges_hashes: Vec<VertexHash> = sampled_parents.iter().map(|v| v.hash.clone()).collect();
        if let Some(anchor) = self.get_anchor(round - 1) {
            if !edges_hashes.contains(&anchor.hash) {
                edges_hashes.push(anchor.hash.clone());
            }
        }
        let signature = sign_round(round, &self.private_key);
        let mut new_vertex = Vertex {
            hash: vec![],
            round,
            source: self.environment.my_node.id,
            block: bincode::serialize(&self.transaction_generator.generate()).expect("Failed to serialize block"),
            edges: edges_hashes,
            signed_round: signature.to_bytes().to_vec(),
            sample_proof,
        };
        new_vertex.hash = new_vertex.calculate_hash();
        if let Ok(vertex_bytes) = bincode::serialize(&new_vertex){
            self.total_bytes_created += vertex_bytes.len() as u64;
        }  
        new_vertex
    }

    fn validate_vertex(&self, v: &Vertex, round: u64, source: u32) -> bool {
        // Special validation for Round 1
        if v.round == 1 {
            let genesis_hash = vec![0; 32];
            if v.edges.len() == 1 && v.edges[0] == genesis_hash && v.hash == v.calculate_hash() {
                return true;
            } else {
                warn!("[Node {}] Round 1 vertex has an invalid link to the genesis block.", self.environment.my_node.id);
                return false;
            }
        }

        // --- General Validation for Rounds > 1 ---

        // 1. Basic checks
        if v.source != source || v.round != round {
            warn!("[Node {}] Vertex failed basic validation: source/round mismatch.", self.environment.my_node.id);
            return false;
        }
        if v.edges.len() > self.d + 2 {
            warn!("[Node {}] Vertex failed validation: too many edges.", self.environment.my_node.id);
            return false;
        }

        // 2. Cryptographic proof validation
        if bincode::deserialize::<SampleProof>(&v.sample_proof).is_err() {
            warn!("[Node {}] Failed to deserialize sample proof.", self.environment.my_node.id);
            return false;
        }
        if !validate(v.round - 1, &v.sample_proof, &self.public_keys) {
            warn!("[Node {}] Vertex failed validation: invalid sample proof.", self.environment.my_node.id);
            return false;
        }

        // 3. ROBUST parent check: Verify we have the parents the vertex actually links to.
        // This now correctly uses the get_round function.
        let parent_round_number = v.round - 1;
        if let Some(parent_vertices) = self.dag.get_round(parent_round_number) {
            for edge_hash in &v.edges {
                // Check if any vertex in the parent round has the required hash.
                if !parent_vertices.iter().any(|parent| parent.hash == *edge_hash) {
                    warn!("[Node {}] Vertex failed validation: missing parent with hash {:?}.", self.environment.my_node.id, edge_hash);
                    return false;
                }
            }
        } else {
            // If the entire parent round is missing, we are definitely missing the parents.
            warn!("[Node {}] Vertex failed validation: missing parent round {}.", self.environment.my_node.id, parent_round_number);
            return false;
        }

        // 4. Final hash check
        if v.hash != v.calculate_hash() {
            warn!("[Node {}] Vertex failed validation: hash mismatch.", self.environment.my_node.id);
            return false;
        }

        true
    }
    fn print_dag_stats(&self) {
        info!("--- [Node {}] FINAL DAG STATS ---", self.environment.my_node.id);

        // 1. Check if the 'vertices' map (used for pathfinding) has all the blocks.
        info!("Total vertices in 'dag.vertices': {}", self.dag.vertices.len());

        // 2. Check if the 'rounds' map has all the blocks.
        let mut vertices_in_rounds = 0;
        for round_vec in self.dag.rounds.values() {
            vertices_in_rounds += round_vec.len();
        }
        info!("Total vertices in 'dag.rounds': {}", vertices_in_rounds);

        // 3. Check if the 'already_ordered' set matches your final count.
        info!("Total unique vertices in 'already_ordered': {}", self.already_ordered.len());
        
        // 4. Check if you left any unprocessed vertices.
        let mut pending_count = 0;
        for pending_vec in self.pending_vertices.values() {
            pending_count += pending_vec.len();
        }
        info!("Total pending vertices (unprocessed): {}", pending_count);
        
        info!("--- END DAG STATS ---");
    }
}