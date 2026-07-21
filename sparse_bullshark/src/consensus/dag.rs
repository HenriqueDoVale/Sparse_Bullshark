use crate::types::vertex::{Vertex};
use std::{collections::{HashMap, HashSet, VecDeque}};
use crate::types::vertex::{VertexHash};

// ── PRBC-Sailfish DAG ─────────────────────────────────────────────────────────
// Separate from the generic DAG; stores round→hash index only, so DAG::insert
// does a single owned-Vertex move (zero 256 KB copies vs. the two in the generic).
pub struct PRBCDag {
    pub rounds: HashMap<u64, Vec<VertexHash>>,
    pub vertices: HashMap<VertexHash, Vertex>,
}
impl PRBCDag {
    pub fn new() -> Self {
        Self {
            rounds: HashMap::new(),
            vertices: HashMap::new(),
        }
    }
    pub fn insert(&mut self, vertex: Vertex) {
        let h = vertex.hash.clone();
        self.rounds.entry(vertex.round).or_default().push(h.clone());
        self.vertices.insert(h, vertex);
    }
    pub fn prune(&mut self, before_round: u64) {
        let to_remove: Vec<u64> = self.rounds.keys()
            .filter(|&&r| r < before_round)
            .cloned()
            .collect();
        for r in to_remove {
            if let Some(hashes) = self.rounds.remove(&r) {
                for h in hashes {
                    self.vertices.remove(&h);
                }
            }
        }
    }
}

pub struct DAG {
    pub rounds: HashMap<u64, Vec<Vertex>>,
    pub vertices: HashMap<VertexHash, Vertex>,
}
impl DAG {
    pub fn new() -> Self {
        Self{ 
            rounds : HashMap::new(),
            vertices : HashMap::new(), 
        }
    }
    
    pub fn insert(&mut self, vertex: Vertex){
        self.rounds.entry(vertex.round).or_default().push(vertex.clone());
        self.vertices.insert(vertex.hash, self.rounds.get(&vertex.round).unwrap().last().unwrap().clone());
    }

    pub fn get_round(&self, round : u64) -> Option<&Vec<Vertex>> {
            self.rounds.get(&round)
    }

    /// Drop all rounds strictly below `before_round` from both indexes.
    /// Call after updating `last_ordered_round` with a small safety window
    /// (e.g. `last_ordered_round.saturating_sub(4)`) to bound memory usage.
    pub fn prune(&mut self, before_round: u64) {
        let to_remove: Vec<u64> = self.rounds.keys()
            .filter(|&&r| r < before_round)
            .cloned()
            .collect();
        for r in to_remove {
            if let Some(vs) = self.rounds.remove(&r) {
                for v in vs {
                    self.vertices.remove(&v.hash);
                }
            }
        }
    }
    /* 
    pub fn get_vertices_by_sources(&self, round: u64, sources: &[NodeId]) -> Vec<Vertex> {
        let mut result = Vec::new();
        let sources_set: HashSet<_> = sources.iter().collect();
        if let Some(round_vertices) = self.rounds.get(&round)  {
            for vertex in round_vertices {
                if sources_set.contains(&vertex.clone().source){
                    result.push(vertex.clone());
                }
            }
        }
        result
    }
    */
    pub fn has_path(&self, start_vertex: &Vertex, target_vertex: &Vertex) -> bool {
       if start_vertex.hash == target_vertex.hash {
            return true;
        }

        let mut queue = VecDeque::new();
        let mut visited = HashSet::new();

        queue.push_back(start_vertex.clone());
        visited.insert(start_vertex.hash.clone());

        while let Some(current) = queue.pop_front() {
            if current.hash == target_vertex.hash {
                return true;
            }

            // Don't search past the target's round
            if current.round <= target_vertex.round {
                continue;
            }

            for parent_hash in &current.edges {
                if !visited.contains(parent_hash) {
                    if let Some(parent_vertex) = self.vertices.get(parent_hash) {
                        visited.insert(parent_hash.clone());
                        queue.push_back(parent_vertex.clone());
                    }
                }
            }
        }

        false
    }
}