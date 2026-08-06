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

    /// Replace a hash-only skeleton with the complete vertex without adding a
    /// duplicate entry to the round index. If no skeleton exists, insert the
    /// vertex normally.
    pub fn replace_or_insert(&mut self, vertex: Vertex) {
        let hash = vertex.hash.clone();
        if let Some(existing) = self.vertices.get_mut(&hash) {
            *existing = vertex;
        } else {
            self.insert(vertex);
        }
    }

    /// Prune old vertices only after they have been ordered. Unordered old
    /// vertices must remain available so a later weak edge can include them.
    pub fn prune_ordered(
        &mut self,
        before_round: u64,
        ordered: &HashSet<VertexHash>,
    ) {
        let to_remove: Vec<u64> = self.rounds.keys()
            .filter(|&&r| r < before_round)
            .cloned()
            .collect();
        for r in to_remove {
            if let Some(hashes) = self.rounds.remove(&r) {
                let mut retained = Vec::new();
                for hash in hashes {
                    if ordered.contains(&hash) {
                        self.vertices.remove(&hash);
                    } else {
                        retained.push(hash);
                    }
                }
                if !retained.is_empty() {
                    self.rounds.insert(r, retained);
                }
            }
        }
    }
}

#[cfg(test)]
mod prbc_dag_tests {
    use super::PRBCDag;
    use crate::types::vertex::{TimeoutCertificate, Vertex};
    use std::collections::{BTreeMap, HashSet};

    #[test]
    fn replacing_skeleton_preserves_all_hash_authenticated_fields() {
        let mut signatures = BTreeMap::new();
        signatures.insert(1, vec![7; 64]);

        let mut full_vertex = Vertex {
            hash: Vec::new(),
            round: 2,
            source: 1,
            block: vec![3; 32],
            edges: vec![vec![4; 32]],
            weak_edges: vec![vec![5; 32]],
            signed_round: vec![6],
            sample_proof: vec![7],
            tc: Some(TimeoutCertificate {
                round: 1,
                signatures,
            }),
            nvc: None,
        };
        full_vertex.hash = full_vertex.calculate_hash();

        let skeleton = Vertex {
            hash: full_vertex.hash.clone(),
            round: full_vertex.round,
            source: full_vertex.source,
            block: Vec::new(),
            edges: Vec::new(),
            weak_edges: Vec::new(),
            signed_round: Vec::new(),
            sample_proof: Vec::new(),
            tc: None,
            nvc: None,
        };

        let mut dag = PRBCDag::new();
        dag.insert(skeleton);
        dag.replace_or_insert(full_vertex.clone());

        let stored = dag.vertices.get(&full_vertex.hash).unwrap();
        assert_eq!(stored, &full_vertex);
        assert_eq!(stored.calculate_hash(), full_vertex.hash);
        assert!(stored.tc.is_some());
        assert_eq!(dag.rounds.get(&full_vertex.round).unwrap().len(), 1);
    }

    #[test]
    fn pruning_keeps_unordered_vertices_for_future_weak_edges() {
        let mut dag = PRBCDag::new();
        let ordered = Vertex {
            hash: vec![1; 32],
            round: 1,
            source: 1,
            block: Vec::new(),
            edges: Vec::new(),
            weak_edges: Vec::new(),
            signed_round: Vec::new(),
            sample_proof: Vec::new(),
            tc: None,
            nvc: None,
        };
        let mut unordered = ordered.clone();
        unordered.hash = vec![2; 32];
        unordered.source = 2;

        dag.insert(ordered.clone());
        dag.insert(unordered.clone());
        dag.prune_ordered(2, &HashSet::from([ordered.hash.clone()]));

        assert!(!dag.vertices.contains_key(&ordered.hash));
        assert_eq!(dag.vertices.get(&unordered.hash), Some(&unordered));
        assert_eq!(dag.rounds.get(&1), Some(&vec![unordered.hash]));
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
