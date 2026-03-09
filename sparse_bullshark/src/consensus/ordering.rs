use super::sparse_bullshark::SparseBullshark;
use super::bullshark::Bullshark; // Import your other struct
use crate::types::vertex::Vertex;
use log::{debug};
use std::collections::HashSet;

// 1. Define a macro that wraps your entire implementation block
macro_rules! impl_ordering_logic {
    // It takes the Struct Name and a boolean for the sparse threshold
    ($struct_name:ty, $is_sparse:expr) => {
        
        impl $struct_name {
            pub fn try_committing(&mut self, committed_vertex: Vertex) {
                if committed_vertex.round < 2 {
                    return;
                }

                let anchor_round = committed_vertex.round - 2;
                
                let anchor = match self.get_anchor(anchor_round){
                    Some(a) => a.clone(),
                    None => return,
                };

                if anchor.round <= self.last_ordered_round {
                    return;
                }
                
                let mut vote_count = 0;
                if let Some(voters) = self.dag.get_round(anchor_round + 1) {
                    for voter in voters {
                        if voter.edges.contains(&anchor.hash) {
                            vote_count += 1;
                        }
                    }
                }

                // 2. The macro uses the boolean passed in to set the threshold
                let direct_commit_threshold = if $is_sparse {
                    2 * self.f + 1
                } else {
                    self.f + 1
                };

                if vote_count >= direct_commit_threshold {
                    debug!(
                        "[Node {}] DIRECT COMMIT of anchor in round {}",
                        self.environment.my_node.id, anchor.round
                    );
                    self.order_anchors(anchor);
                }
            }

            pub fn order_anchors(&mut self, anchor: Vertex) {
                self.ordered_anchors_stack.push(anchor.clone());
                let mut current_anchor = anchor;
                let mut r = current_anchor.round - 2;
                
                while r > self.last_ordered_round {
                    if let Some(prev_anchor) = self.get_anchor(r).cloned() {
                        if self.dag.has_path(&current_anchor, &prev_anchor) {
                            debug!(
                                "[Node {}] INDIRECT COMMIT of anchor in round {}",
                                self.environment.my_node.id, prev_anchor.round
                            );
                            self.ordered_anchors_stack.push(prev_anchor.clone());
                            current_anchor = prev_anchor.clone();
                        }
                    }
                    r -= 2;
                }
                
                let new_ordered_round = self.ordered_anchors_stack.last().unwrap().round;
                self.last_ordered_round = new_ordered_round;    
                self.order_history();
            }

            pub fn order_history(&mut self) {
                while let Some(anchor) = self.ordered_anchors_stack.pop() {
                    let mut to_order_queue = vec![anchor.clone()];
                    let mut to_order_set = HashSet::new();
                    to_order_set.insert(anchor.hash.clone());

                    let mut head = 0;
                    while head < to_order_queue.len() {
                        let current = to_order_queue[head].clone();
                        head += 1;
                        if self.already_ordered.contains(&current.hash) {
                            continue;
                        }
                        for parent_hash in &current.edges {
                            if !to_order_set.contains(parent_hash) {
                                if let Some(parent) = self.dag.vertices.get(parent_hash) {
                                    to_order_set.insert(parent.hash.clone());
                                    to_order_queue.push(parent.clone());
                                }
                            }
                        }
                    }
                    
                    to_order_queue.sort_by(|a, b| a.hash.cmp(&b.hash));

                    for vertex in to_order_queue {
                        if !self.already_ordered.contains(&vertex.hash) {
                            debug!(
                                "[Node {}] FINALIZING AND ORDERING Vertex from Node {} in round {}",
                                self.environment.my_node.id, vertex.source, vertex.round
                            );
                            self.finalized_block_count += 1;
                            self.already_ordered.insert(vertex.hash.clone());
                        }
                    }
                }
            }
        }
    };
}

// 3. FINALLY: Invoke the macro for both structs!
// This magically generates the `impl SparseBullshark` and `impl Bullshark` blocks.
impl_ordering_logic!(SparseBullshark, true);
impl_ordering_logic!(Bullshark, false);