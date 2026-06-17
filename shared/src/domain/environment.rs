use crate::domain::node::Node;


#[derive(Debug)]
pub struct Environment {
    pub my_node: Node,
    pub nodes: Vec<Node>,
    pub test_flag: bool,
    pub transaction_size: usize,
    pub n_transactions: usize,
    pub input_rate: u64, // tx/s; 0 = unlimited
}
