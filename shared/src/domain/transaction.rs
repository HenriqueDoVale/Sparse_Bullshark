use std::hash::{Hash};

#[derive(Hash, Eq, PartialEq, Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Transaction {
    pub padding: String,
}

impl Transaction {
    pub fn new(padding_size: usize) -> Self {
        let padding = "X".repeat(padding_size);
        Transaction { padding }
    }
}
