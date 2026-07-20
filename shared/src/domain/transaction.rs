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

    /// Same byte-length as `new(padding_size)` (so the calibrated transaction
    /// size is preserved), but the first bytes encode a unique `id`. This makes
    /// otherwise-identical padding transactions serialize to distinct bytes —
    /// and therefore distinct batch digests — which the decoupled mempool needs
    /// to avoid collapsing every batch to a single cached entry.
    pub fn with_id(padding_size: usize, id: u64) -> Self {
        let mut padding = "X".repeat(padding_size);
        let tag = format!("{:016x}", id); // 16 ASCII hex chars
        let n = tag.len().min(padding.len());
        // Safe: `padding` is all ASCII 'X' and `tag` is ASCII hex, so both
        // range bounds fall on char boundaries and the length is unchanged.
        padding.replace_range(0..n, &tag[..n]);
        Transaction { padding }
    }
}
