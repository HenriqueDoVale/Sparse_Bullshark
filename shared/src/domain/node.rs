
#[derive(Debug, serde::Deserialize, Clone)]
pub struct Node {
    pub id: u32,
    pub host: String,
    pub port: u16,
}
