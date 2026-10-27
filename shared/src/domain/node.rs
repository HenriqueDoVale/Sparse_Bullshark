
#[derive(Debug, Clone, PartialEq)]
pub enum NodeBehavior {
    Ok,
    Byz1,   // Sends VAL/Propose to only 2f+1 nodes
    Silent, // Never creates or broadcasts its own vertex
    Byz2,   // Forwards a fake block body with a wrong hash
    Byz3,   // PRBC: sends its own batch to only 2f+1 peers (batch counterpart of Byz1)
    Byz4,   // PRBC: never answers vertex or batch recovery requests
    Byz5,   // PRBC: Byz1, and its votes too go to only 2f+1 peers (tests certificate fetch)
}

impl Default for NodeBehavior {
    fn default() -> Self {
        NodeBehavior::Ok
    }
}

impl<'de> serde::Deserialize<'de> for NodeBehavior {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        match s.to_lowercase().as_str() {
            "byz1"   => Ok(NodeBehavior::Byz1),
            "silent" => Ok(NodeBehavior::Silent),
            "byz2"   => Ok(NodeBehavior::Byz2),
            "byz3"   => Ok(NodeBehavior::Byz3),
            "byz4"   => Ok(NodeBehavior::Byz4),
            "byz5"   => Ok(NodeBehavior::Byz5),
            _        => Ok(NodeBehavior::Ok),
        }
    }
}

#[derive(Debug, serde::Deserialize, Clone)]
pub struct Node {
    pub id: u32,
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub behavior: NodeBehavior,
}
