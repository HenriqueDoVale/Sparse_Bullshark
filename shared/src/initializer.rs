use std::collections::HashMap;
use std::error::Error;
use std::{env, fs};
use std::fs::File;
use csv::ReaderBuilder;
use toml::Value;
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::{Keypair, PublicKey};
use crate::domain::environment::Environment;
use crate::domain::node::Node;

pub const MINUTES_PER_HOUR: u32 = 60;
pub const SECONDS_PER_HOUR: u32 = 3600;
pub const SECONDS_PER_MINUTE: u32 = 60;
pub const ADD_ONE_MINUTE: u32 = 1;
pub const ADD_ONE_HOUR: u32 = 1;
const MIN_ARGS: usize = 4;
const MY_NODE_ID_ARG_POS: usize = 1;
const TRANSACTION_SIZE_ARG_POS: usize = 2;
const N_TRANSACTIONS_ARG_POS: usize = 3;
const NODES_FILENAME: &str = "./shared/nodes.csv";
const PUBLIC_KEYS_FILENAME: &str = "./shared/public_keys.toml";
const PUBLIC_KEYS_FILE_INDEX: &str = "public_key";
const PRIVATE_KEY_ENV: &str = "PRIVATE_KEY_";


pub fn get_environment(args: Vec<String>) -> Result<Environment, Box<dyn Error>> {
    if args.len() < MIN_ARGS {
        return Err("Usage: simplex [my_node_id] [transaction_size] [number of transactions] [protocol_mode: optional] [test_flag: optional]".into());
    }

    let my_id = args[MY_NODE_ID_ARG_POS].parse::<u32>()?;
    let transaction_size = args[TRANSACTION_SIZE_ARG_POS].parse::<usize>()?;
    let n_transactions = args[N_TRANSACTIONS_ARG_POS].parse::<usize>()?;
    let test_flag = false;//false no sigs true sigs
    //let test_flag = args.iter().any(|arg| arg == "test");
    let nodes = read_nodes_from_csv(NODES_FILENAME)?;
    let my_node = nodes.iter().find(|node| node.id == my_id).ok_or("This process' node was not found")?.clone();

    Ok(Environment {
        my_node,
        nodes,
        test_flag,
        transaction_size,
        n_transactions,
    })
}

pub fn read_nodes_from_csv(file_path: &str) -> Result<Vec<Node>, Box<dyn Error>> {
    let file = File::open(file_path)?;
    let mut rdr = ReaderBuilder::new()
        .has_headers(true)
        .from_reader(file);

    let mut nodes = Vec::new();
    for result in rdr.deserialize() {
        match result {
            Ok(node) => nodes.push(node),
            Err(e) => eprintln!("Error parsing CSV line: {}", e),
        }
    }
    Ok(nodes)
}

pub fn get_public_keys() -> HashMap<u32, PublicKey> {
    let content = fs::read_to_string(PUBLIC_KEYS_FILENAME).expect("Failed to read public key file");
    let data: Value = content.parse::<Value>().expect("Failed to parse TOML data");
    let data_table = data.as_table().expect("Expected TOML data to be a table");
    let mut public_keys = HashMap::new();
    for (node_id, node_info) in data_table {
        if let Some(public_key_str) = node_info.get(PUBLIC_KEYS_FILE_INDEX).and_then(|v| v.as_str()) {
            let id = node_id.parse::<u32>().expect("Failed to parse node id from public key file");
            let public_key_bytes = general_purpose::STANDARD.decode(public_key_str).expect("Failed to decode base64 public key");
            public_keys.insert(id, PublicKey::from_bytes(&public_key_bytes).unwrap());
        }
    }
    public_keys
}

pub fn get_private_key(node_id: u32) -> Keypair {
    let encoded_key = env::var(format!("{}{}", PRIVATE_KEY_ENV, node_id)).expect("Private key environment variable is not set");
    println!("{}",encoded_key.to_string());
    let key_data = general_purpose::STANDARD.decode(encoded_key).expect("Failed to decode base64 private key");
    Keypair::from_bytes(&key_data).expect("Failed to parse private key")
}
