mod consensus;
mod crypto;
mod network;
mod types;
mod utils;
mod config;

use std::env;
use env_logger::Env;
use log::{info, error};
use shared::initializer::{get_environment, get_private_key, get_public_keys};

use consensus::sparse_bullshark::SparseBullshark;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    // Initialize the logger
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    // Read CLI args (e.g. path to env file or node ID)
    let args: Vec<String> = env::args().collect();

    // Load environment and crypto setup
    match get_environment(args) {
        Ok(env) => {
            info!("Successfully read environment: {:?}", env);

            // Load public/private keys
            let public_keys = get_public_keys();
            let private_key = get_private_key(env.my_node.id);

            // Create node instance
            let mut node = SparseBullshark::new(env, public_keys, private_key);
            
            node.start().await;
        }
        Err(err) => {
            error!("Error loading environment: {}", err);
        }
    }
}
