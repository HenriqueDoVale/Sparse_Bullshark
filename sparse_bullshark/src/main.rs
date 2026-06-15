mod consensus;
mod crypto;
mod network;
mod types;
mod utils;
mod config;

use std::env;
use env_logger::Env;
use log::{info, error};
use consensus::bullshark::Bullshark;
use shared::{domain::node::NodeBehavior, initializer::{get_environment, get_private_key, get_public_keys}};

use consensus::sparse_bullshark::SparseBullshark;

use crate::consensus::sailfish::Sailfish;
use crate::consensus::prbc_sailfish::PRBCSailfish;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    // Initialize the logger
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    // Read CLI args (e.g. path to env file or node ID)
    let args: Vec<String> = env::args().collect();
    let protocol_mode = env::var("PROTOCOL").unwrap_or_else(|_| "sparse".to_string()).to_lowercase();
    // Load environment and crypto setup
    match get_environment(args) {
        Ok(env) => {
            info!("Successfully read environment: {:?}", env);

            let (behavior_label, behavior_desc) = match env.my_node.behavior {
                NodeBehavior::Ok     => ("OK",     "Normal honest node — full participation"),
                NodeBehavior::Byz1   => ("BYZ1",   "Byzantine: sends proposal to only 2f+1 peers"),
                NodeBehavior::Silent => ("SILENT",  "Byzantine: never creates or sends its own vertex"),
                NodeBehavior::Byz2   => ("BYZ2",   "Byzantine: forwards fake payload (wrong body, original hash)"),
            };
            println!("\n\
                ╔══════════════════════════════════════════════════════╗\n\
                ║  NODE {:2}  |  PROTOCOL: {:12}  |  {:6}         ║\n\
                ║  {}  ║\n\
                ╚══════════════════════════════════════════════════════╝\n",
                env.my_node.id,
                protocol_mode.to_uppercase(),
                behavior_label,
                format!("{:<52}", behavior_desc),
            );

            // Load public/private keys
            let public_keys = get_public_keys();
            let private_key = get_private_key(env.my_node.id);

            if protocol_mode == "dense" {
                // --- Run Standard (Dense) Bullshark ---
                let node = Bullshark::new(env, public_keys, private_key);
                node.start().await;
            } else if protocol_mode == "sailfish" {
                let node = Sailfish::new(env, public_keys, private_key);
                node.start().await;
            } else if protocol_mode == "prbc_sailfish" {
                let node = PRBCSailfish::new(env, public_keys, private_key);
                node.start().await;
            } else {
                let node = SparseBullshark::new(env, public_keys, private_key);
                node.start().await;
            }
        }
        Err(err) => {
            error!("Error loading environment: {}", err);
        }
    }
}
