use ed25519_dalek::ed25519::signature;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use bincode::serialize;
use log::error;
use crate::network::message::SparseMessage;
use rand::rngs::OsRng;
use rand::RngCore;
use ed25519_dalek::Keypair; 
use ed25519_dalek::Signer;
use std::sync::Arc;

pub const NONCE_BYTES_LENGTH: usize = 32;
pub const MESSAGE_BYTES_LENGTH: usize = 4; // Ensure this is defined here or imported

pub async fn reliable_broadcast(
    connections: &mut [Option<TcpStream>],
    message: &SparseMessage,
    private_key: &Arc<Keypair>,
) {
    // 1. Serialize the message payload.
    let payload = match bincode::serialize(message) {
        Ok(msg) => msg,
        Err(e) => {
            error!("Failed to serialize message for broadcast: {}", e);
            return;
        }
    };
    
    // 2. Sign the payload.
    let signature = private_key.sign(&payload);

    // 3. Get the payload length in bytes.
    let length_bytes = (payload.len() as u32).to_be_bytes();

    // 4. Write each part of the frame to all active connections.
    let mut failed_indices = vec![];
    for (i, stream_option) in connections.iter_mut().enumerate() {
        if let Some(stream) = stream_option {
            // Write length, then payload, then signature. If any write fails, mark for removal.
            if stream.write_all(&length_bytes).await.is_err() ||
               stream.write_all(&payload).await.is_err() ||
               stream.write_all(signature.as_ref()).await.is_err() {
                error!("Failed to send message to peer {}. Marking for removal.", i);
                failed_indices.push(i);
            }
        }
    }

    // 5. Remove any connections that failed.
    for i in failed_indices {
        connections[i] = None;
    }
}


pub fn generate_nonce() -> [u8; NONCE_BYTES_LENGTH] {
    let mut nonce = [0u8; NONCE_BYTES_LENGTH];
    OsRng.fill_bytes(&mut nonce);
    nonce
}