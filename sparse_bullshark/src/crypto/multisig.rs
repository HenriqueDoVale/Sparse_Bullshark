use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier, ed25519::signature::Signature as _};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use log::{error, warn};
use crate::types::vertex::NodeId;

/// A structure to bundle signatures and their signers for the sample_proof.
/// This gets serialized into the `Vec<u8>` of the vertex's `sample_proof` field.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SampleProof {
    pub signatures: Vec<Signature>,
    pub signers: Vec<NodeId>,
}

/// Creates a cryptographic signature of the round number using the node's private key.
pub fn sign_round(round: u64, private_key: &Keypair) -> Signature {
    let message = round.to_be_bytes();
    private_key.sign(&message)
}

/// Aggregates a collection of signatures and signer IDs into a serializable proof.
pub fn aggregate(signatures: Vec<Signature>, signers: Vec<NodeId>) -> Vec<u8> {
    let proof = SampleProof {
        signatures,
        signers,
    };

    // Serialize the proof structure into a byte vector for transport.
    bincode::serialize(&proof).unwrap_or_else(|e| {
        error!("Failed to serialize sample proof: {}", e);
        vec![]
    })
}

/// Validates a serialized sample proof.
/// It deserializes the proof and then verifies each signature against the
/// corresponding public key of the signer.
pub fn validate(
    round: u64,
    sample_proof: &[u8],
    public_keys: &HashMap<NodeId, PublicKey>,
) -> bool {
    let proof: SampleProof = match bincode::deserialize(sample_proof) {
        Ok(p) => p,
        Err(e) => {
            warn!("Failed to deserialize sample proof: {}", e);
            return false;
        }
    };

    if proof.signatures.len() != proof.signers.len() {
        warn!("Mismatched number of signatures and signers in proof.");
        return false;
    }

    let message = round.to_be_bytes();
    let mut messages: Vec<&[u8]> = Vec::new();
    let mut signatures_to_verify: Vec<Signature> = Vec::new();
    let mut keys_to_verify: Vec<PublicKey> = Vec::new();

    for (sig, signer_id) in proof.signatures.iter().zip(proof.signers.iter()) {
        if let Some(public_key) = public_keys.get(signer_id) {
            messages.push(&message);
            signatures_to_verify.push(*sig);
            keys_to_verify.push(*public_key);
        } else {
            warn!("Public key not found for signer ID: {}", signer_id);
            return false; // A signer must have a known public key
        }
    }
    
    // Use batch verification for efficiency, as recommended by the library.
    ed25519_dalek::verify_batch(&messages, &signatures_to_verify, &keys_to_verify).is_ok()
}