use std::collections::HashSet;
use ed25519_dalek::{Keypair, PublicKey, Signature, Signer, Verifier};
use rand::{SeedableRng};
use rand::seq::SliceRandom;
use sha2::{Sha256, Digest};


pub fn vrf_prove(
    private_key: &Keypair,
    seed: &str,
    sample_size: usize,
    s: u32,
    leader_id: u32,
) -> (HashSet<u32>, Vec<u8>) {
    let mut possible_ids: Vec<u32> = (0..s).collect();
    possible_ids.retain(|&id| id != leader_id);

    let seed_bytes = seed.as_bytes();
    let proof = private_key.sign(seed_bytes);

    let mut hasher = Sha256::new();
    hasher.update(proof.as_ref());
    let hash_output = hasher.finalize();

    let mut rng = rand::rngs::StdRng::from_seed(hash_output[0..32].try_into().unwrap());
    possible_ids.shuffle(&mut rng);

    let mut sample_set: HashSet<u32> = possible_ids.into_iter().take(sample_size - 1).collect();
    sample_set.insert(leader_id);

    (sample_set, proof.as_ref().to_vec())
}

pub fn vrf_verify(
    public_key: &PublicKey,
    seed: &str,
    sample_size: usize,
    s: u32,
    leader_id: u32,
    sample_set: &Vec<u32>,
    proof: &[u8],
) -> bool {
    let mut possible_ids: Vec<u32> = (0..s).collect();
    possible_ids.retain(|&id| id != leader_id);

    let seed_bytes = seed.as_bytes();

    if public_key.verify(seed_bytes, &Signature::from_bytes(proof).unwrap()).is_err() {
        return false;
    }

    let mut hasher = Sha256::new();
    hasher.update(proof);
    let hash_output = hasher.finalize();

    let mut rng = rand::rngs::StdRng::from_seed(hash_output[0..32].try_into().unwrap());
    possible_ids.shuffle(&mut rng);

    let mut expected_sample_set: HashSet<u32> = possible_ids.into_iter().take(sample_size - 1).collect();
    expected_sample_set.insert(leader_id);

    let actual_sample_set: HashSet<u32> = sample_set.iter().copied().collect();
    actual_sample_set == expected_sample_set
}
