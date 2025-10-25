use crate::types::vertex::Vertex;
use rand::{SeedableRng, seq::SliceRandom};
use rand_chacha::ChaCha20Rng;

pub type NodeId = u32;

pub fn random_sample<'a>(
    candidates: &'a [Vertex],
    d: usize,
    seed: &[u8],
) -> Vec<Vertex> {
    let mut rng = ChaCha20Rng::from_seed(seed[..32].try_into().unwrap());
    let mut sample = candidates.to_vec();
    sample.shuffle(&mut rng);
    sample.into_iter().take(d).collect()
}
