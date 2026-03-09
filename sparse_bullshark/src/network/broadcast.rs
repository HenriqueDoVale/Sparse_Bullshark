use rand::rngs::OsRng;
use rand::RngCore;

pub const NONCE_BYTES_LENGTH: usize = 32;

pub fn generate_nonce() -> [u8; NONCE_BYTES_LENGTH] {
    let mut nonce = [0u8; NONCE_BYTES_LENGTH];
    OsRng.fill_bytes(&mut nonce);
    nonce
}