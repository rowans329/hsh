// External imports
use sha3::{Digest, Keccak256};

// Internal imports
use crate::hasher::Hasher;

pub struct Keccak256Hasher;

impl Hasher for Keccak256Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Keccak256::new();
        hasher.update(bytes);
        hasher.finalize().to_vec()
    }
}
