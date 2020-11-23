// External imports
use sha2::{Digest, Sha256};

// Internal imports
use crate::hasher::Hasher;

pub struct Sha256Hasher;

impl Hasher for Sha256Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hasher.finalize().to_vec()
    }
}
