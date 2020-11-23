// External imports
use sha3::{Digest, Sha3_256};

// Internal imports
use crate::hasher::Hasher;

pub struct Sha3_256Hasher;

impl Hasher for Sha3_256Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Sha3_256::new();
        hasher.update(bytes);
        hasher.finalize().to_vec()
    }
}
