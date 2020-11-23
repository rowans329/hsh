// External imports
use sha3::{Digest, Keccak224};

// Internal imports
use crate::hasher::Hasher;

pub struct Keccak224Hasher;

impl Hasher for Keccak224Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Keccak224::new();
        hasher.update(bytes);
        hasher.finalize().to_vec()
    }
}
