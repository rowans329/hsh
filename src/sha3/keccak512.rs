// External imports
use sha3::{Digest, Keccak512};

// Internal imports
use crate::hasher::Hasher;

pub struct Keccak512Hasher;

impl Hasher for Keccak512Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Keccak512::new();
        hasher.update(bytes);
        hasher.finalize().to_vec()
    }
}
