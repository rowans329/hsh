// External imports
use shabal::{Digest, Shabal256};

// Internal imports
use crate::hasher::Hasher;

pub struct Shabal256Hasher;

impl Hasher for Shabal256Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Shabal256::new();
        hasher.update(bytes);
        hasher.finalize().to_vec()
    }
}
