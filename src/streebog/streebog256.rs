// External imports
use streebog::{Digest, Streebog256};

// Internal imports
use crate::hasher::Hasher;

pub struct Streebog256Hasher;

impl Hasher for Streebog256Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Streebog256::new();
        hasher.update(bytes);
        hasher.finalize().to_vec()
    }
}
