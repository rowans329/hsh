// External imports
use groestl::{Digest, Groestl256};

// Internal imports
use crate::hasher::Hasher;

pub struct Groestl256Hasher;

impl Hasher for Groestl256Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Groestl256::new();
        hasher.update(bytes);
        hasher.finalize().to_vec()
    }
}
