// External imports
use sha2::{Digest, Sha224};

// Internal imports
use crate::hasher::Hasher;

pub struct Sha224Hasher;

impl Hasher for Sha224Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Sha224::new();
        hasher.update(bytes);
        hasher.finalize().to_vec()
    }
}
