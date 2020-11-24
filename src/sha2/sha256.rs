// External imports
use sha2::{Digest, Sha256};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Sha256Hasher;

impl Hasher for Sha256Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}
