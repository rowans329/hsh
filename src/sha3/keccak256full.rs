// External imports
use sha3::{Digest, Keccak256Full};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Keccak256FullHasher;

impl Hasher for Keccak256FullHasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Keccak256Full::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}
