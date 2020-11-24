// External imports
use sha3::{Digest, Keccak512};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Keccak512Hasher;

impl Hasher for Keccak512Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Keccak512::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}
