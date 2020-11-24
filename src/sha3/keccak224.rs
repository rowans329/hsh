// External imports
use sha3::{Digest, Keccak224};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Keccak224Hasher;

impl Hasher for Keccak224Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Keccak224::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}
