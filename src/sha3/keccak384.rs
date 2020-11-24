// External imports
use sha3::{Digest, Keccak384};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Keccak384Hasher;

impl Hasher for Keccak384Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Keccak384::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}
