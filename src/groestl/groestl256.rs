// External imports
use groestl::{Digest, Groestl256};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Groestl256Hasher;

impl Hasher for Groestl256Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Groestl256::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}
