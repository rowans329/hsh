// External imports
use shabal::{Digest, Shabal256};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Shabal256Hasher;

impl Hasher for Shabal256Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Shabal256::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}
