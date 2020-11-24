// External imports
use streebog::{Digest, Streebog256};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Streebog256Hasher;

impl Hasher for Streebog256Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Streebog256::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}
