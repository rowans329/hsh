// External imports
use streebog::{Digest, Streebog512};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Streebog512Hasher;

impl Hasher for Streebog512Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Streebog512::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}
