// External imports
use sha2::{Digest, Sha512};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Sha512Hasher;

impl Hasher for Sha512Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Sha512::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}
