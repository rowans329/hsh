// External imports
use sha1::{Digest, Sha1};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Sha1Hasher;

impl Hasher for Sha1Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Sha1::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}
