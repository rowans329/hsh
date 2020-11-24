// External imports
use sha2::{Digest, Sha384};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Sha384Hasher;

impl Hasher for Sha384Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Sha384::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}
