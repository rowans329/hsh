// External imports
use sha3::{Digest, Sha3_384};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Sha3_384Hasher;

impl Hasher for Sha3_384Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Sha3_384::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}
