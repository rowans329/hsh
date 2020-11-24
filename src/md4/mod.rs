// External imports
use md4::{Digest, Md4};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Md4Hasher;

impl Hasher for Md4Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Md4::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}
