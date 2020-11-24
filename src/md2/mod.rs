// External imports
use md2::{Digest, Md2};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Md2Hasher;

impl Hasher for Md2Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Md2::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}
