// External imports
use md5::{Digest, Md5};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Md5Hasher;

impl Hasher for Md5Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Md5::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}
