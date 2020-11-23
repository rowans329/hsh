// External imports
use md2::{Digest, Md2};

// Internal imports
use crate::hasher::Hasher;

pub struct Md2Hasher;

impl Hasher for Md2Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Md2::new();
        hasher.update(bytes);
        hasher.finalize().to_vec()
    }
}
