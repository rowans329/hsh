// External imports
use md5::{Digest, Md5};

// Internal imports
use crate::hasher::Hasher;

pub struct Md5Hasher;

impl Hasher for Md5Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Md5::new();
        hasher.update(bytes);
        hasher.finalize().to_vec()
    }
}
