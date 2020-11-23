// External imports
use ripemd320::{Digest, Ripemd320};

// Internal imports
use crate::hasher::Hasher;

pub struct Ripemd320Hasher;

impl Hasher for Ripemd320Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Ripemd320::new();
        hasher.update(bytes);
        hasher.finalize().to_vec()
    }
}
