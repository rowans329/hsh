// External imports
use ripemd160::{Digest, Ripemd160};

// Internal imports
use crate::hasher::Hasher;

pub struct Ripemd160Hasher;

impl Hasher for Ripemd160Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Ripemd160::new();
        hasher.update(bytes);
        hasher.finalize().to_vec()
    }
}
