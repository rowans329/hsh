// External imports
use blake2::{Blake2b, Digest};

// Internal imports
use crate::hasher::Hasher;

pub struct Blake2Hasher;

impl Hasher for Blake2Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Blake2b::new();
        hasher.update(bytes);
        hasher.finalize().to_vec()
    }
}
