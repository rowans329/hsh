// External imports
use shabal::{Digest, Shabal224};

// Internal imports
use crate::hasher::Hasher;

pub struct Shabal224Hasher;

impl Hasher for Shabal224Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Shabal224::new();
        hasher.update(bytes);
        hasher.finalize().to_vec()
    }
}
