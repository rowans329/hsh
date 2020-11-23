// External imports
use shabal::{Digest, Shabal192};

// Internal imports
use crate::hasher::Hasher;

pub struct Shabal192Hasher;

impl Hasher for Shabal192Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Shabal192::new();
        hasher.update(bytes);
        hasher.finalize().to_vec()
    }
}
