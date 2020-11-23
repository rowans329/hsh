// External imports
use shabal::{Digest, Shabal512};

// Internal imports
use crate::hasher::Hasher;

pub struct Shabal512Hasher;

impl Hasher for Shabal512Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Shabal512::new();
        hasher.update(bytes);
        hasher.finalize().to_vec()
    }
}
