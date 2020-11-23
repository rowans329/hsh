// External imports
use groestl::{Digest, Groestl512};

// Internal imports
use crate::hasher::Hasher;

pub struct Groestl512Hasher;

impl Hasher for Groestl512Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Groestl512::new();
        hasher.update(bytes);
        hasher.finalize().to_vec()
    }
}
