// External imports
use groestl::{Digest, Groestl224};

// Internal imports
use crate::hasher::Hasher;

pub struct Groestl224Hasher;

impl Hasher for Groestl224Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Groestl224::new();
        hasher.update(bytes);
        hasher.finalize().to_vec()
    }
}
