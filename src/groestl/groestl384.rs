// External imports
use groestl::{Digest, Groestl384};

// Internal imports
use crate::hasher::Hasher;

pub struct Groestl384Hasher;

impl Hasher for Groestl384Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Groestl384::new();
        hasher.update(bytes);
        hasher.finalize().to_vec()
    }
}
