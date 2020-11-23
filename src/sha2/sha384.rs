// External imports
use sha2::{Digest, Sha384};

// Internal imports
use crate::hasher::Hasher;

pub struct Sha384Hasher;

impl Hasher for Sha384Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Sha384::new();
        hasher.update(bytes);
        hasher.finalize().to_vec()
    }
}
