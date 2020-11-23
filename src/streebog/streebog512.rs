// External imports
use streebog::{Digest, Streebog512};

// Internal imports
use crate::hasher::Hasher;

pub struct Streebog512Hasher;

impl Hasher for Streebog512Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Streebog512::new();
        hasher.update(bytes);
        hasher.finalize().to_vec()
    }
}
