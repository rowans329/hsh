// External imports
use shabal::{Digest, Shabal384};

// Internal imports
use crate::hasher::Hasher;

pub struct Shabal384Hasher;

impl Hasher for Shabal384Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Shabal384::new();
        hasher.update(bytes);
        hasher.finalize().to_vec()
    }
}
