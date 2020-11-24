// External imports
use groestl::{Digest, Groestl384};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Groestl384Hasher;

impl Hasher for Groestl384Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Groestl384::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}
