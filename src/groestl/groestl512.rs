// External imports
use groestl::{Digest, Groestl512};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Groestl512Hasher;

impl Hasher for Groestl512Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Groestl512::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}
