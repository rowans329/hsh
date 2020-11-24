// External imports
use groestl::{Digest, Groestl224};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Groestl224Hasher;

impl Hasher for Groestl224Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Groestl224::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}
