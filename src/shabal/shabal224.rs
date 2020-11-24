// External imports
use shabal::{Digest, Shabal224};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Shabal224Hasher;

impl Hasher for Shabal224Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Shabal224::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}
