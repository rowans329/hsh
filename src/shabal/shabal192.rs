// External imports
use shabal::{Digest, Shabal192};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Shabal192Hasher;

impl Hasher for Shabal192Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Shabal192::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}
