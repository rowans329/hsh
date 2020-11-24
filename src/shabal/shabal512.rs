// External imports
use shabal::{Digest, Shabal512};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Shabal512Hasher;

impl Hasher for Shabal512Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Shabal512::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}
