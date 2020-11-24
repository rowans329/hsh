// External imports
use whirlpool::{Digest, Whirlpool};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct WhirlpoolHasher;

impl Hasher for WhirlpoolHasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Whirlpool::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}
