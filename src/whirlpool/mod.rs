// External imports
use whirlpool::{Digest, Whirlpool};

// Internal imports
use crate::hasher::Hasher;

pub struct WhirlpoolHasher;

impl Hasher for WhirlpoolHasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Whirlpool::new();
        hasher.update(bytes);
        hasher.finalize().to_vec()
    }
}
