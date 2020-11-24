// External imports
use shabal::{Digest, Shabal384};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Shabal384Hasher;

impl Hasher for Shabal384Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Shabal384::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}
