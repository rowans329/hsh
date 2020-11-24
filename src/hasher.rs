// Internal imports
use crate::types::HashOutput;

pub trait Hasher {
    type HashInput;

    fn hash(&self, input: Self::HashInput, bytes: &[u8]) -> HashOutput;

    fn hash_str(&self, input: Self::HashInput, str: &str) -> HashOutput {
        self.hash(input, &str.as_bytes())
    }
}
