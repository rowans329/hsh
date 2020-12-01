// Internal imports
use crate::error::HshResult;
use crate::types::HashOutput;

pub trait Hasher {
    type HashInput;

    fn hash(&self, input: Self::HashInput, bytes: &[u8]) -> HshResult<HashOutput>;

    fn hash_str(&self, input: Self::HashInput, str: &str) -> HshResult<HashOutput> {
        self.hash(input, &str.as_bytes())
    }
}
