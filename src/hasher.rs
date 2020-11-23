// External imports
use hex::ToHex;

pub trait Hasher {
    type HashInput;

    fn hash(&self, input: Self::HashInput, bytes: &[u8]) -> Vec<u8>;

    fn hash_str(&self, input: Self::HashInput, str: &str) -> Vec<u8> {
        self.hash(input, &str.as_bytes())
    }

    fn hash_hex(&self, input: Self::HashInput, bytes: &[u8]) -> String {
        self.hash(input, bytes).encode_hex()
    }

    fn hash_str_hex(&self, input: Self::HashInput, str: &str) -> String {
        self.hash_str(input, str).encode_hex()
    }
}
