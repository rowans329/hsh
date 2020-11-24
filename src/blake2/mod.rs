// External imports
use blake2::{Blake2b, Digest};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Blake2Hasher;

impl Hasher for Blake2Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Blake2b::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const HELLO_WORLD_HASH_BYTES: [u8; 64] = [
        162, 118, 77, 19, 58, 22, 129, 107, 88, 71, 167, 55, 167, 134, 242, 236, 228, 193, 72, 9,
        92, 95, 170, 115, 226, 75, 76, 197, 214, 102, 195, 228, 94, 194, 113, 80, 78, 20, 220, 97,
        39, 221, 252, 228, 225, 68, 251, 35, 185, 26, 111, 123, 4, 181, 61, 105, 85, 2, 41, 7, 34,
        149, 59, 15,
    ];

    const HELLO_WORLD_HASH_HEX: &str = "a2764d133a16816b5847a737a786f2ece4c148095c5faa73e24b4cc5d666c3e45ec271504e14dc6127ddfce4e144fb23b91a6f7b04b53d695502290722953b0f";

    #[test]
    fn blake2_hash_bytes_test() {
        let bytes = b"Hello, world!";
        let hash = Blake2Hasher.hash((), bytes);
        assert_eq!(HELLO_WORLD_HASH_BYTES.to_vec(), hash.as_bytes());
    }

    #[test]
    fn blake2_hash_string_test() {
        let string = "Hello, world!";
        let hash = Blake2Hasher.hash_str((), string);
        assert_eq!(HELLO_WORLD_HASH_BYTES.to_vec(), hash.as_bytes());
    }

    #[test]
    fn blake2_hash_bytes_hex_test() {
        let bytes = b"Hello, world!";
        let hash = Blake2Hasher.hash((), bytes);
        assert_eq!(HELLO_WORLD_HASH_HEX, hash.as_hex());
    }
    #[test]
    fn blake2_hash_string_hex_test() {
        let string = "Hello, world!";
        let hash = Blake2Hasher.hash_str((), string);
        assert_eq!(HELLO_WORLD_HASH_HEX, hash.as_hex());
    }
}
