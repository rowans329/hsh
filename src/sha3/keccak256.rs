// External imports
use sha3::{Digest, Keccak256};

// Internal imports
use crate::error::HshResult;
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Keccak256Hasher;

impl Hasher for Keccak256Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HshResult<HashOutput> {
        let mut hasher = Keccak256::new();
        hasher.update(bytes);
        Ok(HashOutput::new(hasher.finalize()))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_keccak256_hash_password() {
        let password = "password";

        let hash = Keccak256Hasher.hash_str((), password).unwrap();

        assert_eq!(
            "b68fe43f0d1a0d7aef123722670be50268e15365401c442f8806ef83b612976b",
            hash.as_hex()
        );
    }

    #[test]
    fn test_keccak256_hash_bytes() {
        let bytes = b"password";

        let hash = Keccak256Hasher.hash((), bytes).unwrap();

        assert_eq!(
            "b68fe43f0d1a0d7aef123722670be50268e15365401c442f8806ef83b612976b",
            hash.as_hex()
        );
    }

    proptest! {
        #[test]
        fn fuzz_keccak256_hash_does_not_panic(pass in ".*") {
            let _ = Keccak256Hasher.hash_str((), &pass);
        }

        #[test]
        fn fuzz_keccak256_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = Keccak256Hasher.hash((), &bytes);
        }

        #[test]
        fn fuzz_keccak256_hash_returns_ok(pass in ".*") {
            Keccak256Hasher.hash_str((), &pass).unwrap();
        }

        #[test]
        fn fuzz_keccak256_hash_bytes_returns_ok(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            Keccak256Hasher.hash((), &bytes).unwrap();
        }
    }
}
