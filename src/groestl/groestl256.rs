// External imports
use groestl::{Digest, Groestl256};

// Internal imports
use crate::error::HshResult;
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Groestl256Hasher;

impl Hasher for Groestl256Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HshResult<HashOutput> {
        let mut hasher = Groestl256::new();
        hasher.update(bytes);
        Ok(HashOutput::new(hasher.finalize()))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_groestl256_hash_password() {
        let password = "password";

        let hash = Groestl256Hasher.hash_str((), password).unwrap();

        assert_eq!(
            "5fc07d8c8d9d54bf2733c8f3d4d2aa8b3f1603970001fc987f1cdecde18f520f",
            hash.as_hex()
        );
    }

    #[test]
    fn test_groestl256_hash_bytes() {
        let bytes = b"password";

        let hash = Groestl256Hasher.hash((), bytes).unwrap();

        assert_eq!(
            "5fc07d8c8d9d54bf2733c8f3d4d2aa8b3f1603970001fc987f1cdecde18f520f",
            hash.as_hex()
        );
    }

    proptest! {
        #[test]
        fn fuzz_groestl256_hash_does_not_panic(pass in ".*") {
            let _ = Groestl256Hasher.hash_str((), &pass);
        }

        #[test]
        fn fuzz_groestl256_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = Groestl256Hasher.hash((), &bytes);
        }

        #[test]
        fn fuzz_groestl256_hash_returns_ok(pass in ".*") {
            Groestl256Hasher.hash_str((), &pass).unwrap();
        }

        #[test]
        fn fuzz_groestl256_hash_bytes_returns_ok(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            Groestl256Hasher.hash((), &bytes).unwrap();
        }
    }
}
