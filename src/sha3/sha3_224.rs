// External imports
use sha3::{Digest, Sha3_224};

// Internal imports
use crate::error::HshResult;
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Sha3_224Hasher;

impl Hasher for Sha3_224Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HshResult<HashOutput> {
        let mut hasher = Sha3_224::new();
        hasher.update(bytes);
        Ok(HashOutput::new(hasher.finalize()))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_sha3_224_hash_password() {
        let password = "password";

        let hash = Sha3_224Hasher.hash_str((), password).unwrap();

        assert_eq!(
            "c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c",
            hash.as_hex()
        );
    }

    #[test]
    fn test_sha3_224_hash_bytes() {
        let bytes = b"password";

        let hash = Sha3_224Hasher.hash((), bytes).unwrap();

        assert_eq!(
            "c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c",
            hash.as_hex()
        );
    }

    proptest! {
        #[test]
        fn fuzz_sha3_224_hash_does_not_panic(pass in ".*") {
            let _ = Sha3_224Hasher.hash_str((), &pass);
        }

        #[test]
        fn fuzz_sha3_224_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = Sha3_224Hasher.hash((), &bytes);
        }

        #[test]
        fn fuzz_sha3_224_hash_returns_ok(pass in ".*") {
            Sha3_224Hasher.hash_str((), &pass).unwrap();
        }

        #[test]
        fn fuzz_sha3_224_hash_bytes_returns_ok(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            Sha3_224Hasher.hash((), &bytes).unwrap();
        }
    }
}
