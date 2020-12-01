// External imports
use streebog::{Digest, Streebog256};

// Internal imports
use crate::error::HshResult;
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Streebog256Hasher;

impl Hasher for Streebog256Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HshResult<HashOutput> {
        let mut hasher = Streebog256::new();
        hasher.update(bytes);
        Ok(HashOutput::new(hasher.finalize()))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_streebog256_hash_password() {
        let password = "password";

        let hash = Streebog256Hasher.hash_str((), password).unwrap();

        assert_eq!(
            "568c150cc0d9a006cf9c4f280a427686e8f46c543ada3dabe83199dd8fa82141",
            hash.as_hex()
        );
    }

    #[test]
    fn test_streebog256_hash_bytes() {
        let bytes = b"password";

        let hash = Streebog256Hasher.hash((), bytes).unwrap();

        assert_eq!(
            "568c150cc0d9a006cf9c4f280a427686e8f46c543ada3dabe83199dd8fa82141",
            hash.as_hex()
        );
    }

    proptest! {
        #[test]
        fn fuzz_streebog256_hash_does_not_panic(pass in ".*") {
            let _ = Streebog256Hasher.hash_str((), &pass);
        }

        #[test]
        fn fuzz_streebog256_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = Streebog256Hasher.hash((), &bytes);
        }

        #[test]
        fn fuzz_streebog256_hash_returns_ok(pass in ".*") {
            Streebog256Hasher.hash_str((), &pass).unwrap();
        }

        #[test]
        fn fuzz_streebog256_hash_bytes_returns_ok(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            Streebog256Hasher.hash((), &bytes).unwrap();
        }
    }
}
