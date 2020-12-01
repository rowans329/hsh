// External imports
use blake2::{Blake2b, Digest};

// Internal imports
use crate::error::HshResult;
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Blake2Hasher;

impl Hasher for Blake2Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HshResult<HashOutput> {
        let mut hasher = Blake2b::new();
        hasher.update(bytes);
        Ok(HashOutput::new(hasher.finalize()))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_blake2_hash_password() {
        let password = "password";

        let hash = Blake2Hasher.hash_str((), password).unwrap();

        assert_eq!("7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8", hash.as_hex());
    }

    #[test]
    fn test_blake2_hash_bytes() {
        let bytes = b"password";

        let hash = Blake2Hasher.hash((), bytes).unwrap();

        assert_eq!("7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33e67611f0a42addb8", hash.as_hex());
    }

    proptest! {
        #[test]
        fn fuzz_blake2_hash_does_not_panic(pass in ".*") {
            let _ = Blake2Hasher.hash_str((), &pass);
        }

        #[test]
        fn fuzz_blake2_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = Blake2Hasher.hash((), &bytes);
        }

        #[test]
        fn fuzz_blake2_hash_returns_ok(pass in ".*") {
            Blake2Hasher.hash_str((), &pass).unwrap();
        }

        #[test]
        fn fuzz_blake2_hash_bytes_returns_ok(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            Blake2Hasher.hash((), &bytes).unwrap();
        }
    }
}
