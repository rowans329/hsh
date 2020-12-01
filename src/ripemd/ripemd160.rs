// External imports
use ripemd160::{Digest, Ripemd160};

// Internal imports
use crate::error::HshResult;
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Ripemd160Hasher;

impl Hasher for Ripemd160Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HshResult<HashOutput> {
        let mut hasher = Ripemd160::new();
        hasher.update(bytes);
        Ok(HashOutput::new(hasher.finalize()))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_ripemd160_hash_password() {
        let password = "password";

        let hash = Ripemd160Hasher.hash_str((), password).unwrap();

        assert_eq!("2c08e8f5884750a7b99f6f2f342fc638db25ff31", hash.as_hex());
    }

    #[test]
    fn test_ripemd160_hash_bytes() {
        let bytes = b"password";

        let hash = Ripemd160Hasher.hash((), bytes).unwrap();

        assert_eq!("2c08e8f5884750a7b99f6f2f342fc638db25ff31", hash.as_hex());
    }

    proptest! {
        #[test]
        fn fuzz_ripemd160_hash_does_not_panic(pass in ".*") {
            let _ = Ripemd160Hasher.hash_str((), &pass);
        }

        #[test]
        fn fuzz_ripemd160_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = Ripemd160Hasher.hash((), &bytes);
        }

        #[test]
        fn fuzz_ripemd160_hash_returns_ok(pass in ".*") {
            Ripemd160Hasher.hash_str((), &pass).unwrap();
        }

        #[test]
        fn fuzz_ripemd160_hash_bytes_returns_ok(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            Ripemd160Hasher.hash((), &bytes).unwrap();
        }
    }
}
