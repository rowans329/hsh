// External imports
use sha3::{Digest, Keccak224};

// Internal imports
use crate::error::HshResult;
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Keccak224Hasher;

impl Hasher for Keccak224Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HshResult<HashOutput> {
        let mut hasher = Keccak224::new();
        hasher.update(bytes);
        Ok(HashOutput::new(hasher.finalize()))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_keccak224_hash_password() {
        let password = "password";

        let hash = Keccak224Hasher.hash_str((), password).unwrap();

        assert_eq!(
            "12cfa398e1a905fe361713aa798b5a77655980cee83b4dd57ec8c595",
            hash.as_hex()
        );
    }

    #[test]
    fn test_keccak224_hash_bytes() {
        let bytes = b"password";

        let hash = Keccak224Hasher.hash((), bytes).unwrap();

        assert_eq!(
            "12cfa398e1a905fe361713aa798b5a77655980cee83b4dd57ec8c595",
            hash.as_hex()
        );
    }

    proptest! {
        #[test]
        fn fuzz_keccak224_hash_does_not_panic(pass in ".*") {
            let _ = Keccak224Hasher.hash_str((), &pass);
        }

        #[test]
        fn fuzz_keccak224_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = Keccak224Hasher.hash((), &bytes);
        }

        #[test]
        fn fuzz_keccak224_hash_returns_ok(pass in ".*") {
            Keccak224Hasher.hash_str((), &pass).unwrap();
        }

        #[test]
        fn fuzz_keccak224_hash_bytes_returns_ok(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            Keccak224Hasher.hash((), &bytes).unwrap();
        }
    }
}
