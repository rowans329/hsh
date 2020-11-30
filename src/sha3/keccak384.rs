// External imports
use sha3::{Digest, Keccak384};

// Internal imports
use crate::error::HshResult;
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Keccak384Hasher;

impl Hasher for Keccak384Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HshResult<HashOutput> {
        let mut hasher = Keccak384::new();
        hasher.update(bytes);
        Ok(HashOutput::new(hasher.finalize()))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_keccak384_hash_password() {
        let password = "password";

        let hash = Keccak384Hasher.hash_str((), password).unwrap();

        assert_eq!("e0779e9bb200a589bc70e499a9f7db1006e181519394990ef41800bebe452c23b4a8372fd89df8d5e0d951af240be7bc", hash.as_hex());
    }

    #[test]
    fn test_keccak384_hash_bytes() {
        let bytes = b"password";

        let hash = Keccak384Hasher.hash((), bytes).unwrap();

        assert_eq!("e0779e9bb200a589bc70e499a9f7db1006e181519394990ef41800bebe452c23b4a8372fd89df8d5e0d951af240be7bc", hash.as_hex());
    }

    proptest! {
        #[test]
        fn fuzz_keccak384_hash_does_not_panic(pass in ".*") {
            let _ = Keccak384Hasher.hash_str((), &pass);
        }

        #[test]
        fn fuzz_keccak384_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = Keccak384Hasher.hash((), &bytes);
        }

        #[test]
        fn fuzz_keccak384_hash_returns_ok(pass in ".*") {
            Keccak384Hasher.hash_str((), &pass).unwrap();
        }

        #[test]
        fn fuzz_keccak384_hash_bytes_returns_ok(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            Keccak384Hasher.hash((), &bytes).unwrap();
        }
    }
}
