// External imports
use md2::{Digest, Md2};

// Internal imports
use crate::error::HshResult;
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Md2Hasher;

impl Hasher for Md2Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HshResult<HashOutput> {
        let mut hasher = Md2::new();
        hasher.update(bytes);
        Ok(HashOutput::new(hasher.finalize()))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_md2_hash_password() {
        let password = "password";

        let hash = Md2Hasher.hash_str((), password).unwrap();

        assert_eq!("f03881a88c6e39135f0ecc60efd609b9", hash.as_hex());
    }

    #[test]
    fn test_md2_hash_bytes() {
        let bytes = b"password";

        let hash = Md2Hasher.hash((), bytes).unwrap();

        assert_eq!("f03881a88c6e39135f0ecc60efd609b9", hash.as_hex());
    }

    proptest! {
        #[test]
        fn fuzz_md2_hash_does_not_panic(pass in ".*") {
            let _ = Md2Hasher.hash_str((), &pass);
        }

        #[test]
        fn fuzz_md2_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = Md2Hasher.hash((), &bytes);
        }

        #[test]
        fn fuzz_md2_hash_returns_ok(pass in ".*") {
            Md2Hasher.hash_str((), &pass).unwrap();
        }

        #[test]
        fn fuzz_md2_hash_bytes_returns_ok(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            Md2Hasher.hash((), &bytes).unwrap();
        }
    }
}
