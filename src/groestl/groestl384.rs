// External imports
use groestl::{Digest, Groestl384};

// Internal imports
use crate::error::HshResult;
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Groestl384Hasher;

impl Hasher for Groestl384Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HshResult<HashOutput> {
        let mut hasher = Groestl384::new();
        hasher.update(bytes);
        Ok(HashOutput::new(hasher.finalize()))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_groestl384_hash_password() {
        let password = "password";

        let hash = Groestl384Hasher.hash_str((), password).unwrap();

        assert_eq!("689cc12d7c232ab2503cc596b4973ea1e7b75361cfbbfd947c92ef02b65b5b1ca71c4391d3c50f3d092481d6ba459b13", hash.as_hex());
    }

    #[test]
    fn test_groestl384_hash_bytes() {
        let bytes = b"password";

        let hash = Groestl384Hasher.hash((), bytes).unwrap();

        assert_eq!("689cc12d7c232ab2503cc596b4973ea1e7b75361cfbbfd947c92ef02b65b5b1ca71c4391d3c50f3d092481d6ba459b13", hash.as_hex());
    }

    proptest! {
        #[test]
        fn fuzz_groestl384_hash_does_not_panic(pass in ".*") {
            let _ = Groestl384Hasher.hash_str((), &pass);
        }

        #[test]
        fn fuzz_groestl384_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = Groestl384Hasher.hash((), &bytes);
        }

        #[test]
        fn fuzz_groestl384_hash_returns_ok(pass in ".*") {
            Groestl384Hasher.hash_str((), &pass).unwrap();
        }

        #[test]
        fn fuzz_groestl384_hash_bytes_returns_ok(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            Groestl384Hasher.hash((), &bytes).unwrap();
        }
    }
}
