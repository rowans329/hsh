// External imports
use ripemd320::{Digest, Ripemd320};

// Internal imports
use crate::error::HshResult;
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Ripemd320Hasher;

impl Hasher for Ripemd320Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HshResult<HashOutput> {
        let mut hasher = Ripemd320::new();
        hasher.update(bytes);
        Ok(HashOutput::new(hasher.finalize()))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_ripemd320_hash_password() {
        let password = "password";

        let hash = Ripemd320Hasher.hash_str((), password).unwrap();

        assert_eq!(
            "c571d82e535de67ff5f87e417b3d53125f2d83ed7598b89d74483e6c0dfe8d86e88b380249fc8fb4",
            hash.as_hex()
        );
    }

    #[test]
    fn test_ripemd320_hash_bytes() {
        let bytes = b"password";

        let hash = Ripemd320Hasher.hash((), bytes).unwrap();

        assert_eq!(
            "c571d82e535de67ff5f87e417b3d53125f2d83ed7598b89d74483e6c0dfe8d86e88b380249fc8fb4",
            hash.as_hex()
        );
    }

    proptest! {
        #[test]
        fn fuzz_ripemd320_hash_does_not_panic(pass in ".*") {
            let _ = Ripemd320Hasher.hash_str((), &pass);
        }

        #[test]
        fn fuzz_ripemd320_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = Ripemd320Hasher.hash((), &bytes);
        }

        #[test]
        fn fuzz_ripemd320_hash_returns_ok(pass in ".*") {
            Ripemd320Hasher.hash_str((), &pass).unwrap();
        }

        #[test]
        fn fuzz_ripemd320_hash_bytes_returns_ok(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            Ripemd320Hasher.hash((), &bytes).unwrap();
        }
    }
}
