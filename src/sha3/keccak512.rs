// External imports
use sha3::{Digest, Keccak512};

// Internal imports
use crate::error::HshResult;
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Keccak512Hasher;

impl Hasher for Keccak512Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HshResult<HashOutput> {
        let mut hasher = Keccak512::new();
        hasher.update(bytes);
        Ok(HashOutput::new(hasher.finalize()))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_keccak512_hash_password() {
        let password = "password";

        let hash = Keccak512Hasher.hash_str((), password).unwrap();

        assert_eq!("a6818b8188b36c44d17784c5551f63accc5deaf8786f9d0ad1ae3cd8d887cbab4f777286dbb315fb14854c8774dc0d10b5567e4a705536cc2a1d61ec0a16a7a6", hash.as_hex());
    }

    #[test]
    fn test_keccak512_hash_bytes() {
        let bytes = b"password";

        let hash = Keccak512Hasher.hash((), bytes).unwrap();

        assert_eq!("a6818b8188b36c44d17784c5551f63accc5deaf8786f9d0ad1ae3cd8d887cbab4f777286dbb315fb14854c8774dc0d10b5567e4a705536cc2a1d61ec0a16a7a6", hash.as_hex());
    }

    proptest! {
        #[test]
        fn fuzz_keccak512_hash_does_not_panic(pass in ".*") {
            let _ = Keccak512Hasher.hash_str((), &pass);
        }

        #[test]
        fn fuzz_keccak512_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = Keccak512Hasher.hash((), &bytes);
        }

        #[test]
        fn fuzz_keccak512_hash_returns_ok(pass in ".*") {
            Keccak512Hasher.hash_str((), &pass).unwrap();
        }

        #[test]
        fn fuzz_keccak512_hash_bytes_returns_ok(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            Keccak512Hasher.hash((), &bytes).unwrap();
        }
    }
}
