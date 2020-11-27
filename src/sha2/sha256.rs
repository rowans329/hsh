// External imports
use sha2::{Digest, Sha256};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Sha256Hasher;

impl Hasher for Sha256Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_sha256_hash_password() {
        let password = "password";

        let hash = Sha256Hasher.hash_str((), password);

        assert_eq!("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", hash.as_hex());
    }

    #[test]
    fn test_sha256_hash_bytes() {
        let bytes = b"password";

        let hash = Sha256Hasher.hash((), bytes);

        assert_eq!("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8", hash.as_hex());
    }

    proptest! {
        #[test]
        fn fuzz_sha256_hash_does_not_panic(pass in ".*") {
            let _ = Sha256Hasher.hash_str((), &pass);
        }

        #[test]
        fn fuzz_sha256_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = Sha256Hasher.hash((), &bytes);
        }
    }
}
