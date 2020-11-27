// External imports
use sha3::{Digest, Sha3_256};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Sha3_256Hasher;

impl Hasher for Sha3_256Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Sha3_256::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_sha3_256_hash_password() {
        let password = "password";

        let hash = Sha3_256Hasher.hash_str((), password);

        assert_eq!(
            "c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484",
            hash.as_hex()
        );
    }

    #[test]
    fn test_sha3_256_hash_bytes() {
        let bytes = b"password";

        let hash = Sha3_256Hasher.hash((), bytes);

        assert_eq!(
            "c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484",
            hash.as_hex()
        );
    }

    proptest! {
        #[test]
        fn fuzz_sha3_256_hash_does_not_panic(pass in ".*") {
            let _ = Sha3_256Hasher.hash_str((), &pass);
        }

        #[test]
        fn fuzz_sha3_256_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = Sha3_256Hasher.hash((), &bytes);
        }
    }
}
