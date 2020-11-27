// External imports
use sha1::{Digest, Sha1};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Sha1Hasher;

impl Hasher for Sha1Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Sha1::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_sha1_hash_password() {
        let password = "password";

        let hash = Sha1Hasher.hash_str((), password);

        assert_eq!("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", hash.as_hex());
    }

    #[test]
    fn test_sha1_hash_bytes() {
        let bytes = b"password";

        let hash = Sha1Hasher.hash((), bytes);

        assert_eq!("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8", hash.as_hex());
    }

    proptest! {
        #[test]
        fn fuzz_sha1_hash_does_not_panic(pass in ".*") {
            let _ = Sha1Hasher.hash_str((), &pass);
        }

        #[test]
        fn fuzz_sha1_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = Sha1Hasher.hash((), &bytes);
        }
    }
}
