// External imports
use shabal::{Digest, Shabal224};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Shabal224Hasher;

impl Hasher for Shabal224Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Shabal224::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_shabal224_hash_password() {
        let password = "password";

        let hash = Shabal224Hasher.hash_str((), password);

        assert_eq!(
            "d2d9053f6c23d9d34e008f8f6b3fbf023370f05371315b406a45771f",
            hash.as_hex()
        );
    }

    #[test]
    fn test_shabal224_hash_bytes() {
        let bytes = b"password";

        let hash = Shabal224Hasher.hash((), bytes);

        assert_eq!(
            "d2d9053f6c23d9d34e008f8f6b3fbf023370f05371315b406a45771f",
            hash.as_hex()
        );
    }

    proptest! {
        #[test]
        fn fuzz_shabal224_hash_does_not_panic(pass in ".*") {
            let _ = Shabal224Hasher.hash_str((), &pass);
        }

        #[test]
        fn fuzz_shabal224_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = Shabal224Hasher.hash((), &bytes);
        }
    }
}
