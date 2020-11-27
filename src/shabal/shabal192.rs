// External imports
use shabal::{Digest, Shabal192};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Shabal192Hasher;

impl Hasher for Shabal192Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Shabal192::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_shabal192_hash_password() {
        let password = "password";

        let hash = Shabal192Hasher.hash_str((), password);

        assert_eq!("50d3d99549fc5f75bfae91e632f551a6bec000a3c3a5cfe7", hash.as_hex());
    }

    #[test]
    fn test_shabal192_hash_bytes() {
        let bytes = b"password";

        let hash = Shabal192Hasher.hash((), bytes);

        assert_eq!("50d3d99549fc5f75bfae91e632f551a6bec000a3c3a5cfe7", hash.as_hex());
    }

    proptest! {
        #[test]
        fn fuzz_shabal192_hash_does_not_panic(pass in ".*") {
            let _ = Shabal192Hasher.hash_str((), &pass);
        }

        #[test]
        fn fuzz_shabal192_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = Shabal192Hasher.hash((), &bytes);
        }
    }
}
