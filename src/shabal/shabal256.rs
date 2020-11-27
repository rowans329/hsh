// External imports
use shabal::{Digest, Shabal256};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Shabal256Hasher;

impl Hasher for Shabal256Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Shabal256::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_shabal256_hash_password() {
        let password = "password";

        let hash = Shabal256Hasher.hash_str((), password);

        assert_eq!("efb82bf2dc681f74951a61a8795606a47d1cdf573980d3cf65a3cb3371e8e7a8", hash.as_hex());
    }

    #[test]
    fn test_shabal256_hash_bytes() {
        let bytes = b"password";

        let hash = Shabal256Hasher.hash((), bytes);

        assert_eq!("efb82bf2dc681f74951a61a8795606a47d1cdf573980d3cf65a3cb3371e8e7a8", hash.as_hex());
    }

    proptest! {
        #[test]
        fn fuzz_shabal256_hash_does_not_panic(pass in ".*") {
            let _ = Shabal256Hasher.hash_str((), &pass);
        }

        #[test]
        fn fuzz_shabal256_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = Shabal256Hasher.hash((), &bytes);
        }
    }
}
