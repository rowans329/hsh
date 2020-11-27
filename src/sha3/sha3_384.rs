// External imports
use sha3::{Digest, Sha3_384};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Sha3_384Hasher;

impl Hasher for Sha3_384Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Sha3_384::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_sha3_384_hash_password() {
        let password = "password";

        let hash = Sha3_384Hasher.hash_str((), password);

        assert_eq!("9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc", hash.as_hex());
    }

    #[test]
    fn test_sha3_384_hash_bytes() {
        let bytes = b"password";

        let hash = Sha3_384Hasher.hash((), bytes);

        assert_eq!("9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368fd00b85ead506eefa90702673d873cb2c9357eafc", hash.as_hex());
    }

    proptest! {
        #[test]
        fn fuzz_sha3_384_hash_does_not_panic(pass in ".*") {
            let _ = Sha3_384Hasher.hash_str((), &pass);
        }

        #[test]
        fn fuzz_sha3_384_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = Sha3_384Hasher.hash((), &bytes);
        }
    }
}
