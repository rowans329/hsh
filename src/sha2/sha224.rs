// External imports
use sha2::{Digest, Sha224};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Sha224Hasher;

impl Hasher for Sha224Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Sha224::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_sha224_hash_password() {
        let password = "password";

        let hash = Sha224Hasher.hash_str((), password);

        assert_eq!("d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01", hash.as_hex());
    }

    #[test]
    fn test_sha224_hash_bytes() {
        let bytes = b"password";

        let hash = Sha224Hasher.hash((), bytes);

        assert_eq!("d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01", hash.as_hex());
    }

    proptest! {
        #[test]
        fn fuzz_sha224_hash_does_not_panic(pass in ".*") {
            let _ = Sha224Hasher.hash_str((), &pass);
        }

        #[test]
        fn fuzz_sha224_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = Sha224Hasher.hash((), &bytes);
        }
    }
}
