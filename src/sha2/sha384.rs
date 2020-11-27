// External imports
use sha2::{Digest, Sha384};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Sha384Hasher;

impl Hasher for Sha384Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Sha384::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_sha384_hash_password() {
        let password = "password";

        let hash = Sha384Hasher.hash_str((), password);

        assert_eq!("a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7", hash.as_hex());
    }

    #[test]
    fn test_sha384_hash_bytes() {
        let bytes = b"password";

        let hash = Sha384Hasher.hash((), bytes);

        assert_eq!("a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7", hash.as_hex());
    }

    proptest! {
        #[test]
        fn fuzz_sha384_hash_does_not_panic(pass in ".*") {
            let _ = Sha384Hasher.hash_str((), &pass);
        }

        #[test]
        fn fuzz_sha384_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = Sha384Hasher.hash((), &bytes);
        }
    }
}
