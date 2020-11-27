// External imports
use md4::{Digest, Md4};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Md4Hasher;

impl Hasher for Md4Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Md4::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_md4_hash_password() {
        let password = "password";

        let hash = Md4Hasher.hash_str((), password);

        assert_eq!("8a9d093f14f8701df17732b2bb182c74", hash.as_hex());
    }

    #[test]
    fn test_md4_hash_bytes() {
        let bytes = b"password";

        let hash = Md4Hasher.hash((), bytes);

        assert_eq!("8a9d093f14f8701df17732b2bb182c74", hash.as_hex());
    }

    proptest! {
        #[test]
        fn fuzz_md4_hash_does_not_panic(pass in ".*") {
            let _ = Md4Hasher.hash_str((), &pass);
        }

        #[test]
        fn fuzz_md4_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = Md4Hasher.hash((), &bytes);
        }
    }
}
