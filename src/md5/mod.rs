// External imports
use md5::{Digest, Md5};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Md5Hasher;

impl Hasher for Md5Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Md5::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_md5_hash_password() {
        let password = "password";

        let hash = Md5Hasher.hash_str((), password);

        assert_eq!("5f4dcc3b5aa765d61d8327deb882cf99", hash.as_hex());
    }

    #[test]
    fn test_md5_hash_bytes() {
        let bytes = b"password";

        let hash = Md5Hasher.hash((), bytes);

        assert_eq!("5f4dcc3b5aa765d61d8327deb882cf99", hash.as_hex());
    }

    proptest! {
        #[test]
        fn fuzz_md5_hash_does_not_panic(pass in ".*") {
            let _ = Md5Hasher.hash_str((), &pass);
        }

        #[test]
        fn fuzz_md5_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = Md5Hasher.hash((), &bytes);
        }
    }
}
