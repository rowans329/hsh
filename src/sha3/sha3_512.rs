// External imports
use sha3::{Digest, Sha3_512};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Sha3_512Hasher;

impl Hasher for Sha3_512Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Sha3_512::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_sha3_512_hash_password() {
        let password = "password";

        let hash = Sha3_512Hasher.hash_str((), password);

        assert_eq!("e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716", hash.as_hex());
    }

    #[test]
    fn test_sha3_512_hash_bytes() {
        let bytes = b"password";

        let hash = Sha3_512Hasher.hash((), bytes);

        assert_eq!("e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68afea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e6368c1a62e909716", hash.as_hex());
    }

    proptest! {
        #[test]
        fn fuzz_sha3_512_hash_does_not_panic(pass in ".*") {
            let _ = Sha3_512Hasher.hash_str((), &pass);
        }

        #[test]
        fn fuzz_sha3_512_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = Sha3_512Hasher.hash((), &bytes);
        }
    }
}
