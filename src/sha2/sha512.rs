// External imports
use sha2::{Digest, Sha512};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Sha512Hasher;

impl Hasher for Sha512Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Sha512::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_sha512_hash_password() {
        let password = "password";

        let hash = Sha512Hasher.hash_str((), password);

        assert_eq!("b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86", hash.as_hex());
    }

    #[test]
    fn test_sha512_hash_bytes() {
        let bytes = b"password";

        let hash = Sha512Hasher.hash((), bytes);

        assert_eq!("b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86", hash.as_hex());
    }

    proptest! {
        #[test]
        fn fuzz_sha512_hash_does_not_panic(pass in ".*") {
            let _ = Sha512Hasher.hash_str((), &pass);
        }

        #[test]
        fn fuzz_sha512_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = Sha512Hasher.hash((), &bytes);
        }
    }
}
