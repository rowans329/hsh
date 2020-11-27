// External imports
use groestl::{Digest, Groestl224};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Groestl224Hasher;

impl Hasher for Groestl224Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Groestl224::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_groestl224_hash_password() {
        let password = "password";

        let hash = Groestl224Hasher.hash_str((), password);

        assert_eq!("dbe1a8a95773766b4e80a4ab34232dfb63a23253106896c83c2edb45", hash.as_hex());
    }

    #[test]
    fn test_groestl224_hash_bytes() {
        let bytes = b"password";

        let hash = Groestl224Hasher.hash((), bytes);

        assert_eq!("dbe1a8a95773766b4e80a4ab34232dfb63a23253106896c83c2edb45", hash.as_hex());
    }

    proptest! {
        #[test]
        fn fuzz_groestl224_hash_does_not_panic(pass in ".*") {
            let _ = Groestl224Hasher.hash_str((), &pass);
        }

        #[test]
        fn fuzz_groestl224_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = Groestl224Hasher.hash((), &bytes);
        }
    }
}
