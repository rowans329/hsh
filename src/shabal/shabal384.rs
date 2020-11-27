// External imports
use shabal::{Digest, Shabal384};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Shabal384Hasher;

impl Hasher for Shabal384Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Shabal384::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_shabal384_hash_password() {
        let password = "password";

        let hash = Shabal384Hasher.hash_str((), password);

        assert_eq!("673f98958f04371edad63fe095e6903fdf894324b9944f36a6828e2b8b6dd2f4986cd4a61e29bf2866f021bbbaa02e8a", hash.as_hex());
    }

    #[test]
    fn test_shabal384_hash_bytes() {
        let bytes = b"password";

        let hash = Shabal384Hasher.hash((), bytes);

        assert_eq!("673f98958f04371edad63fe095e6903fdf894324b9944f36a6828e2b8b6dd2f4986cd4a61e29bf2866f021bbbaa02e8a", hash.as_hex());
    }

    proptest! {
        #[test]
        fn fuzz_shabal384_hash_does_not_panic(pass in ".*") {
            let _ = Shabal384Hasher.hash_str((), &pass);
        }

        #[test]
        fn fuzz_shabal384_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = Shabal384Hasher.hash((), &bytes);
        }
    }
}
