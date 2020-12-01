// External imports
use shabal::{Digest, Shabal512};

// Internal imports
use crate::error::HshResult;
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Shabal512Hasher;

impl Hasher for Shabal512Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HshResult<HashOutput> {
        let mut hasher = Shabal512::new();
        hasher.update(bytes);
        Ok(HashOutput::new(hasher.finalize()))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_shabal512_hash_password() {
        let password = "password";

        let hash = Shabal512Hasher.hash_str((), password).unwrap();

        assert_eq!("5bd02e3b4f473505d82df934449933a867d6a6667ce2ef1a2723599bbb0d134f6de5bf19dccd31c841d70192634aba67a19b29dfa51ffc5e958cebf50a919223", hash.as_hex());
    }

    #[test]
    fn test_shabal512_hash_bytes() {
        let bytes = b"password";

        let hash = Shabal512Hasher.hash((), bytes).unwrap();

        assert_eq!("5bd02e3b4f473505d82df934449933a867d6a6667ce2ef1a2723599bbb0d134f6de5bf19dccd31c841d70192634aba67a19b29dfa51ffc5e958cebf50a919223", hash.as_hex());
    }

    proptest! {
        #[test]
        fn fuzz_shabal512_hash_does_not_panic(pass in ".*") {
            let _ = Shabal512Hasher.hash_str((), &pass);
        }

        #[test]
        fn fuzz_shabal512_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = Shabal512Hasher.hash((), &bytes);
        }

        #[test]
        fn fuzz_shabal512_hash_returns_ok(pass in ".*") {
            Shabal512Hasher.hash_str((), &pass).unwrap();
        }

        #[test]
        fn fuzz_shabal512_hash_bytes_returns_ok(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            Shabal512Hasher.hash((), &bytes).unwrap();
        }
    }
}
