// External imports
use groestl::{Digest, Groestl512};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Groestl512Hasher;

impl Hasher for Groestl512Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HashOutput {
        let mut hasher = Groestl512::new();
        hasher.update(bytes);
        HashOutput::new(hasher.finalize())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_groestl512_hash_password() {
        let password = "password";

        let hash = Groestl512Hasher.hash_str((), password);

        assert_eq!("ced825c4699fc51ff75c3031357994e7abaa94b38a5e037cfd075021a9dba00fc54c586eb0b7cb01fede27f6b61dde292f5a7e8ab42ccbd11bef8b538119750d", hash.as_hex());
    }

    #[test]
    fn test_groestl512_hash_bytes() {
        let bytes = b"password";

        let hash = Groestl512Hasher.hash((), bytes);

        assert_eq!("ced825c4699fc51ff75c3031357994e7abaa94b38a5e037cfd075021a9dba00fc54c586eb0b7cb01fede27f6b61dde292f5a7e8ab42ccbd11bef8b538119750d", hash.as_hex());
    }

    proptest! {
        #[test]
        fn fuzz_groestl512_hash_does_not_panic(pass in ".*") {
            let _ = Groestl512Hasher.hash_str((), &pass);
        }

        #[test]
        fn fuzz_groestl512_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = Groestl512Hasher.hash((), &bytes);
        }
    }
}
