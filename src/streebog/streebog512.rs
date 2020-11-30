// External imports
use streebog::{Digest, Streebog512};

// Internal imports
use crate::error::HshResult;
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Streebog512Hasher;

impl Hasher for Streebog512Hasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HshResult<HashOutput> {
        let mut hasher = Streebog512::new();
        hasher.update(bytes);
        Ok(HashOutput::new(hasher.finalize()))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_streebog512_hash_password() {
        let password = "password";

        let hash = Streebog512Hasher.hash_str((), password).unwrap();

        assert_eq!("1c0fe130cdde2e5018892d7749f859ab65858a19312174427576717694352734c53ba393b5ef475ee4c49f26ccd489b35cc4c72ce511b5a67e6f19e95d69db43", hash.as_hex());
    }

    #[test]
    fn test_streebog512_hash_bytes() {
        let bytes = b"password";

        let hash = Streebog512Hasher.hash((), bytes).unwrap();

        assert_eq!("1c0fe130cdde2e5018892d7749f859ab65858a19312174427576717694352734c53ba393b5ef475ee4c49f26ccd489b35cc4c72ce511b5a67e6f19e95d69db43", hash.as_hex());
    }

    proptest! {
        #[test]
        fn fuzz_streebog512_hash_does_not_panic(pass in ".*") {
            let _ = Streebog512Hasher.hash_str((), &pass);
        }

        #[test]
        fn fuzz_streebog512_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = Streebog512Hasher.hash((), &bytes);
        }

        #[test]
        fn fuzz_streebog512_hash_returns_ok(pass in ".*") {
            Streebog512Hasher.hash_str((), &pass).unwrap();
        }

        #[test]
        fn fuzz_streebog512_hash_bytes_returns_ok(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            Streebog512Hasher.hash((), &bytes).unwrap();
        }
    }
}
