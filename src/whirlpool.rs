// External imports
use whirlpool::{Digest, Whirlpool};

// Internal imports
use crate::error::HshResult;
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct WhirlpoolHasher;

impl Hasher for WhirlpoolHasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HshResult<HashOutput> {
        let mut hasher = Whirlpool::new();
        hasher.update(bytes);
        Ok(HashOutput::new(hasher.finalize()))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_whirlpool_hash_password() {
        let password = "password";

        let hash = WhirlpoolHasher.hash_str((), password).unwrap();

        assert_eq!("74dfc2b27acfa364da55f93a5caee29ccad3557247eda238831b3e9bd931b01d77fe994e4f12b9d4cfa92a124461d2065197d8cf7f33fc88566da2db2a4d6eae", hash.as_hex());
    }

    #[test]
    fn test_whirlpool_hash_bytes() {
        let bytes = b"password";

        let hash = WhirlpoolHasher.hash((), bytes).unwrap();

        assert_eq!("74dfc2b27acfa364da55f93a5caee29ccad3557247eda238831b3e9bd931b01d77fe994e4f12b9d4cfa92a124461d2065197d8cf7f33fc88566da2db2a4d6eae", hash.as_hex());
    }

    proptest! {
        #[test]
        fn fuzz_whirlpool_hash_does_not_panic(pass in ".*") {
            let _ = WhirlpoolHasher.hash_str((), &pass);
        }

        #[test]
        fn fuzz_whirlpool_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = WhirlpoolHasher.hash((), &bytes);
        }

        #[test]
        fn fuzz_whirlpool_hash_returns_ok(pass in ".*") {
            WhirlpoolHasher.hash_str((), &pass).unwrap();
        }

        #[test]
        fn fuzz_whirlpool_hash_bytes_returns_ok(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            WhirlpoolHasher.hash((), &bytes).unwrap();
        }
    }
}
