// External imports
use sha3::{Digest, Keccak256Full};

// Internal imports
use crate::error::HshResult;
use crate::hasher::Hasher;
use crate::types::HashOutput;

pub struct Keccak256FullHasher;

impl Hasher for Keccak256FullHasher {
    type HashInput = ();

    fn hash(&self, _input: (), bytes: &[u8]) -> HshResult<HashOutput> {
        let mut hasher = Keccak256Full::new();
        hasher.update(bytes);
        Ok(HashOutput::new(hasher.finalize()))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_keccak256_full_hash_password() {
        let password = "password";

        let hash = Keccak256FullHasher.hash_str((), password).unwrap();

        assert_eq!("b68fe43f0d1a0d7aef123722670be50268e15365401c442f8806ef83b612976b35076a9404c654b79f6590d0c41e130dabc93bdc37397e1d0bf1921c3c5a267332e2ceca4535a6f04ea73f2986cec5dcafc05b7d4b5495ab5fb1aaf3650f0713c7d9280508b3c9271698856e7521f8d91e0ad1d83f44a133c4db87ecb4af53b53868807dd3c1827acf2b2cccfcb2cb69e337d98eb56fecd2559310b9dd015bed94c993c0cad1bf73a328f6891c1b29c4935ed787fa9ef40b860eab776ff77f4a870966e58c894687", hash.as_hex());
    }

    #[test]
    fn test_keccak256_full_hash_bytes() {
        let bytes = b"password";

        let hash = Keccak256FullHasher.hash((), bytes).unwrap();

        assert_eq!("b68fe43f0d1a0d7aef123722670be50268e15365401c442f8806ef83b612976b35076a9404c654b79f6590d0c41e130dabc93bdc37397e1d0bf1921c3c5a267332e2ceca4535a6f04ea73f2986cec5dcafc05b7d4b5495ab5fb1aaf3650f0713c7d9280508b3c9271698856e7521f8d91e0ad1d83f44a133c4db87ecb4af53b53868807dd3c1827acf2b2cccfcb2cb69e337d98eb56fecd2559310b9dd015bed94c993c0cad1bf73a328f6891c1b29c4935ed787fa9ef40b860eab776ff77f4a870966e58c894687", hash.as_hex());
    }

    proptest! {
        #[test]
        fn fuzz_keccak256_full_hash_does_not_panic(pass in ".*") {
            let _ = Keccak256FullHasher.hash_str((), &pass);
        }

        #[test]
        fn fuzz_keccak256_full_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = Keccak256FullHasher.hash((), &bytes);
        }

        #[test]
        fn fuzz_keccak256_full_hash_returns_ok(pass in ".*") {
            Keccak256FullHasher.hash_str((), &pass).unwrap();
        }

        #[test]
        fn fuzz_keccak256_full_hash_bytes_returns_ok(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            Keccak256FullHasher.hash((), &bytes).unwrap();
        }
    }
}
