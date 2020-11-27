// External imports
use gost94::{Digest, Gost94CryptoPro, Gost94Test};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

#[derive(Clone, Debug)]
pub enum SBox {
    Test,
    CryptoPro,
}

pub struct Gost94Hasher;

impl Hasher for Gost94Hasher {
    type HashInput = SBox;

    fn hash(&self, input: SBox, bytes: &[u8]) -> HashOutput {
        match input {
            SBox::Test => {
                let mut hasher = Gost94Test::new();
                hasher.update(bytes);
                HashOutput::new(hasher.finalize())
            }
            SBox::CryptoPro => {
                let mut hasher = Gost94CryptoPro::new();
                hasher.update(bytes);
                HashOutput::new(hasher.finalize())
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_gost94_hash_password_test_params() {
        let password = "password";

        let hash = Gost94Hasher.hash_str(SBox::Test, password);

        assert_eq!(
            "db4d9992897eda89b50f1d3208db607902da7e79c6f3bc6e6933cc5919068564",
            hash.as_hex()
        );
    }

    #[test]
    fn test_gost94_hash_password_crypto_pro() {
        let password = "password";

        let hash = Gost94Hasher.hash_str(SBox::CryptoPro, password);

        assert_eq!(
            "9de785f479c3d3b2ababef7f4738817e10b656f854e64d023ec58931d2464d8f",
            hash.as_hex()
        );
    }

    #[test]
    fn test_gost94_hash_bytes_test_params() {
        let bytes = b"password";

        let hash = Gost94Hasher.hash(SBox::Test, bytes);

        assert_eq!(
            "db4d9992897eda89b50f1d3208db607902da7e79c6f3bc6e6933cc5919068564",
            hash.as_hex()
        );
    }

    #[test]
    fn test_gost94_hash_bytes_crypto_pro() {
        let bytes = b"password";

        let hash = Gost94Hasher.hash(SBox::CryptoPro, bytes);

        assert_eq!(
            "9de785f479c3d3b2ababef7f4738817e10b656f854e64d023ec58931d2464d8f",
            hash.as_hex()
        );
    }

    proptest! {
        #[test]
        fn fuzz_gost94_hash_does_not_panic(pass in ".*", sbox in random_sbox()) {
            let _ = Gost94Hasher.hash_str(sbox, &pass);
        }

        #[test]
        fn fuzz_gost94_hash_bytes_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000),
            sbox in random_sbox(),
        ) {
            let _ = Gost94Hasher.hash(sbox, &bytes);
        }
    }

    fn random_sbox() -> impl Strategy<Value = SBox> {
        prop_oneof![Just(SBox::Test), Just(SBox::CryptoPro),]
    }
}
