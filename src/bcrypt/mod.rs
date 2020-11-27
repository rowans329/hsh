// Std imports
use std::str::FromStr;

// Internal imports
use crate::error::{HshErr, HshResult};
use crate::hasher::Hasher;
use crate::types::HashOutput;

#[derive(Clone, Debug, PartialEq)]
pub struct Salt([u8; 16]);

impl Salt {
    pub fn new(data: [u8; 16]) -> Self {
        Self(data)
    }

    pub fn from_vec(data: Vec<u8>) -> HshResult<Self> {
        if data.len() != 16 {
            return Err(HshErr::InvalidSalt(format!(
                "incorrect salt length (should be 16 bytes, found {})",
                data.len()
            )));
        }

        let mut arr = [0u8; 16];

        for (i, v) in data.iter().enumerate() {
            arr[i] = *v;
        }

        Ok(Self::new(arr))
    }
}

impl FromStr for Salt {
    type Err = HshErr;

    fn from_str(str: &str) -> HshResult<Salt> {
        let decoded = hex::decode(str);

        if let Err(err) = decoded {
            return Err(HshErr::InvalidSaltHex(err));
        }

        Salt::from_vec(decoded.unwrap())
    }
}

#[derive(Debug)]
pub struct BcryptInput {
    cost: u32,
    salt: Salt,
}

impl BcryptInput {
    pub fn new(cost: u32, salt: Salt) -> Self {
        BcryptInput { cost, salt }
    }
}

pub struct BcryptHasher;

impl Hasher for BcryptHasher {
    type HashInput = BcryptInput;

    fn hash(&self, input: BcryptInput, bytes: &[u8]) -> HashOutput {
        let mut hash: [u8; 24] = [0; 24];
        bcrypt::bcrypt(input.cost, &input.salt.0, bytes, &mut hash);
        HashOutput::new(hash.to_vec())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_salt_new() {
        let bytes = [7, 4, 2, 5, 7, 2, 6, 19, 1, 0, 3, 3, 6, 4, 2, 33];

        let salt = Salt::new(bytes);

        assert_eq!(bytes, salt.0);
    }

    #[test]
    fn test_salt_from_vec_valid() {
        let bytes = vec![7, 4, 2, 5, 7, 2, 6, 19, 1, 0, 3, 3, 6, 4, 2, 33];

        let salt = Salt::from_vec(bytes).unwrap();

        assert_eq!([7, 4, 2, 5, 7, 2, 6, 19, 1, 0, 3, 3, 6, 4, 2, 33], salt.0);
    }

    #[test]
    fn test_salt_from_empty_vec() {
        let bytes = vec![];

        let err = Salt::from_vec(bytes).unwrap_err();

        assert_eq!(
            HshErr::InvalidSalt(String::from(
                "incorrect salt length (should be 16 bytes, found 0)"
            )),
            err,
        )
    }

    #[test]
    fn test_salt_from_vec_long() {
        let bytes = vec![
            8, 42, 4, 0, 72, 83, 5, 4, 185, 4, 68, 42, 9, 0, 2, 84, 4, 82, 5, 216, 0, 137,
        ];

        let err = Salt::from_vec(bytes).unwrap_err();

        assert_eq!(
            HshErr::InvalidSalt(String::from(
                "incorrect salt length (should be 16 bytes, found 22)"
            )),
            err,
        );
    }

    #[test]
    fn test_salt_from_str_valid() {
        let bytes = [7, 4, 2, 5, 7, 2, 6, 19, 1, 0, 3, 3, 6, 4, 2, 33];
        let hex = hex::encode(bytes);

        let salt = Salt::from_str(&hex).unwrap();

        assert_eq!(bytes, salt.0);
    }

    #[test]
    fn test_salt_from_empty_str() {
        let hex = "";

        let err = Salt::from_str(&hex).unwrap_err();

        assert_eq!(
            HshErr::InvalidSalt(String::from(
                "incorrect salt length (should be 16 bytes, found 0)"
            )),
            err,
        )
    }

    #[test]
    fn test_salt_from_str_odd_length() {
        let hex = "a83e8f932";

        let err = Salt::from_str(&hex).unwrap_err();

        assert_eq!(HshErr::InvalidSaltHex(hex::FromHexError::OddLength), err);
    }

    #[test]
    fn test_salt_from_str_invalid_characters() {
        let hex = "an7c123'573b9VB769p/yvgwoehgi42\"";

        let err = Salt::from_str(&hex).unwrap_err();
        let err_msg = format!("{}", err);

        assert_eq!(
            "invalid salt hex -- Invalid character 'n' at position 1",
            err_msg
        );
    }

    #[test]
    fn test_salt_from_str_long() {
        let bytes = [
            8, 42, 4, 0, 72, 83, 5, 4, 185, 4, 68, 42, 9, 0, 2, 84, 4, 82, 5, 216, 0, 137,
        ];
        let hex = hex::encode(bytes);

        let err = Salt::from_str(&hex).unwrap_err();

        assert_eq!(
            HshErr::InvalidSalt(String::from(
                "incorrect salt length (should be 16 bytes, found 22)"
            )),
            err
        );
    }

    #[test]
    fn test_bcrypt_input_new() {
        let cost = 1;
        let salt = Salt::new([7, 4, 2, 5, 7, 2, 6, 19, 1, 0, 3, 3, 6, 4, 2, 33]);

        let input = BcryptInput::new(cost, salt.clone());

        assert_eq!(cost, input.cost);
        assert_eq!(salt, input.salt);
    }

    #[test]
    fn test_bcrypt_hash_password() {
        let cost = 10;
        let salt = Salt::from_str("07040205070206130100030306040221").unwrap();
        let input = BcryptInput::new(cost, salt);

        let password = "password";

        let hash = BcryptHasher.hash_str(input, password);

        assert_eq!(
            "dfcd71d5fb5c9f17bddc20eff324be2926529c01c440fcfb",
            hash.as_hex()
        );
    }

    #[test]
    fn test_bcrypt_hash_bytes() {
        let cost = 10;
        let salt = Salt::from_str("07040205070206130100030306040221").unwrap();
        let input = BcryptInput::new(cost, salt);

        let bytes = b"password";

        let hash = BcryptHasher.hash(input, bytes);

        assert_eq!(
            "dfcd71d5fb5c9f17bddc20eff324be2926529c01c440fcfb",
            hash.as_hex()
        );
    }

    proptest! {
        #[test]
        fn fuzz_salt_from_vec(vec in proptest::collection::vec(any::<u8>(), 0..1000)) {
            let len = vec.len();

            let res = Salt::from_vec(vec.clone());

            if len == 16 {
                assert_eq!(vec, res.unwrap().0.to_vec());
            } else {
                assert_eq!(
                    HshErr::InvalidSalt(format!(
                        "incorrect salt length (should be 16 bytes, found {})",
                        len
                    )),
                    res.unwrap_err(),
                )
            }
        }

        #[test]
        fn fuzz_salt_from_str_does_not_panic(str in ".*") {
            let _ = Salt::from_str(&str);
        }

        #[test]
        fn fuzz_salt_from_str_arbitrary_valid_hex(arr in [any::<u8>(); 16]) {
            let hex = hex::encode(arr);
            let salt = Salt::from_str(&hex).unwrap();
            assert_eq!(arr, salt.0);
        }

        #[test]
        fn fuzz_salt_from_str_odd_length(hex in "[0-9a-f]([0-9a-f][0-9a-f])*") {
            let err = Salt::from_str(&hex).unwrap_err();
            assert_eq!(HshErr::InvalidSaltHex(hex::FromHexError::OddLength), err);
        }

        #[test]
        fn fuzz_salt_from_str_invalid_characters(hex in "([g-zG-Z][g-zG-Z])+") {
            let err = Salt::from_str(&hex).unwrap_err();
            let err_msg = format!("{}", err);
            assert!(err_msg.contains("invalid salt hex -- Invalid character"));
        }

        #[test]
        #[ignore]
        fn fuzz_bcrypt_hash_does_not_panic(
            input in arbitrary_input(),
            pass in ".{1,72}",
        ) {
            let _ = BcryptHasher.hash_str(input, &pass);
        }

        #[test]
        #[ignore]
        fn fuzz_bcrypt_hash_bytes_does_not_panic(
            input in arbitrary_input(),
            bytes in proptest::collection::vec(any::<u8>(), 1..72),
        ) {
            let _ = BcryptHasher.hash(input, &bytes);
        }
    }

    fn arbitrary_input() -> BoxedStrategy<BcryptInput> {
        (any::<u32>(), ([any::<u8>(); 16]).prop_map(|arr| Salt(arr)))
            .prop_map(|(cost, salt)| BcryptInput::new(cost, salt))
            .boxed()
    }
}
