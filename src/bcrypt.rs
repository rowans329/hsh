// Std imports
use std::str::FromStr;

// External imports
use b64::FromBase64;
use lazy_static::lazy_static;
use regex::Regex;

// Internal imports
use crate::error::{HshError, HshResult, SaltFromStrError};
use crate::format::get_salt_format;
use crate::hasher::Hasher;
use crate::types::{Format, HashOutput};

#[derive(Clone, Debug, PartialEq)]
pub struct Salt([u8; 16]);

impl Salt {
    pub fn new(data: [u8; 16]) -> Self {
        Self(data)
    }

    pub fn from_vec(data: Vec<u8>) -> Result<Self, SaltFromStrError> {
        if data.len() != 16 {
            return Err(SaltFromStrError::IncorrectLength(16, data.len()));
        }

        let mut arr = [0u8; 16];

        for (i, v) in data.iter().enumerate() {
            arr[i] = *v;
        }

        Ok(Self::new(arr))
    }

    pub fn from_bytes(str: &str) -> Result<Self, SaltFromStrError> {
        let str = str
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .ok_or(SaltFromStrError::InvalidByteFormat)?;

        let strs = str.split(',');
        let mut bytes = Vec::with_capacity(16);

        for (i, s) in strs.enumerate() {
            let s = s.trim();
            let res = u8::from_str(s);

            if res.is_err() {
                return Err(SaltFromStrError::InvalidByte(s.to_string(), i));
            }

            bytes.push(res.unwrap());
        }

        Self::from_vec(bytes)
    }

    pub fn from_hex(str: &str) -> Result<Self, SaltFromStrError> {
        lazy_static! {
            static ref REGEX: Regex = Regex::new(r"([^0-9a-fA-F])").unwrap();
        }

        if str.len() % 2 != 0 {
            return Err(SaltFromStrError::InvalidHexLength);
        }

        let illegal_char = REGEX.find(str);
        if let Some(char) = illegal_char {
            let start = char.start();
            let char = char.as_str().chars().next().unwrap();

            return Err(SaltFromStrError::InvalidHexCharacter(char, start));
        }

        let decoded = hex::decode(str).unwrap();
        Self::from_vec(decoded)
    }

    pub fn from_base64(str: &str) -> Result<Self, SaltFromStrError> {
        lazy_static! {
            static ref REGEX: Regex = Regex::new(r"([^0-9a-zA-Z/\+=])").unwrap();
        }

        if str.len() % 4 != 0 {
            return Err(SaltFromStrError::InvalidBase64Length);
        }

        let illegal_char = REGEX.find(str);
        if let Some(char) = illegal_char {
            let start = char.start();
            let char = char.as_str().chars().next().unwrap();

            return Err(SaltFromStrError::InvalidBase64Character(char, start));
        }

        let decoded = str.from_base64().unwrap();
        Salt::from_vec(decoded)
    }
}

impl FromStr for Salt {
    type Err = HshError;

    fn from_str(str: &str) -> HshResult<Salt> {
        if str.is_empty() {
            return Err(HshError::SaltFromStrError(SaltFromStrError::BlankStr));
        }

        match get_salt_format() {
            Format::Base64 => Ok(Salt::from_base64(str)?),
            Format::Bytes => Ok(Salt::from_bytes(str)?),
            Format::Hex => Ok(Salt::from_hex(str)?),
        }
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

    fn hash(&self, input: BcryptInput, bytes: &[u8]) -> HshResult<HashOutput> {
        if bytes.is_empty() || bytes.len() > 72 {
            return Err(HshError::UnsuportedStrLength(String::from(
                "input string for bcrypt hash function must be between 0 and 72 bytes",
            )));
        }

        let mut hash: [u8; 24] = [0; 24];
        bcrypt::bcrypt(input.cost, &input.salt.0, bytes, &mut hash);

        Ok(HashOutput::new(hash.to_vec()))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::format::FORMAT_MODE;
    use crate::types::Format;
    use b64::{CharacterSet, Config, Newline, ToBase64};
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

        assert_eq!(SaltFromStrError::IncorrectLength(16, 0), err,);
    }

    #[test]
    fn test_salt_from_vec_long() {
        let bytes = vec![
            8, 42, 4, 0, 72, 83, 5, 4, 185, 4, 68, 42, 9, 0, 2, 84, 4, 82, 5, 216, 0, 137,
        ];

        let err = Salt::from_vec(bytes).unwrap_err();

        assert_eq!(SaltFromStrError::IncorrectLength(16, 22), err,);
    }

    #[test]
    fn test_salt_from_bytes_valid() {
        let bytes = "[7, 4, 2, 5, 7, 2, 6, 19, 1, 0, 3, 3, 6, 4, 2, 33]";

        let salt = Salt::from_bytes(&bytes).unwrap();

        assert_eq!([7, 4, 2, 5, 7, 2, 6, 19, 1, 0, 3, 3, 6, 4, 2, 33], salt.0);
    }

    #[test]
    fn test_salt_from_empty_bytes() {
        let bytes = "";

        let err = Salt::from_bytes(&bytes).unwrap_err();

        assert_eq!(SaltFromStrError::InvalidByteFormat, err,);
    }

    #[test]
    fn test_salt_from_bytes_invalid_bytes() {
        let bytes = "[7, 4, 2, 5, 7, 2, 6, nineteen, 1, 0, 3, 3, 6, 4, 2, 33]";

        let err = Salt::from_bytes(&bytes).unwrap_err();

        assert_eq!(
            SaltFromStrError::InvalidByte(String::from("nineteen"), 7),
            err
        );
    }

    #[test]
    fn test_salt_from_bytes_long() {
        let bytes =
            "[8, 42, 4, 0, 72, 83, 5, 4, 185, 4, 68, 42, 9, 0, 2, 84, 4, 82, 5, 216, 0, 137]";

        let err = Salt::from_bytes(&bytes).unwrap_err();

        assert_eq!(SaltFromStrError::IncorrectLength(16, 22), err,);
    }

    #[test]
    fn test_salt_from_hex_valid() {
        let bytes = [7, 4, 2, 5, 7, 2, 6, 19, 1, 0, 3, 3, 6, 4, 2, 33];
        let hex = hex::encode(bytes);

        let salt = Salt::from_hex(&hex).unwrap();

        assert_eq!(bytes, salt.0);
    }

    #[test]
    fn test_salt_from_empty_hex() {
        let hex = "";

        let err = Salt::from_hex(&hex).unwrap_err();

        assert_eq!(SaltFromStrError::IncorrectLength(16, 0), err,);
    }

    #[test]
    fn test_salt_from_hex_odd_length() {
        let hex = "a83e8f932";

        let err = Salt::from_hex(&hex).unwrap_err();

        assert_eq!(SaltFromStrError::InvalidHexLength, err);
    }

    #[test]
    fn test_salt_from_hex_invalid_characters() {
        let hex = "an7c123'573b9VB769p/yvgwoehgi42\"";

        let err = Salt::from_hex(&hex).unwrap_err();

        assert_eq!(SaltFromStrError::InvalidHexCharacter('n', 1), err);
    }

    #[test]
    fn test_salt_from_hex_long() {
        let bytes = [
            8, 42, 4, 0, 72, 83, 5, 4, 185, 4, 68, 42, 9, 0, 2, 84, 4, 82, 5, 216, 0, 137,
        ];
        let hex = hex::encode(bytes);

        let err = Salt::from_hex(&hex).unwrap_err();

        assert_eq!(SaltFromStrError::IncorrectLength(16, 22), err,);
    }

    #[test]
    fn test_salt_from_base64_valid() {
        let bytes = [7, 4, 2, 5, 7, 2, 6, 19, 1, 0, 3, 3, 6, 4, 2, 33];
        let base64 = bytes.to_base64(Config {
            char_set: CharacterSet::Standard,
            newline: Newline::LF,
            pad: true,
            line_length: None,
        });

        let salt = Salt::from_base64(&base64).unwrap();

        assert_eq!(bytes, salt.0);
    }

    #[test]
    fn test_salt_from_empty_base64() {
        let base64 = "";

        let err = Salt::from_base64(&base64).unwrap_err();

        assert_eq!(SaltFromStrError::IncorrectLength(16, 0), err,);
    }

    #[test]
    fn test_salt_from_base64_invalid_length() {
        let base64 = "a83eMf932";

        let err = Salt::from_base64(&base64).unwrap_err();

        assert_eq!(SaltFromStrError::InvalidBase64Length, err);
    }

    #[test]
    fn test_salt_from_base64_invalid_characters() {
        let base64 = "an7c123$573M9VB769p/yv+wo~ehgi42";

        let err = Salt::from_base64(&base64).unwrap_err();

        assert_eq!(SaltFromStrError::InvalidBase64Character('$', 7), err);
    }

    #[test]
    fn test_salt_from_base64_long() {
        let bytes = [
            8, 42, 4, 0, 72, 83, 5, 4, 185, 4, 68, 42, 9, 0, 2, 84, 4, 82, 5, 216, 0, 137,
        ];
        let base64 = bytes.to_base64(Config {
            char_set: CharacterSet::Standard,
            newline: Newline::LF,
            pad: true,
            line_length: None,
        });

        let err = Salt::from_base64(&base64).unwrap_err();

        assert_eq!(SaltFromStrError::IncorrectLength(16, 22), err,);
    }

    #[test]
    fn test_salt_from_str_valid_bytes() {
        FORMAT_MODE.test_with_salt_format(Format::Bytes, || {
            let bytes = "[7, 4, 2, 5, 7, 2, 6, 19, 1, 0, 3, 3, 6, 4, 2, 33]";

            let salt = Salt::from_str(&bytes).unwrap();

            assert_eq!([7, 4, 2, 5, 7, 2, 6, 19, 1, 0, 3, 3, 6, 4, 2, 33], salt.0);
        });
    }

    #[test]
    fn test_salt_from_str_empty_bytes() {
        FORMAT_MODE.test_with_salt_format(Format::Bytes, || {
            let bytes = "";

            let err = Salt::from_str(&bytes).unwrap_err();

            assert_eq!(HshError::SaltFromStrError(SaltFromStrError::BlankStr), err);
        });
    }

    #[test]
    fn test_salt_from_str_invalid_bytes() {
        FORMAT_MODE.test_with_salt_format(Format::Bytes, || {
            let bytes = "[7, 4, 2, 5, 7, 2, 6, nineteen, 1, 0, 3, 3, 6, 4, 2, 33]";

            let err = Salt::from_str(&bytes).unwrap_err();

            assert_eq!(
                HshError::SaltFromStrError(SaltFromStrError::InvalidByte(
                    String::from("nineteen"),
                    7
                )),
                err
            );
        });
    }

    #[test]
    fn test_salt_from_str_long_bytes() {
        FORMAT_MODE.test_with_salt_format(Format::Bytes, || {
            let bytes =
                "[8, 42, 4, 0, 72, 83, 5, 4, 185, 4, 68, 42, 9, 0, 2, 84, 4, 82, 5, 216, 0, 137]";

            let err = Salt::from_str(&bytes).unwrap_err();

            assert_eq!(
                HshError::SaltFromStrError(SaltFromStrError::IncorrectLength(16, 22)),
                err,
            );
        })
    }

    #[test]
    fn test_salt_from_str_valid_hex() {
        FORMAT_MODE.test_with_salt_format(Format::Hex, || {
            let bytes = [7, 4, 2, 5, 7, 2, 6, 19, 1, 0, 3, 3, 6, 4, 2, 33];
            let hex = hex::encode(bytes);

            let salt = Salt::from_str(&hex).unwrap();

            assert_eq!(bytes, salt.0);
        });
    }

    #[test]
    fn test_salt_from_str_empty_hex() {
        FORMAT_MODE.test_with_salt_format(Format::Hex, || {
            let hex = "";

            let err = Salt::from_str(&hex).unwrap_err();

            assert_eq!(HshError::SaltFromStrError(SaltFromStrError::BlankStr), err);
        });
    }

    #[test]
    fn test_salt_from_str_odd_length_hex() {
        FORMAT_MODE.test_with_salt_format(Format::Hex, || {
            let hex = "a83e8f932";

            let err = Salt::from_str(&hex).unwrap_err();

            assert_eq!(
                HshError::SaltFromStrError(SaltFromStrError::InvalidHexLength),
                err
            );
        });
    }

    #[test]
    fn test_salt_from_str_invalid_hex_characters() {
        FORMAT_MODE.test_with_salt_format(Format::Hex, || {
            let hex = "an7c123'573b9VB769p/yvgwoehgi42\"";

            let err = Salt::from_str(&hex).unwrap_err();

            assert_eq!(
                HshError::SaltFromStrError(SaltFromStrError::InvalidHexCharacter('n', 1)),
                err
            );
        });
    }

    #[test]
    fn test_salt_from_str_long_hex() {
        FORMAT_MODE.test_with_salt_format(Format::Hex, || {
            let bytes = [
                8, 42, 4, 0, 72, 83, 5, 4, 185, 4, 68, 42, 9, 0, 2, 84, 4, 82, 5, 216, 0, 137,
            ];
            let hex = hex::encode(bytes);

            let err = Salt::from_str(&hex).unwrap_err();

            assert_eq!(
                HshError::SaltFromStrError(SaltFromStrError::IncorrectLength(16, 22)),
                err,
            );
        });
    }

    #[test]
    fn test_salt_from_str_valid_base64() {
        FORMAT_MODE.test_with_salt_format(Format::Base64, || {
            let bytes = [7, 4, 2, 5, 7, 2, 6, 19, 1, 0, 3, 3, 6, 4, 2, 33];
            let base64 = bytes.to_base64(Config {
                char_set: CharacterSet::Standard,
                newline: Newline::LF,
                pad: true,
                line_length: None,
            });

            let salt = Salt::from_str(&base64).unwrap();

            assert_eq!(bytes, salt.0);
        });
    }

    #[test]
    fn test_salt_from_str_empty_base64() {
        FORMAT_MODE.test_with_salt_format(Format::Base64, || {
            let base64 = "";

            let err = Salt::from_str(&base64).unwrap_err();

            assert_eq!(HshError::SaltFromStrError(SaltFromStrError::BlankStr), err);
        });
    }

    #[test]
    fn test_salt_from_str_invalid_length_base64() {
        FORMAT_MODE.test_with_salt_format(Format::Base64, || {
            let base64 = "a83eMf932";

            let err = Salt::from_str(&base64).unwrap_err();

            assert_eq!(
                HshError::SaltFromStrError(SaltFromStrError::InvalidBase64Length),
                err
            );
        });
    }

    #[test]
    fn test_salt_from_str_invalid_base64_characters() {
        FORMAT_MODE.test_with_salt_format(Format::Base64, || {
            let base64 = "=an7c123;573M9VB769p/yv+wo~ehgi42\"`G";

            println!("{}", base64);
            let err = Salt::from_str(&base64).unwrap_err();

            assert_eq!(
                HshError::SaltFromStrError(SaltFromStrError::InvalidBase64Character(';', 8)),
                err,
            );
        });
    }

    #[test]
    fn test_salt_from_str_long_base64() {
        FORMAT_MODE.test_with_salt_format(Format::Base64, || {
            let bytes = [
                8, 42, 4, 0, 72, 83, 5, 4, 185, 4, 68, 42, 9, 0, 2, 84, 4, 82, 5, 216, 0, 137,
            ];
            let base64 = bytes.to_base64(Config {
                char_set: CharacterSet::Standard,
                newline: Newline::LF,
                pad: true,
                line_length: None,
            });

            let err = Salt::from_str(&base64).unwrap_err();

            assert_eq!(
                HshError::SaltFromStrError(SaltFromStrError::IncorrectLength(16, 22)),
                err,
            );
        });
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
        let salt = Salt::from_hex("07040205070206130100030306040221").unwrap();
        let input = BcryptInput::new(cost, salt);

        let password = "password";

        let hash = BcryptHasher.hash_str(input, password).unwrap();

        assert_eq!(
            "dfcd71d5fb5c9f17bddc20eff324be2926529c01c440fcfb",
            hash.as_hex()
        );
    }

    #[test]
    fn test_bcrypt_hash_empty_string() {
        let cost = 10;
        let salt = Salt::from_hex("07040205070206130100030306040221").unwrap();
        let input = BcryptInput::new(cost, salt);

        let err = BcryptHasher.hash_str(input, "").unwrap_err();

        assert_eq!(
            HshError::UnsuportedStrLength(String::from(
                "input string for bcrypt hash function must be between 0 and 72 bytes"
            )),
            err,
        );
    }

    #[test]
    fn test_bcrypt_hash_bytes() {
        let cost = 10;
        let salt = Salt::from_hex("07040205070206130100030306040221").unwrap();
        let input = BcryptInput::new(cost, salt);

        let bytes = b"password";

        let hash = BcryptHasher.hash(input, bytes).unwrap();

        assert_eq!(
            "dfcd71d5fb5c9f17bddc20eff324be2926529c01c440fcfb",
            hash.as_hex()
        );
    }

    #[test]
    fn test_bcrypt_hash_empty_bytes() {
        let cost = 10;
        let salt = Salt::from_hex("07040205070206130100030306040221").unwrap();
        let input = BcryptInput::new(cost, salt);

        let err = BcryptHasher.hash(input, &[]).unwrap_err();

        assert_eq!(
            HshError::UnsuportedStrLength(String::from(
                "input string for bcrypt hash function must be between 0 and 72 bytes"
            )),
            err
        );
    }

    #[test]
    fn test_bcrypt_hash_long_bytes() {
        let cost = 10;
        let salt = Salt::from_hex("07040205070206130100030306040221").unwrap();
        let input = BcryptInput::new(cost, salt);

        let bytes = [0; 75];

        let err = BcryptHasher.hash(input, &bytes).unwrap_err();

        assert_eq!(
            HshError::UnsuportedStrLength(String::from(
                "input string for bcrypt hash function must be between 0 and 72 bytes"
            )),
            err,
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
                    SaltFromStrError::IncorrectLength(16, len),
                    res.unwrap_err(),
                );
            }
        }

        #[test]
        fn fuzz_salt_from_bytes_does_not_panic(str in ".*") {
            let _ = Salt::from_bytes(&str);
        }

        #[test]
        fn fuzz_salt_from_hex_does_not_panic(str in ".*") {
            let _ = Salt::from_hex(&str);
        }

        #[test]
        fn fuzz_salt_from_base64_does_not_panic(str in ".*") {
            let _ = Salt::from_base64(&str);
        }

        #[test]
        fn fuzz_salt_from_bytes_arbitrary_valid_bytes(arr in [any::<u8>(); 16]) {
            let mut bytes = String::with_capacity(65);
            bytes.push('[');
            bytes.push_str(&arr[0].to_string());
            for b in &arr[1..] {
                bytes.push(',');
                bytes.push_str(&b.to_string());
            }
            bytes.push(']');

            let salt = Salt::from_bytes(&bytes).unwrap();
            assert_eq!(arr, salt.0);
        }

        #[test]
        fn fuzz_salt_from_bytes_invalid_digits(input in "([a-zA-Z]+,)+") {
            let err = Salt::from_bytes(&format!("[{}]", input)).unwrap_err();
            let msg = format!("{}", err);
            assert!(msg.contains("byte input contains invalid byte"));
        }

        #[test]
        fn fuzz_salt_from_bytes_invalid_format(input in "[0-9a-zA-Z]*") {
            let err = Salt::from_bytes(&input).unwrap_err();
            assert_eq!(SaltFromStrError::InvalidByteFormat, err);
        }

        #[test]
        fn fuzz_salt_from_hex_arbitrary_valid_hex(arr in [any::<u8>(); 16]) {
            let hex = hex::encode(arr);
            let salt = Salt::from_hex(&hex).unwrap();
            assert_eq!(arr, salt.0);
        }

        #[test]
        fn fuzz_salt_from_hex_odd_length(hex in "[0-9a-f]([0-9a-f][0-9a-f])*") {
            let err = Salt::from_hex(&hex).unwrap_err();
            assert_eq!(SaltFromStrError::InvalidHexLength, err);
        }

        #[test]
        fn fuzz_salt_from_hex_invalid_characters(hex in "([g-zG-Z][g-zG-Z])+") {
            let err = Salt::from_hex(&hex).unwrap_err();
            let msg = format!("{}", err);
            assert!(msg.contains("invalid character") && msg.contains("in hex at index"));
        }

        #[test]
        fn fuzz_salt_from_base64_arbitrary_valid_base64(arr in [any::<u8>(); 16]) {
            let base64 = arr.to_base64(Config {
                char_set: CharacterSet::Standard,
                newline: Newline::LF,
                pad: true,
                line_length: None,
            });
            let salt = Salt::from_base64(&base64).unwrap();
            assert_eq!(arr, salt.0)
        }

        #[test]
        fn fuzz_salt_from_base64_invalid_length(base64 in "[0-9a-zA-Z/+=]{1,3}([0-9a-zA-Z/+=]{4})*") {
            let err = Salt::from_base64(&base64).unwrap_err();
            assert_eq!(SaltFromStrError::InvalidBase64Length, err);
        }

        #[test]
        fn fuzz_salt_from_base64_invalid_characters(base64 in "[!\"$%&'*,-.:;<=>?@]{4}") {
            let err = Salt::from_base64(&base64).unwrap_err();
            let msg = format!("{}", err);
            assert!(msg.contains("invalid character") && msg.contains("in base64 string at index"));
        }

        #[test]
        #[ignore]
        fn fuzz_bcrypt_hash_does_not_panic(
            input in arbitrary_input(),
            pass in ".*",
        ) {
            let _ = BcryptHasher.hash_str(input, &pass);
        }

        #[test]
        #[ignore]
        fn fuzz_bcrypt_hash_bytes_does_not_panic(
            input in arbitrary_input(),
            bytes in proptest::collection::vec(any::<u8>(), 0..1000),
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
