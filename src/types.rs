// Std imports
use std::fmt::{self, Debug, Display};
use std::str::FromStr;

// External imports
use b64::{CharacterSet, Config, Newline, ToBase64};

// Internal imports
use crate::error::{HshErr, HshResult};
use crate::format::get_format;

// Re-exports
pub use crate::bcrypt::Salt;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum HashFunction {
    Bcrypt,
    Blake2,
    Gost94Test,
    Gost94CryptoPro,
    Groestl224,
    Groestl256,
    Groestl384,
    Groestl512,
    Keccak224,
    Keccak256,
    Keccak256Full,
    Keccak384,
    Keccak512,
    Md2,
    Md4,
    Md5,
    Ripemd160,
    Ripemd320,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Shabal192,
    Shabal224,
    Shabal256,
    Shabal384,
    Shabal512,
    Streebog256,
    Streebog512,
    Whirlpool,
}

impl HashFunction {
    pub fn variants() -> Vec<&'static str> {
        vec![
            "bcrypt",
            "blake2",
            "gost94test",
            "gost94crypto",
            "groestl224",
            "groestl256",
            "groestl384",
            "groestl512",
            "keccak224",
            "keccak256",
            "keccak256full",
            "keccak384",
            "keccak512",
            "md2",
            "md4",
            "md5",
            "ripemd160",
            "ripemd320",
            "sha1",
            "sha224",
            "sha256",
            "sha384",
            "sha512",
            "sha3-224",
            "sha3-256",
            "sha3-384",
            "sha3-512",
            "shabal192",
            "shabal224",
            "shabal256",
            "shabal384",
            "shabal512",
            "streebog256",
            "streebog512",
            "whirlpool",
        ]
    }
}

impl FromStr for HashFunction {
    type Err = HshErr;

    fn from_str(str: &str) -> HshResult<HashFunction> {
        use super::HashFunction::*;

        match str {
            "bcrypt" => Ok(Bcrypt),
            "blake2" => Ok(Blake2),
            "gost94test" => Ok(Gost94Test),
            "gost94crypto" => Ok(Gost94CryptoPro),
            "groestl224" => Ok(Groestl224),
            "groestl256" => Ok(Groestl256),
            "groestl384" => Ok(Groestl384),
            "groestl512" => Ok(Groestl512),
            "keccak224" => Ok(Keccak224),
            "keccak256" => Ok(Keccak256),
            "keccak256full" => Ok(Keccak256Full),
            "keccak384" => Ok(Keccak384),
            "keccak512" => Ok(Keccak512),
            "md2" => Ok(Md2),
            "md4" => Ok(Md4),
            "md5" => Ok(Md5),
            "ripemd160" => Ok(Ripemd160),
            "ripemd320" => Ok(Ripemd320),
            "sha1" => Ok(Sha1),
            "sha224" => Ok(Sha224),
            "sha256" => Ok(Sha256),
            "sha384" => Ok(Sha384),
            "sha512" => Ok(Sha512),
            "sha3-224" => Ok(Sha3_224),
            "sha3-256" => Ok(Sha3_256),
            "sha3-384" => Ok(Sha3_384),
            "sha3-512" => Ok(Sha3_512),
            "shabal192" => Ok(Shabal192),
            "shabal224" => Ok(Shabal224),
            "shabal256" => Ok(Shabal256),
            "shabal384" => Ok(Shabal384),
            "shabal512" => Ok(Shabal512),
            "streebog256" => Ok(Streebog256),
            "streebog512" => Ok(Streebog512),
            "whirlpool" => Ok(Whirlpool),
            str => Err(HshErr::InvalidHashFunction(String::from(str))),
        }
    }
}

#[derive(Debug)]
pub struct HashOutput {
    bytes: Vec<u8>,
}

impl HashOutput {
    pub fn new<I: IntoIterator<Item = u8>>(bytes: I) -> Self {
        Self {
            bytes: bytes.into_iter().collect(),
        }
    }

    pub fn format(&self, format: Format) -> String {
        match format {
            Format::Base64 => self.as_base64(),
            Format::Bytes => format!("{:?}", self.as_bytes()),
            Format::Hex => self.as_hex(),
        }
    }

    pub fn as_base64(&self) -> String {
        self.bytes.to_base64(Config {
            char_set: CharacterSet::Standard,
            newline: Newline::LF,
            pad: true,
            line_length: None,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn as_hex(&self) -> String {
        hex::encode(&self.bytes)
    }
}

impl Display for HashOutput {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let format = get_format();
        f.write_str(&self.format(format))
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Format {
    Base64,
    Bytes,
    Hex,
}

impl Format {
    pub fn variants() -> Vec<&'static str> {
        vec!["base64", "bytes", "hex"]
    }
}

impl FromStr for Format {
    type Err = HshErr;

    fn from_str(str: &str) -> HshResult<Format> {
        match str {
            "base64" => Ok(Format::Base64),
            "bytes" => Ok(Format::Bytes),
            "hex" => Ok(Format::Hex),
            _ => panic!(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_hash_function_from_str_valid() {
        let function = HashFunction::from_str("shabal192").unwrap();
        assert_eq!(HashFunction::Shabal192, function);
    }

    #[test]
    fn test_hash_function_from_empty_str() {
        let err = HashFunction::from_str("").unwrap_err();
        assert_eq!(HshErr::InvalidHashFunction(String::from("")), err);
    }

    #[test]
    fn test_hash_function_from_str_invalid() {
        let err = HashFunction::from_str("foobar").unwrap_err();
        assert_eq!(HshErr::InvalidHashFunction(String::from("foobar")), err);
    }

    #[test]
    fn test_hash_function_variants() {
        let variants = HashFunction::variants();
        assert_eq!(
            vec![
                "bcrypt",
                "blake2",
                "gost94test",
                "gost94crypto",
                "groestl224",
                "groestl256",
                "groestl384",
                "groestl512",
                "keccak224",
                "keccak256",
                "keccak256full",
                "keccak384",
                "keccak512",
                "md2",
                "md4",
                "md5",
                "ripemd160",
                "ripemd320",
                "sha1",
                "sha224",
                "sha256",
                "sha384",
                "sha512",
                "sha3-224",
                "sha3-256",
                "sha3-384",
                "sha3-512",
                "shabal192",
                "shabal224",
                "shabal256",
                "shabal384",
                "shabal512",
                "streebog256",
                "streebog512",
                "whirlpool",
            ],
            variants,
        )
    }

    #[test]
    fn test_hash_output_new_from_array() {
        let bytes = [4, 246, 0, 2, 6, 6, 2, 73, 26, 9, 3, 1, 10, 1, 3, 9];
        let output = HashOutput::new(bytes.to_vec());
        assert_eq!(bytes.to_vec(), output.bytes);
    }

    #[test]
    fn test_hash_output_new_from_vec() {
        let bytes = vec![4, 246, 0, 2, 6, 6, 2, 73, 26, 9, 3, 1, 10, 1, 3, 9];
        let output = HashOutput::new(bytes.clone());
        assert_eq!(bytes, output.bytes);
    }

    #[test]
    fn test_hash_output_as_bytes() {
        let bytes = vec![4, 246, 0, 2, 6, 6, 2, 73, 26, 9, 3, 1, 10, 1, 3, 9];
        let output = HashOutput::new(bytes.clone());
        assert_eq!(bytes.as_slice(), output.as_bytes());
    }

    #[test]
    fn test_hash_output_as_hex() {
        let bytes = [4, 246, 0, 2, 6, 6, 2, 73, 26, 9, 3, 1, 10, 1, 3, 9];
        let output = HashOutput::new(bytes.to_vec());
        assert_eq!("04f60002060602491a0903010a010309", &output.as_hex());
    }

    proptest! {
        #[test]
        fn fuzz_hash_function_from_str_does_not_panic(str in ".*") {
            let _ = HashFunction::from_str(&str);
        }

        #[test]
        fn fuzz_hash_output_new_does_not_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let _ = HashOutput::new(bytes);
        }

        #[test]
        fn fuzz_hash_output_as_bytes(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let output = HashOutput::new(bytes.clone());
            assert_eq!(bytes.as_slice(), output.as_bytes());
        }

        #[test]
        fn fuzz_hash_output_as_hex(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let output = HashOutput::new(bytes.clone());
            assert_eq!(hex::encode(bytes), output.as_hex());
        }
    }
}
