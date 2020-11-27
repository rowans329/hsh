// Std imports
use std::fmt::Debug;
use std::str::FromStr;

// Internal imports
use crate::error::{HshErr, HshResult};

// Re-exports
pub use crate::bcrypt::Salt;

#[derive(Clone, Debug, PartialEq)]
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
            "sha3_224" => Ok(Sha3_224),
            "sha3_256" => Ok(Sha3_256),
            "sha3_384" => Ok(Sha3_384),
            "sha3_512" => Ok(Sha3_512),
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

pub struct HashOutput {
    bytes: Vec<u8>,
}

impl HashOutput {
    pub fn new<I: IntoIterator<Item = u8>>(bytes: I) -> Self {
        Self {
            bytes: bytes.into_iter().collect(),
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn as_hex(&self) -> String {
        hex::encode(&self.bytes)
    }

    pub fn into_hex(self) -> String {
        hex::encode(self.bytes)
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
    fn test_hash_output_into_bytes() {
        let bytes = vec![4, 246, 0, 2, 6, 6, 2, 73, 26, 9, 3, 1, 10, 1, 3, 9];
        let output = HashOutput::new(bytes.clone());
        assert_eq!(bytes, output.into_bytes());
    }

    #[test]
    fn test_hash_output_as_hex() {
        let bytes = [4, 246, 0, 2, 6, 6, 2, 73, 26, 9, 3, 1, 10, 1, 3, 9];
        let output = HashOutput::new(bytes.to_vec());
        assert_eq!("04f60002060602491a0903010a010309", &output.as_hex());
    }

    #[test]
    fn test_hash_output_into_hex() {
        let bytes = [4, 246, 0, 2, 6, 6, 2, 73, 26, 9, 3, 1, 10, 1, 3, 9];
        let output = HashOutput::new(bytes.to_vec());
        assert_eq!("04f60002060602491a0903010a010309", &output.into_hex());
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
        fn fuzz_hash_output_into_bytes(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let output = HashOutput::new(bytes.clone());
            assert_eq!(bytes, output.into_bytes());
        }

        #[test]
        fn fuzz_hash_output_as_hex(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let output = HashOutput::new(bytes.clone());
            assert_eq!(hex::encode(bytes), output.as_hex());
        }

        #[test]
        fn fuzz_hash_output_into_hex(
            bytes in proptest::collection::vec(any::<u8>(), 0..1000)
        ) {
            let output = HashOutput::new(bytes.clone());
            assert_eq!(hex::encode(bytes), output.as_hex());
        }
    }
}
