// Modules
pub mod bcrypt;
pub mod blake2;
pub mod cli;
pub mod error;
pub mod format;
pub mod gost94;
pub mod groestl;
pub mod hasher;
pub mod md2;
pub mod md4;
pub mod md5;
pub mod ripemd;
pub mod sha1;
pub mod sha2;
pub mod sha3;
pub mod shabal;
pub mod streebog;
pub mod types;
pub mod utils;
pub mod whirlpool;

// Internal imports
use crate::bcrypt::{BcryptHasher, BcryptInput};
use crate::blake2::Blake2Hasher;
use crate::error::HshResult;
use crate::gost94::{Gost94Hasher, SBox};
use crate::groestl::*;
use crate::hasher::Hasher;
use crate::md2::Md2Hasher;
use crate::md4::Md4Hasher;
use crate::md5::Md5Hasher;
use crate::ripemd::*;
use crate::sha1::Sha1Hasher;
use crate::sha2::*;
use crate::sha3::*;
use crate::shabal::*;
use crate::streebog::*;
use crate::types::{HashFunction, HashOutput, Salt};
use crate::whirlpool::WhirlpoolHasher;

pub fn hash(
    string: &str,
    function: HashFunction,
    cost: Option<u32>,
    salt: Option<Salt>,
) -> HshResult<HashOutput> {
    use crate::types::HashFunction::*;

    match function {
        Bcrypt => {
            let input = BcryptInput::new(cost.unwrap(), salt.unwrap());
            BcryptHasher.hash_str(input, string)
        }
        Blake2 => Blake2Hasher.hash_str((), string),
        Gost94Test => Gost94Hasher.hash_str(SBox::Test, string),
        Gost94CryptoPro => Gost94Hasher.hash_str(SBox::CryptoPro, string),
        Groestl224 => Groestl224Hasher.hash_str((), string),
        Groestl256 => Groestl256Hasher.hash_str((), string),
        Groestl384 => Groestl384Hasher.hash_str((), string),
        Groestl512 => Groestl512Hasher.hash_str((), string),
        Keccak224 => Keccak224Hasher.hash_str((), string),
        Keccak256 => Keccak256Hasher.hash_str((), string),
        Keccak256Full => Keccak256FullHasher.hash_str((), string),
        Keccak384 => Keccak384Hasher.hash_str((), string),
        Keccak512 => Keccak512Hasher.hash_str((), string),
        Md2 => Md2Hasher.hash_str((), string),
        Md4 => Md4Hasher.hash_str((), string),
        Md5 => Md5Hasher.hash_str((), string),
        Ripemd160 => Ripemd160Hasher.hash_str((), string),
        Ripemd320 => Ripemd320Hasher.hash_str((), string),
        Sha1 => Sha1Hasher.hash_str((), string),
        Sha224 => Sha224Hasher.hash_str((), string),
        Sha256 => Sha256Hasher.hash_str((), string),
        Sha384 => Sha384Hasher.hash_str((), string),
        Sha512 => Sha512Hasher.hash_str((), string),
        Sha3_224 => Sha3_224Hasher.hash_str((), string),
        Sha3_256 => Sha3_256Hasher.hash_str((), string),
        Sha3_384 => Sha3_384Hasher.hash_str((), string),
        Sha3_512 => Sha3_512Hasher.hash_str((), string),
        Shabal192 => Shabal192Hasher.hash_str((), string),
        Shabal224 => Shabal224Hasher.hash_str((), string),
        Shabal256 => Shabal256Hasher.hash_str((), string),
        Shabal384 => Shabal384Hasher.hash_str((), string),
        Shabal512 => Shabal512Hasher.hash_str((), string),
        Streebog256 => Streebog256Hasher.hash_str((), string),
        Streebog512 => Streebog512Hasher.hash_str((), string),
        Whirlpool => WhirlpoolHasher.hash_str((), string),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        #[ignore]
        fn fuzz_hash_does_not_panic(
            str in ".+",
            function in random_function(),
            cost in random_cost(),
            salt in random_salt(),
        ) {
            let _ = hash(&str, function, cost, salt);
        }
    }

    fn random_function() -> impl Strategy<Value = HashFunction> {
        prop_oneof![
            Just(HashFunction::Bcrypt),
            Just(HashFunction::Blake2),
            Just(HashFunction::Gost94Test),
            Just(HashFunction::Gost94CryptoPro),
            Just(HashFunction::Groestl224),
            Just(HashFunction::Groestl256),
            Just(HashFunction::Groestl384),
            Just(HashFunction::Groestl512),
            Just(HashFunction::Md2),
            Just(HashFunction::Md4),
            Just(HashFunction::Md5),
            Just(HashFunction::Ripemd160),
            Just(HashFunction::Ripemd320),
            Just(HashFunction::Sha1),
            Just(HashFunction::Sha224),
            Just(HashFunction::Sha256),
            Just(HashFunction::Sha384),
            Just(HashFunction::Sha512),
            Just(HashFunction::Sha3_224),
            Just(HashFunction::Sha3_256),
            Just(HashFunction::Sha3_384),
            Just(HashFunction::Sha3_512),
            Just(HashFunction::Keccak224),
            Just(HashFunction::Keccak256),
            Just(HashFunction::Keccak256Full),
            Just(HashFunction::Keccak384),
            Just(HashFunction::Keccak512),
            Just(HashFunction::Shabal192),
            Just(HashFunction::Shabal224),
            Just(HashFunction::Shabal256),
            Just(HashFunction::Shabal384),
            Just(HashFunction::Shabal512),
            Just(HashFunction::Streebog256),
            Just(HashFunction::Streebog512),
            Just(HashFunction::Whirlpool),
        ]
    }

    fn random_cost() -> BoxedStrategy<Option<u32>> {
        proptest::option::of(any::<u32>()).boxed()
    }

    fn random_salt() -> BoxedStrategy<Option<Salt>> {
        proptest::option::of(([any::<u8>(); 16]).prop_map(|arr| Salt::new(arr))).boxed()
    }
}
