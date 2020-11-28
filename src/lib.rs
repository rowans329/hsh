// Modules
mod error;
mod hasher;

mod bcrypt;
mod blake2;
mod gost94;
mod groestl {
    pub(crate) mod groestl224;
    pub(crate) mod groestl256;
    pub(crate) mod groestl384;
    pub(crate) mod groestl512;
}
mod md2;
mod md4;
mod md5;
mod ripemd {
    pub(crate) mod ripemd160;
    pub(crate) mod ripemd320;
}
mod sha1;
mod sha2 {
    pub(crate) mod sha224;
    pub(crate) mod sha256;
    pub(crate) mod sha384;
    pub(crate) mod sha512;
}
mod sha3 {
    pub(crate) mod keccak224;
    pub(crate) mod keccak256;
    pub(crate) mod keccak256full;
    pub(crate) mod keccak384;
    pub(crate) mod keccak512;
    pub(crate) mod sha3_224;
    pub(crate) mod sha3_256;
    pub(crate) mod sha3_384;
    pub(crate) mod sha3_512;
}
mod shabal {
    pub(crate) mod shabal192;
    pub(crate) mod shabal224;
    pub(crate) mod shabal256;
    pub(crate) mod shabal384;
    pub(crate) mod shabal512;
}
mod streebog {
    pub(crate) mod streebog256;
    pub(crate) mod streebog512;
}
mod whirlpool;

// Public modules
pub mod types;

// Internal imports
use crate::bcrypt::{BcryptHasher, BcryptInput};
use crate::blake2::Blake2Hasher;
use crate::gost94::{Gost94Hasher, SBox};
use crate::groestl::{
    groestl224::Groestl224Hasher, groestl256::Groestl256Hasher, groestl384::Groestl384Hasher,
    groestl512::Groestl512Hasher,
};
use crate::hasher::Hasher;
use crate::md2::Md2Hasher;
use crate::md4::Md4Hasher;
use crate::md5::Md5Hasher;
use crate::ripemd::{ripemd160::Ripemd160Hasher, ripemd320::Ripemd320Hasher};
use crate::sha1::Sha1Hasher;
use crate::sha2::{
    sha224::Sha224Hasher, sha256::Sha256Hasher, sha384::Sha384Hasher, sha512::Sha512Hasher,
};
use crate::sha3::{
    keccak224::Keccak224Hasher, keccak256::Keccak256Hasher, keccak256full::Keccak256FullHasher,
    keccak384::Keccak384Hasher, keccak512::Keccak512Hasher, sha3_224::Sha3_224Hasher,
    sha3_256::Sha3_256Hasher, sha3_384::Sha3_384Hasher, sha3_512::Sha3_512Hasher,
};
use crate::shabal::{
    shabal192::Shabal192Hasher, shabal224::Shabal224Hasher, shabal256::Shabal256Hasher,
    shabal384::Shabal384Hasher, shabal512::Shabal512Hasher,
};
use crate::streebog::{streebog256::Streebog256Hasher, streebog512::Streebog512Hasher};
use crate::types::{HashFunction, HashOutput, Salt};
use crate::whirlpool::WhirlpoolHasher;

pub fn hash(
    string: &str,
    function: HashFunction,
    cost: Option<u32>,
    salt: Option<Salt>,
) -> HashOutput {
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
