# hsh

![Lines of code](https://img.shields.io/tokei/lines/github/rowans329/hsh)
![GitHub Workflow Status](https://img.shields.io/github/workflow/status/rowans329/hsh/Test)
[![codecov](https://codecov.io/gh/rowans329/hsh/branch/main/graph/badge.svg?token=5YJC5AL364)](https://codecov.io/gh/rowans329/hsh)

hsh is a simple string-hashing CLI written entirely in Rust that supports a wide variety of hashing functions. It mostly relies on the [RustCrypto hash crates](https://github.com/RustCrypto/hashes) to perform the hashing.

### Supported hash functions

- [Bcrypt](https://en.wikipedia.org/wiki/Bcrypt)
- [BLAKE2](<https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE2>)
- [GOST](<https://en.wikipedia.org/wiki/GOST_(hash_function)>) (GOST R 34.11-9) (with both "test parameters" and CryptoPro [S-Box parameters](<https://en.wikipedia.org/wiki/GOST_(hash_function)#Initial_values>))
- [Grøstl](https://en.wikipedia.org/wiki/Grøstl)
  - Grøstl224
  - Grøstl256
  - Grøstl384
  - Grøstl512
- [MD2](<https://wikipedia.org/wiki/MD2_(hash_function)>)
- [MD4](https://wikipedia.org/wiki/MD4)
- [MD5](https://wikipedia.org/wiki/MD5)
- [RIPEMD](https://wikipedia.org/wiki/RIPEMD)
  - RIPEMD160
  - RIPEMD320
- [SHA-1](https://wikipedia.org/wiki/SHA-1)
- [SHA-2](https://wikipedia.org/wiki/SHA-2)
  - SHA-224
  - SHA-256
  - SHA-384
  - SHA-512
- [SHA-3/Keccak](https://wikipedia.org/wiki/SHA-3)
  - Keccak-224
  - Keccak-256
  - Keccak-384
  - Keccak-512
  - SHA3-224
  - SHA3-256
  - SHA3-384
  - SHA3-512
- [Shabal](https://en.wikipedia.org/wiki/Shabal)
  - Shabal-192
  - Shabal-224
  - Shabal-256
  - Shabal-384
  - Shabal-512
- [Streebog](https://en.wikipedia.org/wiki/Streebog)
  - Streebog-256
  - Streebog-512
- [Whirlpool](<https://en.wikipedia.org/wiki/Whirlpool_(hash_function)>)

## Usage

```
hsh 0.1.0
A simple string-hashing CLI that supports a wide variety of hash functions

USAGE:
    hsh [FLAGS] [OPTIONS] <string> <function>

FLAGS:
    -h, --help
            Prints help information

    -V, --version
            Prints version information

    -v, --verbose
            Pass multiple times for increased log output

            By default, only errors are reported. Passing `-v` also prints warnings, `-vv` enables info logging, `-vvv`
            debug, and `-vvvv` trace.

OPTIONS:
    -c, --cost <cost>
            The cost to use when hashing with the Bcrypt hash function

        --format <format>
            The format in which to display the output hash [env: HSH_FORMAT=]  [default: hex]  [possible values: base64,
            bytes, hex]
    -s, --salt <salt>
            The 16-byte salt to use when hashing with the Bcrypt hash function

        --salt-format <salt-format>
            The format of the salt argument (defaults to the value of `format`) [env: SALT_FORMAT=]  [possible values:
            base64, bytes, hex]

ARGS:
    <string>
            The string to be hashed

    <function>
            The hash function to use [possible values: bcrypt, blake2, gost94test, gost94crypto, groestl224, groestl256,
            groestl384, groestl512, keccak224, keccak256, keccak256full, keccak384, keccak512, md2, md4, md5, ripemd160,
            ripemd320, sha1, sha224, sha256, sha384, sha512, sha3-224, sha3-256, sha3-384, sha3-512, shabal192,
            shabal224, shabal256, shabal384, shabal512, streebog256, streebog512, whirlpool]
```

## License

Licensed under either of

- Apache License, Version 2.0
  ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license
  ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
