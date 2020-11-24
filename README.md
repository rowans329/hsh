# hsh
![GitHub](https://img.shields.io/github/license/rowans329/hsh)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/rowans329/hsh)
![Crates.io](https://img.shields.io/crates/v/hsh)
![Crates.io](https://img.shields.io/crates/d/hsh?label=downloads)
![GitHub Workflow Status](https://img.shields.io/github/workflow/status/rowans329/hsh/Test)
[![codecov](https://codecov.io/gh/rowans329/hsh/branch/main/graph/badge.svg?token=5YJC5AL364)](https://codecov.io/gh/rowans329/hsh)

hsh is a simple string-hashing CLI written entirely in Rust that supports a wide variety of hashing functions. It mostly relies on the [RustCrypto hash crates](https://github.com/RustCrypto/hashes) to perform the hashing.

### Supported hash functions

* [Bcrypt](https://en.wikipedia.org/wiki/Bcrypt)
* [BLAKE2](https://en.wikipedia.org/wiki/BLAKE_(hash_function)#BLAKE2)
* [GOST](https://en.wikipedia.org/wiki/GOST_(hash_function)) (GOST R 34.11-9) (with both "test parameters" and CryptoPro [S-Box parameters](https://en.wikipedia.org/wiki/GOST_(hash_function)#Initial_values)
* [Grøstl](https://en.wikipedia.org/wiki/Grøstl)
   * Grøstl224
   * Grøstl256
   * Grøstl384
   * Grøstl512
* [MD2](https://wikipedia.org/wiki/MD2_(hash_function))
* [MD4](https://wikipedia.org/wiki/MD4)
* [MD5](https://wikipedia.org/wiki/MD5)
* [RIPEMD](https://wikipedia.org/wiki/RIPEMD)
   * RIPEMD160
   * RIPEMD320
* [SHA-1](https://wikipedia.org/wiki/SHA-1)
* [SHA-2](https://wikipedia.org/wiki/SHA-2)
   * SHA-224
   * SHA-256
   * SHA-384
   * SHA-512
* [SHA-3/Keccak](https://wikipedia.org/wiki/SHA-3)
   * Keccak-224
   * Keccak-256
   * Keccak-384
   * Keccak-512
   * SHA3-224
   * SHA3-256
   * SHA3-384
   * SHA3-512
* [Shabal](https://en.wikipedia.org/wiki/Shabal)
   * Shabal-192
   * Shabal-224
   * Shabal-256
   * Shabal-384
   * Shabal-512
* [Streebog](https://en.wikipedia.org/wiki/Streebog)
   * Streebog-256
   * Streebog-512
* [Whirlpool](https://en.wikipedia.org/wiki/Whirlpool_(hash_function))

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
