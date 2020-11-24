// External imports
use gost94::{Digest, Gost94CryptoPro, Gost94Test};

// Internal imports
use crate::hasher::Hasher;
use crate::types::HashOutput;

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
