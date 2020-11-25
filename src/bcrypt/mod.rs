// Std imports
use std::str::FromStr;

// Internal imports
use crate::error::{HshErr, HshResult};
use crate::hasher::Hasher;
use crate::types::HashOutput;

#[derive(Debug)]
pub struct Salt([u8; 16]);

impl Salt {
    fn new(data: [u8; 16]) -> Self {
        Self(data)
    }

    fn from_vec(data: Vec<u8>) -> HshResult<Self> {
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
        // let mut hash: Vec<u8> = std::iter::repeat(0).take(24).collect();
        let mut hash: [u8; 24] = [0; 24];
        bcrypt::bcrypt(input.cost, &input.salt.0, bytes, &mut hash);
        HashOutput::new(hash.to_vec())
    }
}
