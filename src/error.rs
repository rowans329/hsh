// Std imports
use std::fmt::{self, Debug, Display};
use std::error::Error as Error;

// External imports
use hex::FromHexError;

pub enum HshErr {
    InvalidHashFunction(String),
    InvalidSaltHex(FromHexError),
}

impl Debug for HshErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HshErr::InvalidHashFunction(str) => f.write_str(&format!("invalid hash function: `{}`", str)),
            HshErr::InvalidSaltHex(err) => f.write_str(&format!("invalid salt hex: {}", err)),
        }
    }
}

impl Display for HshErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

impl Error for HshErr {}

pub type HshResult<T> = Result<T, HshErr>;
