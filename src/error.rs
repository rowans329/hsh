// Std imports
use std::fmt::{self, Debug, Display};

// External imports
use hex::FromHexError;

pub enum HshErr {
<<<<<<< Updated upstream
    InvalidHashFunction,
=======
    InvalidHashFunction(String),
    InvalidSalt(String),
>>>>>>> Stashed changes
    InvalidSaltHex(FromHexError),
}

impl Debug for HshErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HshErr::InvalidHashFunction => f.write_str("invalid hash function"),
            HshErr::InvalidSaltHex(err) => f.write_str(&format!("invalid salt hex: {}", err)),
            HshErr::InvalidSalt(str) => f.write_str(&format!("invalid salt: {}", str)),
        }
    }
}

impl Display for HshErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

pub type HshResult<T> = Result<T, HshErr>;
