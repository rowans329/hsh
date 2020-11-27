// Std imports
use std::cmp::PartialEq;
use std::error::Error;
use std::fmt::{self, Debug, Display};

// External imports
use hex::FromHexError;

#[derive(PartialEq)]
pub enum HshErr {
    InvalidHashFunction(String),
    InvalidSalt(String),
    InvalidSaltHex(FromHexError),
}

impl Debug for HshErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HshErr::InvalidHashFunction(str) => {
                f.write_str(&format!("invalid hash function `{}`", str))
            }
            HshErr::InvalidSaltHex(err) => f.write_str(&format!("invalid salt hex -- {}", err)),
            HshErr::InvalidSalt(str) => f.write_str(&format!("invalid salt -- {}", str)),
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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_hsh_err_debug_invalid_function() {
        let err = HshErr::InvalidHashFunction(String::from("foobar"));

        let err_msg = format!("{:?}", err);

        assert_eq!(format!("invalid hash function `foobar`"), err_msg,)
    }

    #[test]
    fn test_hsh_err_debug_invalid_salt() {
        let err = HshErr::InvalidSalt(String::from("foobar"));

        let err_msg = format!("{:?}", err);

        assert_eq!(format!("invalid salt -- foobar"), err_msg,)
    }

    #[test]
    fn test_hsh_err_debug_invalid_salt_hex() {
        let err = HshErr::InvalidSaltHex(FromHexError::OddLength);

        let err_msg = format!("{:?}", err);

        assert_eq!(format!("invalid salt hex -- Odd number of digits"), err_msg,)
    }

    #[test]
    fn test_hsh_err_display_invalid_function() {
        let err = HshErr::InvalidHashFunction(String::from("foobar"));

        let err_msg = format!("{}", err);

        assert_eq!(format!("invalid hash function `foobar`"), err_msg,)
    }

    #[test]
    fn test_hsh_err_display_invalid_salt() {
        let err = HshErr::InvalidSalt(String::from("foobar"));

        let err_msg = format!("{}", err);

        assert_eq!(format!("invalid salt -- foobar"), err_msg,)
    }

    #[test]
    fn test_hsh_err_display_invalid_salt_hex() {
        let err = HshErr::InvalidSaltHex(FromHexError::OddLength);

        let err_msg = format!("{}", err);

        assert_eq!(format!("invalid salt hex -- Odd number of digits"), err_msg,)
    }
}
