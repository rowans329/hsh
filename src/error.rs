// Std imports
use std::cmp::PartialEq;
use std::error::Error;
use std::fmt::{self, Debug, Display};

#[derive(Debug, PartialEq)]
pub enum HshErr {
    IncorrectSaltLength(String),
    InvalidHashFunction(String),
    SaltFromStrError(String),
    UnsuportedStrLength(String),
}

impl Display for HshErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HshErr::IncorrectSaltLength(msg) => f.write_str(&format!("incorrect salt length ({})", msg)),
            HshErr::InvalidHashFunction(func) => f.write_str(&format!("invalid hash function '{}'", func)),
            HshErr::SaltFromStrError(msg) => f.write_str(&format!("error parsing salt: {}", msg)),
            HshErr::UnsuportedStrLength(msg) => f.write_str(&format!("unsuported string length ({})", msg)),
        }
    }
}

impl Error for HshErr {}

pub type HshResult<T> = Result<T, HshErr>;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_hsh_err_display_incorrect_salt_length() {
        let err = HshErr::IncorrectSaltLength("should be 16 bytes, found 22".to_string());
        let msg = format!("{}", err);
        assert_eq!("incorrect salt length (should be 16 bytes, found 22)", &msg);
    }

    #[test]
    fn test_hsh_err_display_invalid_hash_function() {
        let err = HshErr::InvalidHashFunction("foobar".to_string());
        let msg = format!("{}", err);
        assert_eq!("invalid hash function 'foobar'", &msg);
    }

    #[test]
    fn test_hsh_err_display_salt_from_str_error() {
        let err = HshErr::SaltFromStrError("salt cannot be blank".to_string());
        let msg = format!("{}", err);
        assert_eq!("error parsing salt: salt cannot be blank", &msg);
    }

    #[test]
    fn test_hsh_err_display_unsuported_str_length() {
        let err = HshErr::UnsuportedStrLength("".to_string());
        let msg = format!("{}", err);
        assert_eq!("unsuported string length ()", &msg);
    }
}
