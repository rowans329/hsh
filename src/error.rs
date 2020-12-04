// Std imports
use std::cmp::PartialEq;
use std::error::Error;
use std::fmt::{self, Debug, Display};

// External imports
use exitcode::{ExitCode, DATAERR};
use log::error;

#[derive(Debug, PartialEq)]
pub enum HshErr {
    SaltFromStrError(SaltFromStrError),
    UnsuportedStrLength(String),
}

impl HshErr {
    pub fn exitcode(&self) -> ExitCode {
        match self {
            Self::SaltFromStrError(_) => DATAERR,
            Self::UnsuportedStrLength(_) => DATAERR,
        }
    }
}

impl Display for HshErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HshErr::SaltFromStrError(msg) => {
                f.write_fmt(format_args!("error parsing salt: {}", msg))
            }
            HshErr::UnsuportedStrLength(msg) => {
                f.write_fmt(format_args!("unsuported string length: {}", msg))
            }
        }
    }
}

impl Error for HshErr {}

impl From<SaltFromStrError> for HshErr {
    fn from(err: SaltFromStrError) -> Self {
        Self::SaltFromStrError(err)
    }
}

#[derive(Debug, PartialEq)]
pub enum SaltFromStrError {
    BlankStr,
    IncorrectLength(usize, usize),
    InvalidBase64Character(char, usize),
    InvalidBase64Length,
    InvalidByte(String, usize),
    InvalidByteFormat,
    InvalidHexCharacter(char, usize),
    InvalidHexLength,
}

impl Display for SaltFromStrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::BlankStr => f.write_str("salt cannot be blank"),
            Self::IncorrectLength(exp, act) => f.write_fmt(format_args!("incorrect salt length (expected {} bytes, found {})", exp, act)),
            Self::InvalidBase64Character(c, i) => f.write_fmt(format_args!("invalid character {} in base64 string at index {}", c, i)),
            Self::InvalidBase64Length => f.write_str("length of base64 string must be divisible by 4"),
            Self::InvalidByte(b, i) => f.write_fmt(format_args!("byte input contains invalid byte {} at array index {}", b, i)),
            Self::InvalidByteFormat => f.write_str("byte input was incorrectly formatted (string should begin and end with '[' and ']' and contain a comma-separated list of values)"),
            Self::InvalidHexCharacter(c, i) => f.write_fmt(format_args!("invalid character {} in hex at index {}", c, i)),
            Self::InvalidHexLength => f.write_fmt(format_args!("hex must have even length")),
        }
    }
}

impl Error for SaltFromStrError {}

pub type HshResult<T> = Result<T, HshErr>;

impl<T> UnwrapOrExit<T> for HshResult<T> {
    fn unwrap_or_exit(self) -> T {
        self.unwrap_or_else(|e| {
            error!("{}", e);
            std::process::exit(e.exitcode());
        })
    }
}

pub trait UnwrapOrExit<T> {
    fn unwrap_or_exit(self) -> T;
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn hsh_err_display_salt_from_str_error() {
        let err = HshErr::SaltFromStrError(SaltFromStrError::BlankStr);
        let msg = format!("{}", err);
        assert_eq!("error parsing salt: salt cannot be blank", &msg);
    }

    #[test]
    fn hsh_err_display_unsuported_str_length() {
        let err = HshErr::UnsuportedStrLength(String::from("input string for bcrypt hash function must be between 0 and 72 bytes"));
        let msg = format!("{}", err);
        assert_eq!("unsuported string length: input string for bcrypt hash function must be between 0 and 72 bytes", &msg);
    }

    #[test]
    fn hsh_err_exit_code_salt_from_str_error() {
        let err = HshErr::SaltFromStrError(SaltFromStrError::BlankStr);
        let code = err.exitcode();
        assert_eq!(65i64, code);
    }

    #[test]
    fn hsh_err_exit_code_unsuported_str_length() {
        let err = HshErr::UnsuportedStrLength(String::from("input string for bcrypt hash function must be between 0 and 72 bytes"));
        let code = err.exitcode();
        assert_eq!(65i64, code);
    }

    #[test]
    fn hsh_err_from_salt_from_str_error() {
        let err = HshErr::from(SaltFromStrError::BlankStr);
        assert_eq!(HshErr::SaltFromStrError(SaltFromStrError::BlankStr));
    }

    #[test]
    fn salt_from_str_error_display_blank_str() {
        let err = SaltFromStrError::BlankStr;
        let msg = format!("{}", err);
        assert_eq!("salt cannot be blank", &msg);
    }

    #[test]
    fn salt_from_str_error_display_incorrect_length() {
        let err = SaltFromStrError::IncorrectLength(16, 12);
        let msg = format!("{}", err);
        assert_eq!("incorrect salt length (expected 16 bytes, found 12)", &msg);
    }

    #[test]
    fn salt_from_str_error_display_invalid_base64_character() {
        let err = SaltFromStrError::InvalidBase64Character('~', 4);
        let msg = format!("{}", err);
        assert_eq!("invalid character '~' in base64 string at index 4", &msg);
    }

    #[test]
    fn salt_from_str_error_display_invalid_base64_length() {
        let err = SaltFromStrError::InvalidBase64Length;
        let msg = format!("{}", err);
        assert_eq!("length of base64 string must be divisible by 4", &msg);
    }

    #[test]
    fn salt_from_str_error_display_invalid_byte() {
        let err = SaltFromStrError::InvalidByte("-1", 2);
        let msg = format!("{}", err);
        assert_eq!("byte input contains invalid byte \"-1\" at array index 2", &msg);
    }

    #[test]
    fn salt_from_str_error_display_invalid_byte_format() {
        let err = SaltFromStrError::InvalidByteFormat;
        let msg = format!("{}", err);
        assert_eq!("byte input was incorrectly formatted (string should begin and end with '[' and ']' and contain a comma-separated list of values)", &msg);
    }

    #[test]
    fn salt_from_str_error_display_invalid_hex_character() {
        let err = SaltFromStrError::InvalidHexCharacter('~', 4);
        let msg = format!("{}", err);
        assert_eq!("invalid character '~' in hex string at index 4", &msg);
    }

    #[test]
    fn salt_from_str_error_display_invalid_hex_length() {
        let err = SaltFromStrError::InvalidHexLength;
        let msg = format!("{}", err);
        assert_eq!("hex must be of even length", &msg);
    }

    #[test]
    fn test_hsh_result_unwrap_or_exit_ok() {
        let res: HshResult<i64> = Ok(100);
        assert_eq!(100, res.unwrap_or_exit());
    }
}
