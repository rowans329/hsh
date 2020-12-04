// Std imports
use std::cmp::PartialEq;
use std::error::Error;
use std::fmt::{self, Debug, Display};

// External imports
use exitcode::{ExitCode, DATAERR};
use log::error;

#[derive(Debug, PartialEq)]
pub enum HshErr {
    IncorrectSaltLength(String),
    SaltFromStrError(String),
    UnsuportedStrLength(String),
}

impl HshErr {
    pub fn exitcode(&self) -> ExitCode {
        match self {
            Self::IncorrectSaltLength(_) => DATAERR,
            Self::SaltFromStrError(_) => DATAERR,
            Self::UnsuportedStrLength(_) => DATAERR,
        }
    }
}

impl Display for HshErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HshErr::IncorrectSaltLength(msg) => {
                f.write_str(&format!("incorrect salt length ({})", msg))
            }
            HshErr::SaltFromStrError(msg) => f.write_str(&format!("error parsing salt: {}", msg)),
            HshErr::UnsuportedStrLength(msg) => {
                f.write_str(&format!("unsuported string length: {}", msg))
            }
        }
    }
}

impl Error for HshErr {}

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
    fn test_hsh_err_exit_code_incorrect_salt_length() {
        let err = HshErr::IncorrectSaltLength("should be 16 bytes, found 22".to_string());
        let code = err.exitcode();
        assert_eq!(65i32, code);
    }

    #[test]
    fn test_hsh_err_exit_code_salt_from_str_error() {
        let err = HshErr::SaltFromStrError("salt cannot be blank".to_string());
        let code = err.exitcode();
        assert_eq!(65i32, code);
    }

    #[test]
    fn test_hsh_err_exit_code_unsuported_str_length() {
        let err = HshErr::UnsuportedStrLength("".to_string());
        let code = err.exitcode();
        assert_eq!(65i32, code);
    }

    #[test]
    fn test_hsh_err_display_incorrect_salt_length() {
        let err = HshErr::IncorrectSaltLength("should be 16 bytes, found 22".to_string());
        let msg = format!("{}", err);
        assert_eq!("incorrect salt length (should be 16 bytes, found 22)", &msg);
    }

    #[test]
    fn test_hsh_err_display_salt_from_str_error() {
        let err = HshErr::SaltFromStrError("salt cannot be blank".to_string());
        let msg = format!("{}", err);
        assert_eq!("error parsing salt: salt cannot be blank", &msg);
    }

    #[test]
    fn test_hsh_err_display_unsuported_str_length() {
        let err = HshErr::UnsuportedStrLength(
            "input string for bcrypt hash function must be between 0 and 72 bytes".to_string(),
        );
        let msg = format!("{}", err);
        assert_eq!(
            "unsuported string length: input string for bcrypt hash function must be between 0 and 72 bytes",
            &msg
        );
    }

    #[test]
    fn test_hsh_result_unwrap_or_exit_ok() {
        let res: HshResult<&'static str> = Ok("Hello, world!");
        assert_eq!("Hello, world!", res.unwrap_or_exit());
    }
}
