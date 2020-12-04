// Std imports
use std::cmp::PartialEq;
use std::error::Error;
use std::fmt::{self, Debug, Display};

// External imports
use exitcode::{ExitCode, DATAERR};
use log::error;

#[derive(Debug, PartialEq)]
pub enum HshError {
    SaltFromStrError(SaltFromStrError),
    UnsuportedBcryptLength,
}

impl HshError {
    pub fn exitcode(&self) -> ExitCode {
        match self {
            Self::SaltFromStrError(_) => DATAERR,
            Self::UnsuportedBcryptLength => DATAERR,
        }
    }
}

impl Display for HshError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::SaltFromStrError(msg) => {
                f.write_fmt(format_args!("error parsing salt: {}", msg))
            }
            Self::UnsuportedBcryptLength => {
                f.write_str("input string for bcrypt hash function must be between 0 and 72 bytes")
            }
        }
    }
}

impl Error for HshError {}

impl From<SaltFromStrError> for HshError {
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

pub type HshResult<T> = Result<T, HshError>;

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
