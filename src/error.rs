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
