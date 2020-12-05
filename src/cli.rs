// Std imports
use std::str::FromStr;

// External imports
use log::{debug, LevelFilter};
use structopt::StructOpt;

// Lib imports
use crate::error::HshResult;
use crate::format::FORMAT_MODE;
use crate::types::{Format, HashFunction, Salt};
use crate::utils::parse_verbosity;

#[derive(Debug, StructOpt)]
#[structopt(about = "A simple string-hashing CLI that supports a wide variety of hash functions")]
pub struct Cli {
    /// The string to be hashed
    #[structopt()]
    string: String,
    /// The hash function to use
    #[structopt(possible_values = &HashFunction::variants(), case_insensitive=true)]
    function: HashFunction,
    /// The cost to use when hashing with the Bcrypt hash function
    #[structopt(short, long, required_if("function", "bcrypt"))]
    cost: Option<u32>,
    /// The 16-byte salt to use when hashing with the Bcrypt hash function
    #[structopt(short, long, required_if("function", "bcrypt"))]
    salt: Option<String>,
    /// The format in which to display the output hash
    #[structopt(long, env="HSH_FORMAT", possible_values = &Format::variants(), case_insensitive=true, default_value="hex")]
    format: Format,
    /// The format of the salt argument (defaults to the value of `format`)
    #[structopt(long, env="SALT_FORMAT", possible_values = &Format::variants(), case_insensitive=true)]
    salt_format: Option<Format>,
    /// Pass multiple times for increased log output
    ///
    /// By default, only errors are reported. Passing `-v` also prints warnings, `-vv` enables info logging, `-vvv` debug, and `-vvvv` trace.
    #[structopt(short, long="verbose", parse(from_occurrences = parse_verbosity))]
    verbosity: LevelFilter,
}

impl Cli {
    pub fn parse_from_args() -> Self {
        let cli = Cli::from_args();
        crate::utils::setup_logger(cli.verbosity()).unwrap();
        debug!("cli args: {:#?}", cli);
        cli
    }

    pub fn setup(self) -> Self {
        FORMAT_MODE.init(self.format(), self.salt_format());
        self
    }

    pub fn string(&self) -> &str {
        &self.string
    }

    pub fn function(&self) -> HashFunction {
        self.function
    }

    pub fn cost(&self) -> Option<u32> {
        self.cost
    }

    pub fn salt(&self) -> HshResult<Option<Salt>> {
        if self.salt.is_none() {
            Ok(None)
        } else {
            Ok(Some(Salt::from_str(&self.salt.clone().unwrap())?))
        }
    }

    fn format(&self) -> Format {
        self.format
    }

    fn salt_format(&self) -> Format {
        self.salt_format.unwrap_or_else(|| self.format())
    }

    fn verbosity(&self) -> LevelFilter {
        self.verbosity
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_cli_get_string() {
        let cli = Cli {
            string: String::from("password"),
            function: HashFunction::Sha1,
            cost: None,
            salt: None,
            format: Format::Hex,
            salt_format: None,
            verbosity: LevelFilter::Off,
        };

        assert_eq!("password", cli.string());
    }

    #[test]
    fn test_cli_get_function() {
        let cli = Cli {
            string: String::from("password"),
            function: HashFunction::Sha1,
            cost: None,
            salt: None,
            format: Format::Hex,
            salt_format: None,
            verbosity: LevelFilter::Off,
        };

        assert_eq!(HashFunction::Sha1, cli.function());
    }

    #[test]
    fn test_cli_get_cost() {
        let cli = Cli {
            string: String::from("password"),
            function: HashFunction::Sha1,
            cost: Some(12),
            salt: None,
            format: Format::Hex,
            salt_format: None,
            verbosity: LevelFilter::Off,
        };

        assert_eq!(12, cli.cost().unwrap());
    }

    #[test]
    fn test_cli_get_salt_base64_valid() {
        let cli = Cli {
            string: String::from("password"),
            function: HashFunction::Sha1,
            cost: None,
            salt: Some(String::from("NjQwMTU4NDkyNTc2MDM3NQ==")),
            format: Format::Hex,
            salt_format: Some(Format::Base64),
            verbosity: LevelFilter::Off,
        };

        FORMAT_MODE.test_with_formats(cli.format(), cli.salt_format(), || {
            assert_eq!(
                Salt::new([54, 52, 48, 49, 53, 56, 52, 57, 50, 53, 55, 54, 48, 51, 55, 53]),
                cli.salt().unwrap().unwrap(),
            );
        })
    }

    #[test]
    fn test_cli_get_salt_base64_invalid() {
        let cli = Cli {
            string: String::from("password"),
            function: HashFunction::Sha1,
            cost: None,
            salt: Some(String::from("invalid base64")),
            format: Format::Hex,
            salt_format: Some(Format::Base64),
            verbosity: LevelFilter::Off,
        };

        FORMAT_MODE.test_with_formats(cli.format(), cli.salt_format(), || {
            assert!(cli.salt().is_err());
        })
    }

    #[test]
    fn test_cli_get_salt_bytes_valid() {
        let cli = Cli {
            string: String::from("password"),
            function: HashFunction::Sha1,
            cost: None,
            salt: Some(String::from("[1,6,3,20,4,0,61,189,4,2,8,7,0,7,77,16]")),
            format: Format::Hex,
            salt_format: Some(Format::Bytes),
            verbosity: LevelFilter::Off,
        };

        FORMAT_MODE.test_with_formats(cli.format(), cli.salt_format(), || {
            assert_eq!(
                Salt::new([1, 6, 3, 20, 4, 0, 61, 189, 4, 2, 8, 7, 0, 7, 77, 16]),
                cli.salt().unwrap().unwrap(),
            );
        })
    }

    #[test]
    fn test_cli_get_salt_bytes_invalid() {
        let cli = Cli {
            string: String::from("password"),
            function: HashFunction::Sha1,
            cost: None,
            salt: Some(String::from("invalid bytes")),
            format: Format::Hex,
            salt_format: Some(Format::Bytes),
            verbosity: LevelFilter::Off,
        };

        FORMAT_MODE.test_with_formats(cli.format(), cli.salt_format(), || {
            assert!(cli.salt().is_err());
        })
    }

    #[test]
    fn test_cli_get_salt_hex_valid() {
        let cli = Cli {
            string: String::from("password"),
            function: HashFunction::Sha1,
            cost: None,
            salt: Some(String::from("dfcd71fb5c9f17bdd0efbe529cc4fcfb")),
            format: Format::Hex,
            salt_format: Some(Format::Hex),
            verbosity: LevelFilter::Off,
        };

        FORMAT_MODE.test_with_formats(cli.format(), cli.salt_format(), || {
            assert_eq!(
                Salt::new([
                    223, 205, 113, 251, 92, 159, 23, 189, 208, 239, 190, 82, 156, 196, 252, 251
                ]),
                cli.salt().unwrap().unwrap(),
            );
        })
    }

    #[test]
    fn test_cli_get_salt_hex_invalid() {
        let cli = Cli {
            string: String::from("password"),
            function: HashFunction::Sha1,
            cost: None,
            salt: Some(String::from("invalid hex")),
            format: Format::Hex,
            salt_format: Some(Format::Hex),
            verbosity: LevelFilter::Off,
        };

        FORMAT_MODE.test_with_formats(cli.format(), cli.salt_format(), || {
            assert!(cli.salt().is_err());
        })
    }

    #[test]
    fn test_cli_get_format() {
        let cli = Cli {
            string: String::from("password"),
            function: HashFunction::Sha1,
            cost: None,
            salt: None,
            format: Format::Base64,
            salt_format: None,
            verbosity: LevelFilter::Off,
        };

        assert_eq!(Format::Base64, cli.format());
    }

    #[test]
    fn test_cli_get_salt_format() {
        let cli = Cli {
            string: String::from("password"),
            function: HashFunction::Sha1,
            cost: None,
            salt: None,
            format: Format::Hex,
            salt_format: Some(Format::Bytes),
            verbosity: LevelFilter::Off,
        };

        assert_eq!(Format::Bytes, cli.salt_format());
    }

    #[test]
    fn test_cli_get_salt_format_default() {
        let cli = Cli {
            string: String::from("password"),
            function: HashFunction::Sha1,
            cost: None,
            salt: None,
            format: Format::Base64,
            salt_format: None,
            verbosity: LevelFilter::Off,
        };

        assert_eq!(Format::Base64, cli.salt_format());
    }

    #[test]
    fn test_cli_get_verbosity() {
        let cli = Cli {
            string: String::from("password"),
            function: HashFunction::Sha1,
            cost: None,
            salt: None,
            format: Format::Hex,
            salt_format: None,
            verbosity: LevelFilter::Debug,
        };

        assert_eq!(LevelFilter::Debug, cli.verbosity());
    }
}
