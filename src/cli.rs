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
        self.salt_format.unwrap_or(self.format())
    }

    fn verbosity(&self) -> LevelFilter {
        self.verbosity
    }
}
