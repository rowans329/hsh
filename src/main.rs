// Std imports
use std::str::FromStr;

// External imports
use structopt::StructOpt;

// Lib imports
use hsh::error::HshResult;
use hsh::format::FORMAT_MODE;
use hsh::hash;
use hsh::types::{Format, HashFunction, Salt};

#[derive(Debug, StructOpt)]
struct Opt {
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
}

fn main() {
    let opt = setup();
    let salt = parse_salt(&opt).unwrap_or_else(|err| {
        eprintln!("{}", err);
        std::process::exit(exitcode::DATAERR);
    });
    let hash_res = hash(&opt.string, opt.function, opt.cost, salt);
    if hash_res.is_err() {
        eprintln!("{}", hash_res.unwrap_err());
        std::process::exit(exitcode::DATAERR);
    }
    println!("{}", hash_res.unwrap());
    std::process::exit(exitcode::OK);
}

fn setup() -> Opt {
    let opt = Opt::from_args();
    FORMAT_MODE.init(opt.format, opt.salt_format.unwrap_or(opt.format));
    opt
}

fn parse_salt(opt: &Opt) -> HshResult<Option<Salt>> {
    if opt.salt.is_none() {
        Ok(None)
    } else {
        Ok(Some(Salt::from_str(&opt.salt.clone().unwrap())?))
    }
}
