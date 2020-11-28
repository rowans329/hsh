// External imports
use human_panic::setup_panic;
use structopt::StructOpt;

// Lib imports
use hsh::{
    hash,
    types::{HashFunction, Salt},
};

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
    salt: Option<Salt>,
}

fn main() {
    setup_panic!();
    let opt = Opt::from_args();
    let hash = hash(&opt.string, opt.function, opt.cost, opt.salt);
    println!("{}", hash.as_hex());
}
