// External imports
use structopt::StructOpt;

// Lib imports
use hsh::{
    hash,
    types::{HashFunction, Salt},
};

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt()]
    string: String,
    #[structopt(short, long)]
    function: HashFunction,
    #[structopt(short, long)]
    bytes: bool,
    #[structopt(short, long, required_if("function", "bcrypt"))]
    cost: Option<u32>,
    #[structopt(short, long, required_if("function", "bcrypt"))]
    salt: Option<Salt>,
}

fn main() {
    let opt = Opt::from_args();
    let hash = hash(&opt.string, opt.function, opt.cost, opt.salt);
    if opt.bytes {
        println!("{:?}", hash.as_bytes());
    } else {
        println!("{}", hash.as_hex());
    }
}
