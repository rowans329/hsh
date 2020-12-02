// Std imports
use std::str::FromStr;

// External imports
use atty::Stream;
use chrono::Local;
use fern::{
    colors::{Color, ColoredLevelConfig},
    Dispatch,
};
use log::LevelFilter;
use structopt::StructOpt;

// Lib imports
use hsh::error::{HshResult, UnwrapOrExit};
use hsh::format::FORMAT_MODE;
use hsh::hash;
use hsh::types::{Format, HashFunction, Salt};

fn parse_verbosity(v: u64) -> LevelFilter {
    match v {
        0 => LevelFilter::Off,
        1 => LevelFilter::Warn,
        2 => LevelFilter::Info,
        3 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    }
}

#[derive(Debug, StructOpt)]
#[structopt(about = "A simple string-hashing CLI that supports a wide variety of hash functions")]
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
    /// Pass multiple times for increased log output
    ///
    /// By default, only errors are reported. Passing `-v` also prints warnings, `-vv` enables info logging, `-vvv` debug, and `-vvvv` trace.
    #[structopt(short, long="verbose", parse(from_occurrences = parse_verbosity))]
    verbosity: LevelFilter,
}

fn main() {
    let opt = setup();
    let salt = parse_salt(&opt).unwrap_or_exit();
    let hash = hash(&opt.string, opt.function, opt.cost, salt).unwrap_or_exit();
    println!("{}", hash);
    std::process::exit(exitcode::OK);
}

fn setup() -> Opt {
    let opt = Opt::from_args();
    let coloured = clicolors_control::colors_enabled() && atty::is(Stream::Stdout);
    setup_logger(opt.verbosity, coloured).unwrap();
    FORMAT_MODE.init(opt.format, opt.salt_format.unwrap_or(opt.format));
    opt
}

fn setup_logger(log_level: LevelFilter, colour: bool) -> Result<(), fern::InitError> {
    let colours: ColoredLevelConfig = ColoredLevelConfig::new()
        .warn(Color::Yellow)
        .info(Color::Blue)
        .trace(Color::BrightBlack);

    Dispatch::new()
        .chain(
            Dispatch::new()
                .format(move |out, message, record| {
                    if colour {
                        out.finish(format_args!(
                            "[{}] {}",
                            colours.color(record.level()),
                            message,
                        ))
                    } else {
                        out.finish(format_args!("[{}] {}", record.level(), message,))
                    }
                })
                .level(LevelFilter::Error)
                .chain(std::io::stderr()),
        )
        .chain(
            Dispatch::new()
                .filter(|metadata| metadata.level() != LevelFilter::Error)
                .format(move |out, message, record| {
                    if colour {
                        out.finish(format_args!(
                            "{}[{}][{}] {}",
                            Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                            record.target(),
                            colours.color(record.level()),
                            message,
                        ))
                    } else {
                        out.finish(format_args!(
                            "{}[{}][{}] {}",
                            Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                            record.target(),
                            record.level(),
                            message,
                        ))
                    }
                })
                .level(log_level)
                .chain(std::io::stdout()),
        )
        .apply()?;
    Ok(())
}

fn parse_salt(opt: &Opt) -> HshResult<Option<Salt>> {
    if opt.salt.is_none() {
        Ok(None)
    } else {
        Ok(Some(Salt::from_str(&opt.salt.clone().unwrap())?))
    }
}
