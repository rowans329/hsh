// Lib imports
use hsh::cli::Cli;
use hsh::error::UnwrapOrExit;

fn main() {
    let cli = Cli::parse_from_args().setup();
    let hash = hsh::hash(
        cli.string(),
        cli.function(),
        cli.cost(),
        cli.salt().unwrap_or_exit(),
    )
    .unwrap_or_exit();
    println!("{}", hash);
    std::process::exit(exitcode::OK);
}
