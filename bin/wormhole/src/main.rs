use clap::Parser;
use wormhole::Cli;

fn main() {
    if let Err(error) = Cli::parse().run() {
        eprintln!("Error: {error:?}");
        std::process::exit(1);
    }
}
