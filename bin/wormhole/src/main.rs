use clap::Parser;
use wormhole::Cli;

#[tokio::main]
async fn main() {
    if let Err(error) = Cli::parse().run().await {
        eprintln!("Error: {error:?}");
        std::process::exit(1);
    }
}
