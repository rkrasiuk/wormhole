use alloy_primitives::{hex, U256};
use alloy_wormhole::WormholeSecret;
use clap::{Parser, Subcommand};
use std::time::Instant;

mod input;

mod sp1;
use sp1::Sp1Command;

#[allow(dead_code)]
mod risc0;
use risc0::Risc0Command;

#[derive(Parser, Debug)]
pub struct Cli {
    #[clap(subcommand)]
    command: Command,
}

impl Cli {
    pub fn run(self) -> anyhow::Result<()> {
        match self.command {
            Command::NewSecret => {
                let started_at = Instant::now();
                let secret = WormholeSecret::random();
                println!("Generated new secret in {:?}", started_at.elapsed());
                println!("Secret: {}", hex::encode(secret.as_ref()));
                println!("Burn Address: {}", secret.burn_address());
                println!("Nullifier(0): {}", secret.nullifier(U256::ZERO));
                Ok(())
            }
            Command::Sp1(cmd) => cmd.run(),
            Command::Risc0(cmd) => cmd.run(),
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum Command {
    #[command(name = "new-secret")]
    NewSecret,
    #[command(name = "sp1")]
    Sp1(Sp1Command),
    #[command(name = "risc0")]
    Risc0(Risc0Command),
}
