use clap::{Parser, Subcommand};
use risc0_zkvm::{default_executor, default_prover, ExecutorEnv, ProverOpts};
use std::{fs, path::PathBuf};
use wormhole_program_core::{WormholeProgramInput, WormholeProgramOutput};

include!(concat!(env!("OUT_DIR"), "/methods.rs"));

#[derive(Parser, Debug)]
pub struct Risc0Command {
    #[clap(subcommand)]
    subcommand: Risc0Subcommand,

    #[clap(long)]
    input: PathBuf,
}

impl Risc0Command {
    pub fn run(self) -> anyhow::Result<()> {
        let input: WormholeProgramInput = serde_json::from_slice(&fs::read(&self.input)?)?;
        let env = ExecutorEnv::builder()
            // Send input to the guest
            .write(&input)?
            .build()?;

        match self.subcommand {
            Risc0Subcommand::Execute => {
                let executor = default_executor();
                let session = executor.execute(env, WORMHOLE_PROGRAM_RISC0_ELF)?;

                // Print the output.
                let output: WormholeProgramOutput = session.journal.decode()?;
                println!("Output: {output:?}");

                // Record the number of cycles executed.
                println!("Number of cycles: {}", session.cycles());
            }
            Risc0Subcommand::Prove { verify } => {
                // Obtain the default prover.
                let prover = default_prover();

                // Generate groth16 proof of program execution.
                let info = prover.prove_with_opts(
                    env,
                    WORMHOLE_PROGRAM_RISC0_ELF,
                    &ProverOpts::groth16(),
                )?;
                println!("Receipt: {:?}", info.receipt);

                let output: WormholeProgramOutput = info.receipt.journal.decode()?;
                println!("Output: {output:?}");

                if verify {
                    info.receipt.verify(WORMHOLE_PROGRAM_RISC0_ID)?;
                }
            }
        }

        Ok(())
    }
}

#[derive(Subcommand, Debug)]
pub enum Risc0Subcommand {
    #[command(name = "execute")]
    Execute,
    #[command(name = "prove")]
    Prove {
        /// Flag indicating whether we should verify the proof.
        #[clap(long)]
        verify: bool,
    },
}
