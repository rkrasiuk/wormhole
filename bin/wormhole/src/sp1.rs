use anyhow::Context;
use clap::{Parser, Subcommand};
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};
use std::{fs, path::PathBuf};
use wormhole_program_core::WormholeProgramInput;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const WORMHOLE_PROGRAM_SP1_ELF: &[u8] = include_elf!("wormhole-program-sp1");

#[derive(Parser, Debug)]
pub struct Sp1Command {
    #[clap(subcommand)]
    subcommand: Sp1Subcommand,

    #[clap(long)]
    input: PathBuf,
}

impl Sp1Command {
    pub fn run(self) -> anyhow::Result<()> {
        // Setup the logger.
        sp1_sdk::utils::setup_logger();

        // Setup the prover client.
        let client = ProverClient::from_env();

        // Setup the inputs.
        let input: WormholeProgramInput = serde_json::from_slice(&fs::read(&self.input)?)?;
        let mut stdin = SP1Stdin::new();
        stdin.write(&input);

        match self.subcommand {
            Sp1Subcommand::Execute => {
                let (output, report) = client
                    .execute(WORMHOLE_PROGRAM_SP1_ELF, &stdin)
                    .run()
                    .context("program execution failed")?;

                // Print the output.
                println!("Output: {output:?}");

                // Record the number of cycles executed.
                println!("Number of cycles: {}", report.total_instruction_count());
            }
            Sp1Subcommand::Prove { verify, out } => {
                // Setup the program for proving.
                let (pk, vk) = client.setup(WORMHOLE_PROGRAM_SP1_ELF);

                // Generate the proof
                let proof =
                    client.prove(&pk, &stdin).groth16().run().context("proof generation failed")?;

                let proof_bytes = proof.bytes();
                println!("proof: {proof_bytes:?}");

                if let Some(out) = out {
                    fs::write(out, proof_bytes)?;
                }

                if verify {
                    // Verify the proof.
                    client.verify(&proof, &vk).context("proof verification failed")?;
                }
            }
        };

        Ok(())
    }
}

#[derive(Subcommand, Debug)]
pub enum Sp1Subcommand {
    #[command(name = "execute")]
    Execute,
    #[command(name = "prove")]
    Prove {
        /// Flag indicating whether we should verify the proof.
        #[clap(long)]
        verify: bool,

        /// The optional path to write the proof to.
        #[clap(long)]
        out: Option<PathBuf>,
    },
}
