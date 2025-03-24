use alloy_primitives::{Bytes, B256, U256};
use alloy_wormhole::{sp1::Sp1Input, WormholeSecret};
use anyhow::Context;
use clap::{Parser, Subcommand};
use sp1_sdk::{include_elf, ProverClient, SP1Stdin};

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
pub const WORMHOLE_PROGRAM_ELF: &[u8] = include_elf!("wormhole-program");

#[derive(Parser, Debug)]
pub struct Sp1Command {
    #[clap(subcommand)]
    subcommand: Sp1Subcommand,

    #[clap(flatten)]
    args: Sp1ProgramArgs,
}

impl Sp1Command {
    pub fn run(self) -> anyhow::Result<()> {
        // Setup the logger.
        sp1_sdk::utils::setup_logger();

        // Setup the prover client.
        let client = ProverClient::from_env();

        // Setup the inputs.
        let sp1_input = self.args.into_input();
        let mut stdin = SP1Stdin::new();
        stdin.write(&sp1_input);

        match self.subcommand {
            Sp1Subcommand::Execute => {
                let (output, report) = client
                    .execute(WORMHOLE_PROGRAM_ELF, &stdin)
                    .run()
                    .context("program execution failed")?;

                // Print the output.
                println!("Output: {output:?}");

                // Record the number of cycles executed.
                println!("Number of cycles: {}", report.total_instruction_count());
            }
            Sp1Subcommand::Prove { verify } => {
                // Setup the program for proving.
                let (pk, vk) = client.setup(WORMHOLE_PROGRAM_ELF);

                // Generate the proof
                let proof = client
                    .prove(&pk, &stdin)
                    .groth16()
                    .run()
                    .context("proof generation failed")?;

                // TODO: optionally write to a file
                println!("proof: {:?}", proof.bytes());

                if verify {
                    // Verify the proof.
                    client
                        .verify(&proof, &vk)
                        .context("proof verification failed")?;
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
        verify: bool,
    },
}

#[derive(Parser, Debug)]
struct Sp1ProgramArgs {
    #[clap(long)]
    secret: Bytes,

    #[clap(long)]
    deposit_value: U256,

    #[clap(long)]
    withdraw_value: U256,

    #[clap(long)]
    state_root: B256,

    #[clap(long, num_args = 1.., value_delimiter = ',')]
    deposit_proof: Vec<Bytes>,
}

impl Sp1ProgramArgs {
    fn into_input(self) -> Sp1Input {
        let secret = WormholeSecret::try_from(self.secret).unwrap();
        Sp1Input {
            secret,
            deposit_amount: self.deposit_value,
            withdraw_amount: self.withdraw_value,
            state_root: self.state_root,
            deposit_account_proof: self.deposit_proof,
        }
    }
}
