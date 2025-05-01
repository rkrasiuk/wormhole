use alloy_primitives::{Bytes, B256, U256};
use alloy_wormhole::WormholeSecret;
use clap::Parser;
use wormhole_program_core::WormholeProgramInput;

#[derive(Parser, Debug)]
pub struct ProgramInputArgs {
    #[clap(long)]
    pub secret: Bytes,

    #[clap(long)]
    pub deposit_amount: U256,

    #[clap(long)]
    pub withdraw_amount: U256,

    #[clap(long)]
    pub cumulative_withdrawn_amount: U256,

    #[clap(long)]
    pub withdrawal_index: U256,

    #[clap(long)]
    pub state_root: B256,

    #[clap(long, num_args = 1.., value_delimiter = ',')]
    pub deposit_account_proof: Vec<Bytes>,

    #[clap(long, num_args = 1.., value_delimiter = ',')]
    pub nullifier_account_proof: Vec<Bytes>,

    #[clap(long, value_delimiter = ',')]
    pub previous_nullifier_storage_proof: Vec<Bytes>,
}

impl ProgramInputArgs {
    pub fn into_input(self) -> WormholeProgramInput {
        let secret = WormholeSecret::try_from(self.secret).unwrap();
        WormholeProgramInput {
            secret,
            deposit_amount: self.deposit_amount,
            withdraw_amount: self.withdraw_amount,
            cumulative_withdrawn_amount: self.cumulative_withdrawn_amount,
            withdrawal_index: self.withdrawal_index,
            state_root: self.state_root,
            deposit_account_proof: self.deposit_account_proof,
            nullifier_account_proof: self.nullifier_account_proof,
            previous_nullifier_storage_proof: self.previous_nullifier_storage_proof,
        }
    }
}
