use alloy_eips::{BlockId, BlockNumberOrTag};
use alloy_primitives::{Address, Bytes, U256};
use alloy_provider::{network::Ethereum, Provider, RootProvider};
use alloy_wormhole::WormholeSecret;
use clap::Parser;
use wormhole_program_core::{WormholeProgramError, WormholeProgramInput};

#[derive(Parser, Debug)]
pub struct CreateInputCommand {
    /// The Wormhole secret.
    #[clap(long)]
    pub secret: Bytes,

    /// The node RPC URL.
    #[clap(long)]
    pub rpc_url: String,

    /// The address of the nullifier contract.
    #[clap(long)]
    pub nullifier_address: Address,

    /// Withdraw amount.
    #[clap(long)]
    pub withdraw_amount: U256,

    /// Withdrawal index.
    #[clap(long)]
    pub withdrawal_index: Option<U256>,

    /// Cumulative withdrawn amount.
    #[clap(long)]
    pub cumulative_withdrawn_amount: Option<U256>,
}

impl CreateInputCommand {
    pub async fn run(self) -> anyhow::Result<()> {
        let secret = WormholeSecret::try_from(self.secret)
            .map_err(|_| WormholeProgramError::InvalidSecret)?;

        let provider = RootProvider::<Ethereum>::connect(&self.rpc_url).await?;

        let block_id = BlockId::Number(BlockNumberOrTag::Latest);
        let block = provider
            .get_block(block_id)
            .await?
            .ok_or(anyhow::anyhow!("unknown block"))?;

        let deposit_address = secret.burn_address();
        let deposit_proof = provider
            .get_proof(deposit_address, Vec::new())
            .block_id(block_id)
            .await?;

        let cumulative_withdrawn_amount = self.cumulative_withdrawn_amount.unwrap_or_default();
        if self
            .withdraw_amount
            .saturating_add(cumulative_withdrawn_amount)
            > deposit_proof.balance
        {
            return Err(WormholeProgramError::InvalidWithdrawAmount.into());
        }

        let mut nullifier_keys = Vec::new();
        let withdrawal_index = self.withdrawal_index.unwrap_or_default();
        if !withdrawal_index.is_zero() {
            nullifier_keys.push(secret.nullifier(withdrawal_index - U256::from(1)));
        }
        let mut nullifier_proof = provider
            .get_proof(self.nullifier_address, nullifier_keys)
            .block_id(block_id)
            .await?;
        let previous_nullifier_storage_proof = if withdrawal_index.is_zero() {
            Vec::new()
        } else {
            // TODO: validate against `cumulative_withdrawn_amount`
            nullifier_proof
                .storage_proof
                .pop()
                .ok_or(anyhow::anyhow!("missing previous nullifier proof"))?
                .proof
        };

        let input = WormholeProgramInput {
            secret,
            deposit_amount: deposit_proof.balance,
            withdraw_amount: self.withdraw_amount,
            cumulative_withdrawn_amount,
            withdrawal_index,
            state_root: block.header.state_root,
            deposit_account_proof: deposit_proof.account_proof,
            nullifier_address: self.nullifier_address,
            nullifier_account_proof: nullifier_proof.account_proof,
            previous_nullifier_storage_proof,
        };

        println!("{}", serde_json::to_string_pretty(&input)?);

        Ok(())
    }
}
