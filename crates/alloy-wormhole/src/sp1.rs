use crate::WormholeSecret;
use alloy_primitives::{Bytes, B256, U256};
use serde::{Deserialize, Serialize};

/// The inputs into SP1 program.
#[derive(Serialize, Deserialize, Debug)]
pub struct Sp1Input {
    /// The Wormhole secret.
    pub secret: WormholeSecret,
    /// The deposit (burn) amount.
    pub deposit_amount: U256,
    /// The withdraw amount.
    pub withdraw_amount: U256,
    /// The cumulative withdrawn amount.
    pub cumulative_withdrawn_amount: U256,
    /// The index of the current withdrawal.
    pub withdrawal_index: U256,
    /// The state root of the block to validate against.
    pub state_root: B256,
    /// The deposit account proof.
    pub deposit_account_proof: Vec<Bytes>,
    /// The Wormhole nullifier contract account proof.
    pub nullifier_account_proof: Vec<Bytes>,
    /// The inclusion storage proof of previous nullifier.
    /// Must be empty if withdrawal index is zero.
    pub previous_nullifier_storage_proof: Vec<Bytes>,
    /// The exclusion storage proof for the current nullifier.
    pub nullifier_storage_proof: Vec<Bytes>,
}
