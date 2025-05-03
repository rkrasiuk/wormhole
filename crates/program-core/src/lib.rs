use alloy_primitives::{keccak256, Address, Bytes, B256, U256};
use alloy_rlp::Decodable;
use alloy_trie::{
    nodes::TrieNode,
    proof::{verify_proof, ProofVerificationError},
    Nibbles, TrieAccount,
};
use alloy_wormhole::WormholeSecret;
use core::fmt;

/// Executes the Wormhole withdrawal verification program.
///
/// This function validates a user's withdrawal from a previously deposited (burned)
/// amount in a privacy-preserving manner. It performs several cryptographic and
/// state-based checks to ensure the withdrawal is legitimate:
///
/// 1. Validates the secret used to generate nullifiers.
/// 2. Verifies the correctness of the withdrawal amount against deposit and previously
///    withdrawn amounts.
/// 3. Checks consistency of withdrawal index and related storage proof input.
/// 4. Validates Merkle-Patricia Trie proofs for:
///     - The deposit account state,
///     - The Wormhole nullifier account,
///     - The previous withdrawal's nullifier inclusion in storage (if applicable).
///
/// Upon successful validation, it computes the current nullifier for this withdrawal
/// and returns the resulting program output.
///
/// # Parameters
///
/// * `input` - A [`WormholeProgramInput`] struct containing all required data for proof verification.
///
/// # Returns
///
/// * `Ok(WormholeProgramOutput)` - If all validations and proof checks succeed.
/// * `Err(WormholeProgramError)` - If any validation fails, or if a decoding/proof error occurs.
pub fn execute_wormhole_program(
    input: WormholeProgramInput,
) -> Result<WormholeProgramOutput, WormholeProgramError> {
    // Validate the input.
    if !input.secret.is_valid() {
        return Err(WormholeProgramError::InvalidSecret);
    }

    // Validate withdraw amount
    if input.withdraw_amount.is_zero() {
        return Err(WormholeProgramError::InvalidWithdrawAmount);
    }
    let next_cumulative_withdrawn_amount = input
        .withdraw_amount
        .checked_add(input.cumulative_withdrawn_amount)
        .ok_or(WormholeProgramError::InvalidWithdrawAmount)?;
    if next_cumulative_withdrawn_amount > input.deposit_amount {
        return Err(WormholeProgramError::InvalidWithdrawAmount);
    }

    // Validate withdrawal index against other input fields.
    if input.withdrawal_index.is_zero() {
        if !input.cumulative_withdrawn_amount.is_zero() {
            panic!("cumulative withdrawn amount must be 0 for first withdrawal")
        }

        if !input.previous_nullifier_storage_proof.is_empty() {
            panic!("storage proof for previous nullifier must be empty")
        }
    }

    // Verify the deposit account state proof.
    let deposit_address = input.secret.burn_address();
    let deposit_address_nibbles = Nibbles::unpack(keccak256(&deposit_address));
    let expected = alloy_rlp::encode(TrieAccount {
        balance: input.deposit_amount,
        ..Default::default()
    });
    verify_proof(
        input.state_root,
        deposit_address_nibbles,
        Some(expected),
        &input.deposit_account_proof,
    )?;

    // Verify the Wormhole nullifier account state proof.
    let nullifier_address_nibbles = Nibbles::unpack(keccak256(&input.nullifier_address));
    let nullifier_leaf_node = {
        let last_node_encoded = input.nullifier_account_proof.last().unwrap();
        let nullifier_node = TrieNode::decode(&mut &last_node_encoded[..])?;
        if let TrieNode::Leaf(leaf) = nullifier_node {
            leaf
        } else {
            return Err(WormholeProgramError::NullifierAccountMissing);
        }
    };
    let nullifier_account = TrieAccount::decode(&mut &nullifier_leaf_node.value[..])?;
    verify_proof(
        input.state_root,
        nullifier_address_nibbles,
        Some(nullifier_leaf_node.value),
        &input.nullifier_account_proof,
    )?;

    // Verify previous withdrawal nullifier inclusion storage proof.
    let cumulative_withdrawn_amount_hashed =
        keccak256(B256::new(input.cumulative_withdrawn_amount.to_be_bytes()));
    if !input.withdrawal_index.is_zero() {
        let previous_withdrawal_index = input.withdrawal_index - U256::from(1);
        let previous_nullifier = input.secret.nullifier(previous_withdrawal_index);
        let previous_nullifier_nibbles = Nibbles::unpack(keccak256(previous_nullifier));
        let expected = alloy_rlp::encode_fixed_size(&cumulative_withdrawn_amount_hashed).to_vec();
        verify_proof(
            nullifier_account.storage_root,
            previous_nullifier_nibbles,
            Some(expected),
            &input.previous_nullifier_storage_proof,
        )?;
    }

    // Compute current nullifier to commit to.
    let current_nullifier = input.secret.nullifier(input.withdrawal_index);

    // Return the program output.
    Ok(WormholeProgramOutput {
        nullifier_address: input.nullifier_address,
        state_root: input.state_root,
        withdraw_amount: input.withdraw_amount,
        current_nullifier,
        cumulative_withdrawn_amount_hashed,
    })
}

/// The input into zkvm program.
#[derive(PartialEq, Eq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(test, derive(Default))]
pub struct WormholeProgramInput {
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
    /// The address of the nullifier system contract.
    pub nullifier_address: Address,
    /// The Wormhole nullifier contract account proof.
    pub nullifier_account_proof: Vec<Bytes>,
    /// The inclusion storage proof of previous nullifier.
    /// Must be empty if withdrawal index is zero.
    pub previous_nullifier_storage_proof: Vec<Bytes>,
}

/// The output of the zkvm program.
#[derive(PartialEq, Eq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WormholeProgramOutput {
    /// The address of the nullifier system contract.
    pub nullifier_address: Address,
    /// The state root of the block to validate against provided as part of the input.
    pub state_root: B256,
    /// The withdraw amount provided as part of the input.
    pub withdraw_amount: U256,
    /// The nullifier the withdrawal is for.
    pub current_nullifier: B256,
    /// The keccak256 of cumulative withdrawn amount.
    pub cumulative_withdrawn_amount_hashed: B256,
}

/// The error returned by Wormhole program.
#[derive(PartialEq, Eq, Debug)]
pub enum WormholeProgramError {
    /// Provided secret is not valid.
    InvalidSecret,
    /// The withdrawal amount is zero, overflows, or exceeds the deposited amount.
    InvalidWithdrawAmount,
    /// The nullifier account proof does not contain a valid leaf.
    NullifierAccountMissing,
    /// RLP decoding failure.
    Rlp(alloy_rlp::Error),
    /// Merkle-Patricia Trie proof verification failure.
    Proof(ProofVerificationError),
}

impl core::error::Error for WormholeProgramError {}

impl fmt::Display for WormholeProgramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSecret => write!(f, "invalid secret"),
            Self::InvalidWithdrawAmount => write!(f, "invalid withdraw amount"),
            Self::NullifierAccountMissing => write!(f, "nullifier account missing"),
            Self::Rlp(error) => write!(f, "rlp: {error}"),
            Self::Proof(error) => write!(f, "invalid proof: {error}"),
        }
    }
}

impl From<alloy_rlp::Error> for WormholeProgramError {
    fn from(error: alloy_rlp::Error) -> Self {
        Self::Rlp(error)
    }
}

impl From<ProofVerificationError> for WormholeProgramError {
    fn from(error: ProofVerificationError) -> Self {
        Self::Proof(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_wormhole::secret::TEST_SECRET;

    #[test]
    fn invalid_secret() {
        let mut input = WormholeProgramInput::default();
        assert_eq!(
            execute_wormhole_program(input.clone()),
            Err(WormholeProgramError::InvalidSecret)
        );

        input.secret = WormholeSecret::new_unchecked(Bytes::from_static(&[0x1, 0x2, 0x3]));
        assert_eq!(
            execute_wormhole_program(input),
            Err(WormholeProgramError::InvalidSecret)
        );
    }

    #[test]
    fn invalid_withdraw_amount() {
        let mut input = WormholeProgramInput::default();
        input.secret = TEST_SECRET;

        assert_eq!(
            execute_wormhole_program(input.clone()),
            Err(WormholeProgramError::InvalidWithdrawAmount)
        );

        input.cumulative_withdrawn_amount = U256::MAX;
        input.withdraw_amount = U256::from(2);
        input.deposit_amount = U256::from(2);
        assert_eq!(
            execute_wormhole_program(input.clone()),
            Err(WormholeProgramError::InvalidWithdrawAmount)
        );

        input.cumulative_withdrawn_amount = U256::ZERO;
        input.deposit_amount = U256::from(1);
        assert_eq!(
            execute_wormhole_program(input.clone()),
            Err(WormholeProgramError::InvalidWithdrawAmount)
        );
    }
}
