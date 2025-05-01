use alloy_primitives::{keccak256, Bytes, B256, U256};
use alloy_rlp::Decodable;
use alloy_trie::{nodes::TrieNode, proof::verify_proof, Nibbles, TrieAccount};
use alloy_wormhole::{WormholeSecret, WORMHOLE_NULLIFIER_ADDRESS};

pub fn execute_wormhole_program(input: WormholeProgramInput) -> WormholeProgramOutput {
    // Validate the input.
    assert!(input.secret.is_valid(), "Secret must be valid");

    if input.withdrawal_index.is_zero() {
        if !input.cumulative_withdrawn_amount.is_zero() {
            panic!("cumulative withdrawn amount must be 0 for first withdrawal")
        }

        if !input.previous_nullifier_storage_proof.is_empty() {
            panic!("storage proof for previous nullifier must be empty")
        }
    }

    if input
        .withdraw_amount
        .checked_add(input.cumulative_withdrawn_amount)
        .unwrap()
        < input.deposit_amount
    {
        panic!("withdraw amounts exceed the original deposit amount")
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
    )
    .expect("deposit account proof validation failed");

    // Verify the Wormhole nullifier account state proof.
    let nullifier_address_nibbles = Nibbles::unpack(keccak256(&WORMHOLE_NULLIFIER_ADDRESS));
    let nullifier_leaf_node = {
        let last_node_encoded = input.nullifier_account_proof.last().unwrap();
        let nullifier_node = TrieNode::decode(&mut &last_node_encoded[..])
            .expect("nullifier trie node decoding failed");
        if let TrieNode::Leaf(leaf) = nullifier_node {
            leaf
        } else {
            panic!("nullifier account must be present");
        }
    };
    let nullifier_account = TrieAccount::decode(&mut &nullifier_leaf_node.value[..])
        .expect("nullifier trie account decoding failed");
    verify_proof(
        input.state_root,
        nullifier_address_nibbles,
        Some(nullifier_leaf_node.value),
        &input.nullifier_account_proof,
    )
    .expect("nullifier account proof validation failed");

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
        )
        .expect("previous nullifier inclusion storage proof validation failed");
    }

    // Compute current nullifier to commit to.
    let current_nullifier = input.secret.nullifier(input.withdrawal_index);

    // Return the program output.
    WormholeProgramOutput {
        state_root: input.state_root,
        withdraw_amount: input.withdraw_amount,
        current_nullifier,
        cumulative_withdrawn_amount_hashed,
    }
}

/// The input into zkvm program.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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
    /// The Wormhole nullifier contract account proof.
    pub nullifier_account_proof: Vec<Bytes>,
    /// The inclusion storage proof of previous nullifier.
    /// Must be empty if withdrawal index is zero.
    pub previous_nullifier_storage_proof: Vec<Bytes>,
}

/// The output of the zkvm program.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WormholeProgramOutput {
    /// The state root of the block to validate against provided as part of the input.
    pub state_root: B256,
    /// The withdraw amount provided as part of the input.
    pub withdraw_amount: U256,
    /// The nullifier the withdrawal is for.
    pub current_nullifier: B256,
    /// The keccak256 of cumulative withdrawn amount.
    pub cumulative_withdrawn_amount_hashed: B256,
}
