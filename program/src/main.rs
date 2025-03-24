//! The program for verifying Wormhole Ether deposits.

#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::{keccak256, B256, U256};
use alloy_rlp::Decodable;
use alloy_trie::{nodes::TrieNode, proof::verify_proof, Nibbles, TrieAccount};
use alloy_wormhole::{sp1::Sp1Input, WORMHOLE_NULLIFIER_ADDRESS};

fn main() {
    // Read input.
    let input = sp1_zkvm::io::read::<Sp1Input>();

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

    if input.withdraw_amount + input.cumulative_withdrawn_amount > input.deposit_amount {
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
    if !input.withdrawal_index.is_zero() {
        let previous_withdrawal_index = input.withdrawal_index - U256::from(1);
        let previous_nullifier = input.secret.nullifier(previous_withdrawal_index);
        let previous_nullifier_nibbles = Nibbles::unpack(keccak256(previous_nullifier));
        let expected = alloy_rlp::encode_fixed_size(&input.cumulative_withdrawn_amount).to_vec();
        verify_proof(
            nullifier_account.storage_root,
            previous_nullifier_nibbles,
            Some(expected),
            &input.previous_nullifier_storage_proof,
        )
        .expect("previous nullifier inclusion storage proof validation failed");
    }

    // Verify current withdrawal nullifier exclusion storage proof.
    let current_nullifier = input.secret.nullifier(input.withdrawal_index);
    let current_nullifier_nibbles = Nibbles::unpack(keccak256(current_nullifier));
    verify_proof(
        nullifier_account.storage_root,
        current_nullifier_nibbles,
        None,
        &input.nullifier_storage_proof,
    )
    .expect("nullifier exclusion storage proof validation failed");

    // Commit to the public values of the program.
    sp1_zkvm::io::commit::<B256>(&input.state_root);
    sp1_zkvm::io::commit::<B256>(&current_nullifier);
    sp1_zkvm::io::commit::<U256>(&input.withdraw_amount);
}
