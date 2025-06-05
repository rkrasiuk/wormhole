//! Implementation of Wormhole.

#![cfg_attr(not(feature = "std"), no_std)]

use alloy_consensus::{
    transaction::{RlpEcdsaDecodableTx, RlpEcdsaEncodableTx, SignableTransaction},
    Transaction, Typed2718,
};
use alloy_eip2930::AccessList;
use alloy_eips::{eip2718::IsTyped2718, eip7702::SignedAuthorization};
use alloy_primitives::{Address, Bytes, ChainId, Signature, TxKind, B256, U256};
use alloy_rlp::{BufMut, Decodable, Encodable};
use core::mem;

mod constants;
pub use constants::*;

pub mod secret;
pub use secret::WormholeSecret;

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct WormholeTx {
    /// Added as EIP-pub 155: Simple replay attack protection
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub chain_id: ChainId,
    /// A scalar value equal to the number of transactions sent by the sender; formally Tn.
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub nonce: u64,
    /// A scalar value equal to the maximum
    /// amount of gas that should be used in executing
    /// this transaction. This is paid up-front, before any
    /// computation is done and may not be increased
    /// later; formally Tg.
    #[cfg_attr(
        feature = "serde",
        serde(with = "alloy_serde::quantity", rename = "gas", alias = "gasLimit")
    )]
    pub gas_limit: u64,
    /// A scalar value equal to the maximum
    /// amount of gas that should be used in executing
    /// this transaction. This is paid up-front, before any
    /// computation is done and may not be increased
    /// later; formally Tg.
    ///
    /// As ethereum circulation is around 120mil eth as of 2022 that is around
    /// 120000000000000000000000000 wei we are safe to use u128 as its max number is:
    /// 340282366920938463463374607431768211455
    ///
    /// This is also known as `GasFeeCap`
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub max_fee_per_gas: u128,
    /// Max Priority fee that transaction is paying
    ///
    /// As ethereum circulation is around 120mil eth as of 2022 that is around
    /// 120000000000000000000000000 wei we are safe to use u128 as its max number is:
    /// 340282366920938463463374607431768211455
    ///
    /// This is also known as `GasTipCap`
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub max_priority_fee_per_gas: u128,
    /// The 160-bit address of the message call’s recipient.
    pub to: Address,
    /// Input has two uses depending if transaction is Create or Call (if `to` field is None or
    /// Some). pub init: An unlimited size byte array specifying the
    /// EVM-code for the account initialisation procedure CREATE,
    /// data: An unlimited size byte array specifying the
    /// input data of the message call, formally Td.
    pub input: Bytes,
    /// The accessList specifies a list of addresses and storage keys;
    /// these addresses and storage keys are added into the `accessed_addresses`
    /// and `accessed_storage_keys` global sets (introduced in EIP-2929).
    /// A gas cost is charged, though at a discount relative to the cost of
    /// accessing outside the list.
    pub access_list: AccessList,
    /// The block number of the state root the proof is for.
    #[cfg_attr(feature = "serde", serde(with = "alloy_serde::quantity"))]
    pub proof_block_number: u64,
    /// The proof of program execution alongside public outputs.
    pub proof: WormholeTxProof,
}

impl WormholeTx {
    /// Get the transaction type
    #[doc(alias = "transaction_type")]
    pub const fn tx_type() -> u8 {
        WORMHOLE_TX_TYPE
    }

    /// Calculates a heuristic for the in-memory size of the [WormholeTx].
    /// transaction.
    #[inline]
    pub fn size(&self) -> usize {
        mem::size_of::<ChainId>() + // chain_id
        mem::size_of::<u64>() + // nonce
        mem::size_of::<u64>() + // gas_limit
        mem::size_of::<u128>() + // max_fee_per_gas
        mem::size_of::<u128>() + // max_priority_fee_per_gas
        mem::size_of::<Address>() + // to
        self.input.len() + // input      
        self.access_list.size() + // access_list
        mem::size_of::<u64>() + // proof_block_number
        mem::size_of::<WormholeTxProof>() // proof
    }
}

impl RlpEcdsaEncodableTx for WormholeTx {
    /// Outputs the length of the transaction's fields, without a RLP header.
    fn rlp_encoded_fields_length(&self) -> usize {
        self.chain_id.length() +
            self.nonce.length() +
            self.max_priority_fee_per_gas.length() +
            self.max_fee_per_gas.length() +
            self.gas_limit.length() +
            self.to.length() +
            self.input.0.length() +
            self.access_list.length() +
            self.proof_block_number.length() +
            self.proof.length()
    }

    /// Encodes only the transaction's fields into the desired buffer, without
    /// a RLP header.
    fn rlp_encode_fields(&self, out: &mut dyn alloy_rlp::BufMut) {
        self.chain_id.encode(out);
        self.nonce.encode(out);
        self.max_priority_fee_per_gas.encode(out);
        self.max_fee_per_gas.encode(out);
        self.gas_limit.encode(out);
        self.to.encode(out);
        self.input.0.encode(out);
        self.access_list.encode(out);
        self.proof_block_number.encode(out);
        self.proof.encode(out);
    }
}

impl RlpEcdsaDecodableTx for WormholeTx {
    const DEFAULT_TX_TYPE: u8 = { Self::tx_type() as u8 };

    /// Decodes the inner [WormholeTx] fields from RLP bytes.
    ///
    /// NOTE: This assumes a RLP header has already been decoded, and _just_
    /// decodes the following RLP fields in the following order:
    ///
    /// - `chain_id`
    /// - `nonce`
    /// - `max_priority_fee_per_gas`
    /// - `max_fee_per_gas`
    /// - `gas_limit`
    /// - `to`
    /// - `value`
    /// - `data` (`input`)
    /// - `access_list`
    /// - `proof_block_number`
    /// - `proof`
    fn rlp_decode_fields(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Ok(Self {
            chain_id: Decodable::decode(buf)?,
            nonce: Decodable::decode(buf)?,
            max_priority_fee_per_gas: Decodable::decode(buf)?,
            max_fee_per_gas: Decodable::decode(buf)?,
            gas_limit: Decodable::decode(buf)?,
            to: Decodable::decode(buf)?,
            input: Decodable::decode(buf)?,
            access_list: Decodable::decode(buf)?,
            proof_block_number: Decodable::decode(buf)?,
            proof: Decodable::decode(buf)?,
        })
    }
}

impl Transaction for WormholeTx {
    #[inline]
    fn chain_id(&self) -> Option<ChainId> {
        Some(self.chain_id)
    }

    #[inline]
    fn nonce(&self) -> u64 {
        self.nonce
    }

    #[inline]
    fn gas_limit(&self) -> u64 {
        self.gas_limit
    }

    #[inline]
    fn gas_price(&self) -> Option<u128> {
        None
    }

    #[inline]
    fn max_fee_per_gas(&self) -> u128 {
        self.max_fee_per_gas
    }

    #[inline]
    fn max_priority_fee_per_gas(&self) -> Option<u128> {
        Some(self.max_priority_fee_per_gas)
    }

    #[inline]
    fn max_fee_per_blob_gas(&self) -> Option<u128> {
        None
    }

    #[inline]
    fn priority_fee_or_price(&self) -> u128 {
        self.max_priority_fee_per_gas
    }

    fn effective_gas_price(&self, base_fee: Option<u64>) -> u128 {
        base_fee.map_or(self.max_fee_per_gas, |base_fee| {
            // if the tip is greater than the max priority fee per gas, set it to the max
            // priority fee per gas + base fee
            let tip = self.max_fee_per_gas.saturating_sub(base_fee as u128);
            if tip > self.max_priority_fee_per_gas {
                self.max_priority_fee_per_gas + base_fee as u128
            } else {
                // otherwise return the max fee per gas
                self.max_fee_per_gas
            }
        })
    }

    #[inline]
    fn is_dynamic_fee(&self) -> bool {
        true
    }

    #[inline]
    fn value(&self) -> U256 {
        U256::ZERO
    }

    #[inline]
    fn input(&self) -> &Bytes {
        &self.input
    }

    #[inline]
    fn access_list(&self) -> Option<&AccessList> {
        Some(&self.access_list)
    }

    #[inline]
    fn blob_versioned_hashes(&self) -> Option<&[B256]> {
        None
    }

    #[inline]
    fn authorization_list(&self) -> Option<&[SignedAuthorization]> {
        None
    }

    #[inline]
    fn kind(&self) -> TxKind {
        None.into()
    }

    #[inline]
    fn is_create(&self) -> bool {
        self.to.is_zero()
    }
}

impl Typed2718 for WormholeTx {
    fn ty(&self) -> u8 {
        WORMHOLE_TX_TYPE
    }
}

impl IsTyped2718 for WormholeTx {
    fn is_type(_type_id: u8) -> bool {
        false
    }
}

impl SignableTransaction<Signature> for WormholeTx {
    fn set_chain_id(&mut self, chain_id: ChainId) {
        self.chain_id = chain_id;
    }

    fn encode_for_signing(&self, out: &mut dyn alloy_rlp::BufMut) {
        out.put_u8(Self::tx_type() as u8);
        self.encode(out)
    }

    fn payload_len_for_signature(&self) -> usize {
        self.length() + 1
    }
}

impl Encodable for WormholeTx {
    fn encode(&self, out: &mut dyn BufMut) {
        self.rlp_encode(out);
    }

    fn length(&self) -> usize {
        self.rlp_encoded_length()
    }
}

impl Decodable for WormholeTx {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Self::rlp_decode(buf)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WormholeTxProof {
    /// The state root of the block number deposit was validated against.
    pub state_root: B256,
    /// The nullifier part of the program output.
    pub nullifier: B256,
    /// The withdraw (mint) value.
    pub withdraw_value: u128,
    /// The ZK proof of the program execution.
    pub proof: Bytes,
}

impl Encodable for WormholeTxProof {
    fn encode(&self, out: &mut dyn BufMut) {
        self.state_root.encode(out);
        self.nullifier.encode(out);
        self.withdraw_value.encode(out);
        self.proof.encode(out);
    }

    fn length(&self) -> usize {
        self.state_root.length() +
            self.nullifier.length() +
            self.withdraw_value.length() +
            self.proof.length()
    }
}

impl Decodable for WormholeTxProof {
    fn decode(buf: &mut &[u8]) -> alloy_rlp::Result<Self> {
        Ok(Self {
            state_root: Decodable::decode(buf)?,
            nullifier: Decodable::decode(buf)?,
            withdraw_value: Decodable::decode(buf)?,
            proof: Decodable::decode(buf)?,
        })
    }
}
