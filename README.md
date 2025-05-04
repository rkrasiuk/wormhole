# Wormhole

An opinionated non-spec implementation of [Wormhole EIP-7503](https://eips.ethereum.org/EIPS/eip-7503) in Rust using [alloy](https://github.com/alloy-rs/alloy) and various zkVM backends.

## Specification

### Parameters

| Parameter                     | Value     |
|-------------------------------|-----------|
| `MAGIC_ADDRESS`               | `0xfe`    |
| `MAGIC_NULLIFIER`             | `0x01`    |
| `MAGIC_POW`                   | `0x02`    |
| `POW_LOG_DIFFICULTY`          | `24`      |
| `WORMHOLE_TX_TYPE`            | `TBD`     |
| `WORMHOLE_NULLIFIER_ADDRESS`  | `TBD`     |

### Execution

We define a new [EIP-2718](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2718.md) transaction type, where `TransactionType` is `WORMHOLE_TX_TYPE` and the `TransactionPayload` format is as follows:
```
[chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, data, access_list, state_root_block_number, proof]
```

Verifying this type of transaction requires confirming that:
1. The proof is a zero-knowledge proof:
    * Private inputs: `secret`, `deposit_amount`, `cumulative_withdrawn_amount`, `withdrawal_index`, `deposit_account_proof`, `nullifier_account_proof`, `previous_nullifier_storage_proof`
    * Public inputs: `withdraw_amount`, `state_root`, `nullifier_address`
    * Function:
        - `sha256(MAGIC_POW + secret) % 2**POW_LOG_DIFFICULTY == 0`
        - `withdraw_amount > 0`
        - `withdraw_amount + cumulative_withdrawn_amount <= deposit_amount`
        - `if withdrawal_index == 0`:
            * `cumulative_withdrawn_amount == 0`
            * `len(previous_nullifier_storage_proof) == 0`
        - derive `deposit_address` from the secret (`sha256(MAGIC_ADDRESS + secret)[12:]`)
        - `deposit_account = Account(Uint(0), deposit_amount, bytearray())`
        - `verify_merkle_proof(root=state_root, index=keccak256(deposit_address), leaf=rlp(deposit_account) proof=deposit_account_proof)`
        - `verify_merkle_proof(root=state_root, index=keccak256(nullifier_address), proof=nullifier_account_proof)`
        - `if withdrawal_index > 0`:
            * derive `previous_nullifier` from the secret (`sha256(MAGIC_NULLIFIER + secret + withdrawal_index - 1)`)
            * `verify_merkle_proof(root=state_root, index=keccak(previous_nullifier), leaf=rlp(keccak256(cumulative_withdrawn_amount)), proof=previous_nullifier_storage_proof)`
2. `SLOAD(WORMHOLE_NULLIFIER_ADDRESS, proof.nullifier) == 0`
3. `get_state_root(state_root_block_number) == proof.state_root`

### EIP-7503 Core Differences

1. Removal of non-implemented EIP dependencies

EIP-7503 requires [EIP-7708](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-7708.md) and [EIP-7495](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-7495.md) to be implemented. This implementation removes these dependencies by using state proofs for proving deposits and previous withdrawals.

2. Multiple Deposits & Withdrawals

Unlike the original EIP, which is designed for single-use deposits per burn address, this implementation enables multiple deposits and incremental withdrawals from the same derived deposit address. This is managed using nullifier chains and cumulative withdrawal tracking.

## Usage

#### Secret Generation

Generate a new valid wormhole secret:

```sh
$ wormhole new-secret
```

Sample output:
```sh
Generated new secret in 11.94567025s
Secret: 8045d27691d6cf001491ebeef11a5fc335b90727e8fa40c171c45127d85e3399 # secret bytes
Burn Address: 0xe300dD78D40b8Cd26df62f893a3B224508398A11 # burn address to send deposits to
Nullifier(0): 0xb3f99dab37ecdef88863af5231ae2b72faa95793ff88ed07de9c4e58315f6447 # nullifier slot for withdrawal index `0`
```

#### Program Input

Create program input:
```sh
$ wormhole create-input --secret <SECRET> --nullifier-address <ADDRESS> --rpc-url <RPC_URL> --withdraw-amount <AMOUNT>
```

Sample output:
```js
{
  "secret": "0x8045d27691d6cf001491ebeef11a5fc335b90727e8fa40c171c45127d85e3399", // wormhole secret
  "deposit_amount": "0x64", // total deposit amount (balance of the burn address)
  "withdraw_amount": "0xa", // withdraw amount
  "cumulative_withdrawn_amount": "0x0", // previously withdrawn amount
  "withdrawal_index": "0x0", // withdrawal index
  "state_root": "0x153a3b2082ce10f2c9e421ac684d1d27a96af410000bf94bb986ed227d566cf0", // state root
  "deposit_account_proof": [ /* <PROOF> */ ],
  "nullifier_address": "0xce8f0b46cc1527f27429938d3cc85bf7d270a8f6", // nullifier system contract address
  "nullifier_account_proof": [ /* <PROOF> */ ],
  "previous_nullifier_storage_proof": [ /* <PROOF> */ ],
  "block_number": 322962, // block number proofs were generated at (informational)
  "block_hash": "0x30563f3437279ba3f608319aacc392e52581708bb014ff60532b1eacf99703f7" // block hash proofs were generated at (informational)
}
```

#### Proving

Generate a groth16 proof using specified zkVM:
```sh
$ wormhole <zkvm> prove --input input.json
```

## zkVM Support

| Backend   | Status     | Docs                                            |
|-----------|----------- |-------------------------------------------------|
| **SP1**   | ✅ Ready   | https://docs.succinct.xyz/docs/sp1/introduction |
| **Risc0** | ✅ Ready   | https://dev.risczero.com/api                    |
| **Pico**  | 🚧 WIP     | https://docs.brevis.network/                    |


## Project Layout

| Path                             | Description                                   |
|----------------------------------|-----------------------------------------------|
| `crates/alloy-wormhole`          | EIP-7503 primitives and spec implementation   |
| `crates/wormhole-program-core`   | Core Wormhole program logic                   |
| `programs/*`                     | Wormhole programs using various zkVM backends |
| `contracts/`                     | Mock nullifier system contract                |

## Testing

The `contracts` folder includes a `MockNullifierSystemContract` which can be deployed on a testnet and used as a stub for testing.
It is deployed on hoodi [0xce8f0b46cc1527f27429938d3cc85bf7d270a8f6](https://hoodi.etherscan.io/address/0xce8f0b46cc1527f27429938d3cc85bf7d270a8f6), but only the deployer can set the storage slots.
