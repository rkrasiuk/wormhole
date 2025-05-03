# Wormhole

An opinionated implementation of [Wormhole EIP-7503](https://eips.ethereum.org/EIPS/eip-7503) in Rust using [alloy](https://github.com/alloy-rs/alloy) and various zkVM backends.

## Overview

TODO

## Installation

TODO

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

```sh
$ wormhole create-input ...
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