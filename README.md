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

#### Program input

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