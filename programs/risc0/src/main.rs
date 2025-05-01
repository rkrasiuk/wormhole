//! The Risc0 program for verifying Wormhole Ether deposits.

#![no_main]
#![no_std]

use wormhole_program::{execute_wormhole_program, WormholeProgramInput};

risc0_zkvm::guest::entry!(main);

fn main() {
    // Read input.
    let input = risc0_zkvm::guest::env::read::<WormholeProgramInput>();

    // Execute the program.
    let output = execute_wormhole_program(input);

    // Commit to the public values of the program.
    risc0_zkvm::guest::env::commit(&output);
}
