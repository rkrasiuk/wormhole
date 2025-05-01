//! The SP1 program for verifying Wormhole Ether deposits.

#![no_main]

use wormhole_program_core::{execute_wormhole_program, WormholeProgramInput};

sp1_zkvm::entrypoint!(main);

fn main() {
    // Read input.
    let input = sp1_zkvm::io::read::<WormholeProgramInput>();

    // Execute the program.
    let output = execute_wormhole_program(input);

    // Commit to the public values of the program.
    sp1_zkvm::io::commit(&output);
}
