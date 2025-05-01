//! The Pico program for verifying Wormhole Ether deposits.

#![no_main]

use wormhole_program::{execute_wormhole_program, WormholeProgramInput};

pico_sdk::entrypoint!(main);

pub fn main() {
    // Read input.
    let input = pico_sdk::io::read_as::<WormholeProgramInput>();

    // Execute the program.
    let output = execute_wormhole_program(input);

    // Commit to the public values of the program.
    pico_sdk::io::commit(&output);
}
