fn main() {
    // Build SP1 program
    sp1_build::build_program_with_args("../../programs/sp1", Default::default());

    // Build Risc0 program
    risc0_build::embed_methods();
}
