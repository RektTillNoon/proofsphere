#![no_main]
risc0_zkvm::guest::entry!(main);

fn main() {
    use proofsphere_model::{input::GuestInput, journal::Journal, scenario::Commitments};
    let input = GuestInput::read(risc0_zkvm::guest::env::stdin()).expect("invalid guest input");
    let commitments =
        Commitments::compute(&input.state, input.environment).expect("invalid public setup");
    proofsphere_runner::prove_transition(&input.state, input.environment, &input.calldata)
        .expect("claim not demonstrated");
    risc0_zkvm::guest::env::commit_slice(
        &Journal {
            scenario: commitments.scenario,
            nonce: input.nonce,
        }
        .encode(),
    );
}
