#![cfg(feature = "prove")]
use proofsphere_model::{Environment, input::GuestInput, scenario::Commitments};
use proofsphere_proof::{
    container, prover,
    verify::{Expected, verify},
};

#[test]
#[ignore = "genuine local release-mode proving gate"]
fn genuine_succinct_receipt_binds_setup_and_nonce() {
    if cfg!(debug_assertions) {
        panic!("real proving gate requires --release");
    }
    let runtime =
        hex::decode(include_str!("../../../fixtures/compiler/DemoVault.runtime.hex").trim())
            .unwrap();
    let state = proofsphere_runner::fixture(runtime).unwrap();
    let input = GuestInput {
        state,
        environment: Environment,
        nonce: [0x73; 32],
        calldata: proofsphere_runner::reference_payload(1_000_000_000_000_000_000_u64.into()),
    };
    let proved = prover::prove(&input).expect("genuine proof generation must succeed");
    let receipt = proved.receipt;
    let expected = Expected {
        image: prover::image_id(),
        scenario: Commitments::compute(&input.state, Environment)
            .unwrap()
            .scenario,
        nonce: input.nonce,
    };
    verify(&receipt, expected).unwrap();
    let bytes = container::encode(&receipt).unwrap();
    verify(&container::decode(&bytes).unwrap(), expected).unwrap();
    assert!(
        verify(
            &receipt,
            Expected {
                nonce: [0; 32],
                ..expected
            }
        )
        .is_err()
    );
    assert!(
        verify(
            &receipt,
            Expected {
                scenario: [0; 32],
                ..expected
            }
        )
        .is_err()
    );
    if let Some(path) = std::env::var_os("PROOFSPHERE_PROOF_OUT") {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .unwrap();
        file.write_all(&bytes).unwrap();
    }
    println!(
        "Genuine succinct receipt verified; public container bytes: {}",
        bytes.len()
    );
}
