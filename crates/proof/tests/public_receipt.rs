use proofsphere_proof::{
    container,
    setup::{Challenge, Registry},
    verify::{Expected, Rejection, verify},
};
use risc0_zkvm::sha::Digest;
use std::path::Path;

#[test]
fn committed_genuine_receipt_requires_trusted_image_scenario_and_nonce() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let registry = Registry::load(&root.join("fixtures/registry.json")).unwrap();
    let scenario = registry.get("vault-vulnerable-v1").unwrap();
    let challenge = Challenge::load(&root.join("evidence/demo/challenge.json"), scenario).unwrap();
    let expected = challenge.expected(scenario).unwrap();
    let bytes = std::fs::read(root.join("evidence/demo/vulnerable.psproof")).unwrap();
    let receipt = container::decode(&bytes).unwrap();
    verify(&receipt, expected).unwrap();

    assert_eq!(
        verify(
            &receipt,
            Expected {
                image: Digest::ZERO,
                ..expected
            }
        ),
        Err(Rejection::ReceiptRejected)
    );
    assert_eq!(
        verify(
            &receipt,
            Expected {
                scenario: [0; 32],
                ..expected
            }
        ),
        Err(Rejection::ScenarioMismatch)
    );
    assert_eq!(
        verify(
            &receipt,
            Expected {
                nonce: [0; 32],
                ..expected
            }
        ),
        Err(Rejection::ChallengeMismatch)
    );

    let mut altered_journal = receipt;
    altered_journal.journal.bytes[72] = 0;
    assert_eq!(
        verify(&altered_journal, expected),
        Err(Rejection::ReceiptRejected)
    );
}
