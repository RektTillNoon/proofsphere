use proofsphere_model::journal::Journal;
use risc0_zkvm::{InnerReceipt, Receipt, VerifierContext, sha::Digest};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rejection {
    UnsupportedFormat,
    ReceiptRejected,
    ScenarioMismatch,
    ChallengeMismatch,
    ClaimInvalid,
}
impl Rejection {
    pub fn code(self) -> &'static str {
        match self {
            Self::UnsupportedFormat => "UNSUPPORTED_FORMAT",
            Self::ReceiptRejected => "RECEIPT_REJECTED",
            Self::ScenarioMismatch => "SCENARIO_MISMATCH",
            Self::ChallengeMismatch => "CHALLENGE_MISMATCH",
            Self::ClaimInvalid => "CLAIM_INVALID",
        }
    }
}
#[derive(Clone, Copy)]
pub struct Expected {
    pub image: Digest,
    pub scenario: [u8; 32],
    pub nonce: [u8; 32],
}
pub fn verify(receipt: &Receipt, expected: Expected) -> Result<Journal, Rejection> {
    // Reject other variants even if the SDK would authenticate them. Fake receipts can never be evidence.
    if !matches!(receipt.inner, InnerReceipt::Succinct(_)) {
        return Err(Rejection::UnsupportedFormat);
    }
    // Build a production-only context without consulting RISC0_DEV_MODE. The SDK's
    // Default reads that variable (and panics when disable-dev-mode is compiled in).
    let context = VerifierContext::empty()
        .with_suites(VerifierContext::default_hash_suites())
        .with_succinct_verifier_parameters(Default::default());
    receipt
        .verify_with_context(&context, expected.image)
        .map_err(|_| Rejection::ReceiptRejected)?;
    let journal = Journal::decode(&receipt.journal.bytes).map_err(|_| Rejection::ClaimInvalid)?;
    if journal.scenario != expected.scenario {
        return Err(Rejection::ScenarioMismatch);
    }
    if journal.nonce != expected.nonce {
        return Err(Rejection::ChallengeMismatch);
    }
    Ok(journal)
}
