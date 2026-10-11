use hex::FromHex;
use proofsphere_model::journal::Journal;
use proofsphere_proof::{
    container::{self, ContainerError, MAX_PAYLOAD},
    verify::{Expected, Rejection, verify},
};
use risc0_zkvm::{FakeReceipt, Groth16Receipt, InnerReceipt, Receipt, ReceiptClaim, sha::Digest};

fn expected() -> Expected {
    Expected {
        image: Digest::from([7; 8]),
        scenario: [3; 32],
        nonce: [4; 32],
    }
}
fn fake() -> Receipt {
    let e = expected();
    let journal = Journal {
        scenario: e.scenario,
        nonce: e.nonce,
    }
    .encode()
    .to_vec();
    Receipt::new(
        InnerReceipt::Fake(FakeReceipt::new(ReceiptClaim::ok(e.image, journal.clone()))),
        journal,
    )
}

#[test]
fn fake_receipt_cannot_be_evidence_even_in_dev_mode_shell() {
    assert_eq!(
        verify(&fake(), expected()),
        Err(Rejection::UnsupportedFormat)
    );
    let encoded = container::encode(&fake()).unwrap();
    let decoded = container::decode(&encoded).unwrap();
    assert_eq!(
        verify(&decoded, expected()),
        Err(Rejection::UnsupportedFormat)
    );
}
#[test]
fn groth16_variant_is_not_an_accepted_privacy_format() {
    let receipt = fake();
    let claim = ReceiptClaim::ok(expected().image, receipt.journal.bytes.clone());
    let groth16 = Receipt::new(
        InnerReceipt::Groth16(Groth16Receipt::new(vec![], claim.into(), Digest::ZERO)),
        receipt.journal.bytes,
    );
    assert_eq!(
        verify(&groth16, expected()),
        Err(Rejection::UnsupportedFormat)
    );
}
#[test]
fn bounded_container_rejects_invalid_magic_lengths_and_suffixes() {
    let valid = container::encode(&fake()).unwrap();
    for length in 0..valid.len() {
        assert!(container::decode(&valid[..length]).is_err());
    }
    let mut wrong_magic = valid.clone();
    wrong_magic[0] ^= 1;
    assert!(matches!(
        container::decode(&wrong_magic),
        Err(ContainerError::UnsupportedFormat)
    ));
    let mut suffix = valid.clone();
    suffix.push(0);
    assert!(container::decode(&suffix).is_err());
    let mut too_large = valid.clone();
    too_large[8..16].copy_from_slice(&((MAX_PAYLOAD as u64) + 1).to_le_bytes());
    assert!(matches!(
        container::decode(&too_large),
        Err(ContainerError::TooLarge)
    ));
    let mut invalid_variant = valid.clone();
    invalid_variant[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(container::decode(&invalid_variant).is_err());
    // A vector length cannot cause allocation beyond the bounded payload reader.
    let mut malicious = valid;
    // Receipt metadata ends in a 32-byte digest; preceding it are journal bytes and their u64 length.
    let journal_length_offset = malicious.len() - 32 - 73 - 8;
    malicious[journal_length_offset..journal_length_offset + 8]
        .copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(container::decode(&malicious).is_err());
}
#[test]
fn output_is_atomic_and_does_not_replace_existing_artifact() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("output.psproof");
    proofsphere_proof::files::write_new(&path, b"first artifact").unwrap();
    assert!(proofsphere_proof::files::write_new(&path, b"replacement").is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"first artifact");
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
}
#[test]
fn sdk_image_display_parse_roundtrip_is_the_registry_representation() {
    let image = expected().image;
    let text = image.to_string();
    assert_eq!(Digest::from_hex(&text).unwrap(), image);
}
