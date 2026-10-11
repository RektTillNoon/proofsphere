use proofsphere_model::{
    ENVIRONMENT_LEN, Environment, State, U256, credit_slot, input::GuestInput, journal::Journal,
    scenario::Commitments, victim,
};

fn vectors() -> serde_json::Value {
    serde_json::from_str(include_str!("../../../fixtures/golden.json")).unwrap()
}
fn bytes(name: &str) -> Vec<u8> {
    hex::decode(vectors()[name].as_str().unwrap()).unwrap()
}

#[test]
fn independent_golden_encodings_and_hashes() {
    let state = State::decode(&bytes("state")).unwrap();
    assert_eq!(state.encode().unwrap(), bytes("state"));
    assert_eq!(Environment.encode(), bytes("environment"));
    assert_eq!(Environment.encode().len(), ENVIRONMENT_LEN);
    assert_eq!(proofsphere_model::claim::descriptor(), bytes("claim"));
    assert_eq!(
        Commitments::compute(&state, Environment)
            .unwrap()
            .scenario
            .to_vec(),
        bytes("scenario_digest")
    );
    assert_eq!(credit_slot(victim()).as_bytes(), bytes("victim_slot"));
    let journal = Journal::decode(&bytes("journal")).unwrap();
    assert_eq!(journal.encode().to_vec(), bytes("journal"));
}
#[test]
fn malformed_truncated_and_suffixed_encodings_are_rejected() {
    let state = bytes("state");
    for length in 0..state.len() {
        assert!(State::decode(&state[..length]).is_err());
    }
    let mut extra = state.clone();
    extra.push(0);
    assert!(State::decode(&extra).is_err());
    let mut huge_count = state;
    huge_count[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(State::decode(&huge_count).is_err());
    let mut env = Environment.encode();
    env[273] = 0; // Explicit randomness-present flag must remain one.
    assert!(Environment::decode(&env).is_err());
    let journal = bytes("journal");
    for length in 0..journal.len() {
        assert!(Journal::decode(&journal[..length]).is_err());
    }
    let mut invalid = journal.clone();
    invalid[72] = 0;
    assert!(Journal::decode(&invalid).is_err());
    let mut suffix = journal;
    suffix.push(0);
    assert!(Journal::decode(&suffix).is_err());
}
#[test]
fn forged_or_reordered_initial_state_rejected() {
    let state = State::decode(&bytes("state")).unwrap();
    let mut forged = state.clone();
    forged.accounts.swap(0, 1);
    assert!(forged.validate().is_err());
    let mut forged = state.clone();
    forged.accounts[2].balance = U256::one();
    assert!(forged.validate().is_err());
    let mut forged = state.clone();
    forged.accounts[1].nonce = 0;
    assert!(forged.validate().is_err());
    let mut forged = state.clone();
    forged.accounts[0].storage.clear();
    assert!(forged.validate().is_err());
    let mut forged = state;
    forged.accounts[1].code = vec![0];
    assert!(forged.validate().is_err());
}
#[test]
fn bounded_input_requires_eof_and_caps_before_allocation() {
    let input = GuestInput {
        state: State::decode(&bytes("state")).unwrap(),
        environment: Environment,
        nonce: [3; 32],
        calldata: vec![4; 256],
    };
    let encoded = input.encode().unwrap();
    let decoded = GuestInput::read(encoded.as_slice()).unwrap();
    assert_eq!(decoded.nonce, input.nonce);
    assert_eq!(decoded.calldata, input.calldata);
    for length in 0..encoded.len() {
        assert!(GuestInput::read(&encoded[..length]).is_err());
    }
    let mut too_large = encoded.clone();
    too_large[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(GuestInput::read(too_large.as_slice()).is_err());
    let mut suffix = encoded;
    suffix.push(0);
    assert!(GuestInput::read(suffix.as_slice()).is_err());
}

#[cfg(feature = "json")]
#[test]
fn strict_json_transport_roundtrip_and_field_validation() {
    use proofsphere_model::transport::{
        decimal, environment_from_json, environment_to_json, fixed_hex, state_from_json,
        state_to_json,
    };
    let state = State::decode(&bytes("state")).unwrap();
    let encoded = state_to_json(&state).unwrap();
    assert_eq!(state_from_json(&encoded).unwrap(), state);
    assert_eq!(
        environment_from_json(&environment_to_json().unwrap()).unwrap(),
        Environment
    );
    for invalid in ["", "00", "01", "-1", "+1", "1.0", "1e18"] {
        assert!(decimal(invalid).is_err());
    }
    assert!(decimal(&"9".repeat(78)).is_err());
    assert!(fixed_hex::<20>("0X0000000000000000000000000000000000002001", true).is_err());
    let text = String::from_utf8(encoded).unwrap();
    let unknown = text.replacen('{', "{\"extra\":1,", 1);
    assert!(state_from_json(unknown.as_bytes()).is_err());
    let duplicate = text.replacen('{', "{\"format\":\"proofsphere-state-v1\",", 1);
    assert!(state_from_json(duplicate.as_bytes()).is_err());
    assert!(state_from_json(&vec![b' '; 65537]).is_err());
}
