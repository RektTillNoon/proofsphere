use proofsphere_model::{DEPOSIT_WEI, Environment, GAS_LIMIT, U256, attacker, target, victim};
use proofsphere_runner::{
    RunnerError, check_predicate, execute, execute_with_gas, fixture, reference_payload,
};

fn state(patched: bool) -> proofsphere_model::State {
    let text = if patched {
        include_str!("../../../fixtures/compiler/PatchedVault.runtime.hex")
    } else {
        include_str!("../../../fixtures/compiler/DemoVault.runtime.hex")
    };
    fixture(hex::decode(text.trim()).unwrap()).unwrap()
}

#[test]
fn ordinary_deposit_produces_fixed_registered_state() {
    for patched in [false, true] {
        let s = state(patched);
        s.validate().unwrap();
        assert_eq!(s.account(victim()).unwrap().nonce, 1);
        assert_eq!(
            s.account(target()).unwrap().balance,
            U256::from(DEPOSIT_WEI)
        );
        assert_eq!(s.account(attacker()).unwrap().nonce, 0);
    }
}
#[test]
fn vulnerable_effects_match_the_contract_characterization() {
    let s = state(false);
    let amount = U256::from(1_000_000_000_000_000_000_u64);
    let result = execute(&s, Environment, &reference_payload(amount)).unwrap();
    check_predicate(&s, &result.state).unwrap();
    assert_eq!(result.state.account(attacker()).unwrap().balance, amount);
    assert_eq!(
        result.state.account(target()).unwrap().balance,
        U256::from(DEPOSIT_WEI) - amount
    );
    assert_eq!(
        result.state.account(victim()).unwrap().balance,
        U256::zero()
    );
    assert_eq!(result.state.account(attacker()).unwrap().nonce, 1);
    assert_eq!(result.state.account(target()).unwrap().nonce, 1);
    assert_eq!(result.state.account(victim()).unwrap().nonce, 1);
    assert_eq!(
        result.state.account(target()).unwrap().storage,
        s.account(target()).unwrap().storage
    );
}
#[test]
fn patched_same_payload_reverts() {
    let s = state(true);
    assert!(matches!(
        execute(
            &s,
            Environment,
            &reference_payload(1_000_000_000_000_000_000_u64.into())
        ),
        Err(RunnerError::TransactionFailed)
    ));
}
#[test]
fn checked_amount_boundaries_and_fresh_state() {
    let s = state(false);
    for amount in [
        0,
        1,
        1_000_000_000_000_000_000,
        DEPOSIT_WEI,
        DEPOSIT_WEI + 1,
    ] {
        let result = execute(&s, Environment, &reference_payload(amount.into()));
        if amount == 0 || amount > DEPOSIT_WEI {
            assert!(matches!(result, Err(RunnerError::TransactionFailed)));
        } else {
            check_predicate(&s, &result.unwrap().state).unwrap();
        }
    }
    let first = execute(&s, Environment, &reference_payload(1.into())).unwrap();
    let again = execute(&s, Environment, &reference_payload(1.into())).unwrap();
    assert_eq!(first.used_gas, again.used_gas);
    assert_eq!(first.state, again.state);
}
#[test]
fn intrinsic_gas_and_rejection_paths() {
    let s = state(false);
    let mut payload = reference_payload(1.into());
    assert!(matches!(
        execute_with_gas(&s, Environment, &payload, 21_000),
        Err(RunnerError::TransactionFailed)
    ));
    let basic = execute(&s, Environment, &payload).unwrap();
    // Trailing ABI data is accepted; each nonzero byte adds intrinsic gas.
    payload.extend_from_slice(&[0xa5; 32]);
    let extended = execute(&s, Environment, &payload).unwrap();
    assert_eq!(extended.used_gas - basic.used_gas, 32 * 16);
    assert!(matches!(
        execute_with_gas(&s, Environment, &payload, 22_000),
        Err(RunnerError::TransactionFailed)
    ));
    assert!(execute(&s, Environment, &[1, 2, 3]).is_err());
    assert!(execute(&s, Environment, &vec![1; 257]).is_err());
    assert!(execute_with_gas(&s, Environment, &payload, GAS_LIMIT + 1).is_err());
}
#[test]
fn forged_post_state_never_satisfies_predicate() {
    let s = state(false);
    let result = execute(&s, Environment, &reference_payload(1.into()))
        .unwrap()
        .state;
    for index in 0..3 {
        let mut forged = result.clone();
        forged.accounts[index].balance = U256::MAX;
        assert!(check_predicate(&s, &forged).is_err());
    }
    let mut forged = result;
    forged.accounts[2].nonce = 0;
    assert!(check_predicate(&s, &forged).is_err());
}
