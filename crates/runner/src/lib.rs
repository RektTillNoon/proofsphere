//! Native and guest execution share this transaction adapter and predicate.
use evm::{
    Config, ExitReason,
    backend::{ApplyBackend, MemoryAccount, MemoryBackend, MemoryVicinity},
    executor::stack::{MemoryStackState, PrecompileFn, StackExecutor, StackSubstateMetadata},
};
use proofsphere_model::{
    Account, DEPOSIT_WEI, Environment, GAS_LIMIT, H160, H256, MAX_CALLDATA, State, U256, attacker,
    credit_slot, target, victim, word,
};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunnerError {
    InvalidSetup,
    InvalidInput,
    TransactionFailed,
    PredicateFailed,
}
impl std::fmt::Display for RunnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidSetup => "invalid public setup",
            Self::InvalidInput => "invalid private input",
            Self::TransactionFailed => "transaction did not succeed",
            Self::PredicateFailed => "unauthorized withdrawal was not demonstrated",
        })
    }
}
impl std::error::Error for RunnerError {}

fn vicinity(origin: H160, _: Environment) -> MemoryVicinity {
    MemoryVicinity {
        gas_price: U256::zero(),
        origin,
        chain_id: 31337.into(),
        block_hashes: vec![],
        block_number: U256::one(),
        block_coinbase: H160::zero(),
        block_timestamp: U256::one(),
        block_difficulty: U256::zero(),
        block_gas_limit: GAS_LIMIT.into(),
        block_base_fee_per_gas: U256::zero(),
        block_randomness: Some(H256::zero()),
    }
}
fn memory(state: &State) -> BTreeMap<H160, MemoryAccount> {
    state
        .accounts
        .iter()
        .map(|a| {
            (
                a.address,
                MemoryAccount {
                    nonce: a.nonce.into(),
                    balance: a.balance,
                    code: a.code.clone(),
                    storage: a.storage.iter().copied().collect(),
                },
            )
        })
        .collect()
}
fn extract(backend: &MemoryBackend<'_>) -> Result<State, RunnerError> {
    let mut accounts = Vec::with_capacity(backend.state().len());
    for (address, a) in backend.state() {
        if a.nonce > U256::from(u64::MAX) {
            return Err(RunnerError::PredicateFailed);
        }
        accounts.push(Account {
            address: *address,
            nonce: a.nonce.as_u64(),
            balance: a.balance,
            code: a.code.clone(),
            storage: a
                .storage
                .iter()
                .filter(|(_, v)| **v != H256::zero())
                .map(|(k, v)| (*k, *v))
                .collect(),
        });
    }
    Ok(State { accounts })
}

/// Diagnostics belong to private test/prover state, never to the claim journal.
pub struct Transition {
    pub state: State,
    pub used_gas: u64,
}

fn transact(
    state: &State,
    environment: Environment,
    caller: H160,
    value: U256,
    calldata: &[u8],
    gas: u64,
) -> Result<Transition, RunnerError> {
    let config = Config::cancun();
    let vicinity = vicinity(caller, environment);
    let mut backend = MemoryBackend::new(&vicinity, memory(state));
    let metadata = StackSubstateMetadata::new(gas, &config);
    let stack = MemoryStackState::new(metadata, &mut backend);
    let precompiles: BTreeMap<H160, PrecompileFn> = BTreeMap::new();
    let mut executor = StackExecutor::new_with_precompiles(stack, &config, &precompiles);
    let (reason, _) =
        executor.transact_call(caller, target(), value, calldata.to_vec(), gas, vec![]);
    if !matches!(reason, ExitReason::Succeed(_)) {
        return Err(RunnerError::TransactionFailed);
    }
    let used_gas = executor.used_gas();
    let (changes, logs) = executor.into_state().deconstruct();
    backend.apply(changes, logs, true);
    Ok(Transition {
        state: extract(&backend)?,
        used_gas,
    })
}

/// Fixture setup is an ordinary victim deposit after explicit synthetic runtime installation.
pub fn fixture(runtime: Vec<u8>) -> Result<State, RunnerError> {
    let state = State {
        accounts: vec![
            Account {
                address: target(),
                nonce: 1,
                balance: U256::zero(),
                code: runtime,
                storage: vec![],
            },
            Account {
                address: victim(),
                nonce: 0,
                balance: DEPOSIT_WEI.into(),
                code: vec![],
                storage: vec![],
            },
            Account {
                address: attacker(),
                nonce: 0,
                balance: U256::zero(),
                code: vec![],
                storage: vec![],
            },
        ],
    };
    let payload = selector(b"deposit()");
    let result = transact(
        &state,
        Environment,
        victim(),
        DEPOSIT_WEI.into(),
        &payload,
        GAS_LIMIT,
    )?;
    result
        .state
        .validate()
        .map_err(|_| RunnerError::InvalidSetup)?;
    Ok(result.state)
}

pub fn execute(
    state: &State,
    environment: Environment,
    calldata: &[u8],
) -> Result<Transition, RunnerError> {
    execute_with_gas(state, environment, calldata, GAS_LIMIT)
}
/// The lower limit is exposed only for native resource-bound tests.
pub fn execute_with_gas(
    state: &State,
    environment: Environment,
    calldata: &[u8],
    gas: u64,
) -> Result<Transition, RunnerError> {
    state.validate().map_err(|_| RunnerError::InvalidSetup)?;
    if calldata.len() > MAX_CALLDATA || gas > GAS_LIMIT {
        return Err(RunnerError::InvalidInput);
    }
    transact(state, environment, attacker(), U256::zero(), calldata, gas)
}

pub fn prove_transition(
    state: &State,
    environment: Environment,
    calldata: &[u8],
) -> Result<(), RunnerError> {
    let result = execute(state, environment, calldata)?;
    check_predicate(state, &result.state)
}

fn credit(account: &Account, owner: H160) -> U256 {
    let slot = credit_slot(owner);
    account
        .storage
        .iter()
        .find(|(k, _)| *k == slot)
        .map(|(_, v)| U256::from_big_endian(v.as_bytes()))
        .unwrap_or_default()
}
pub fn check_predicate(before: &State, after: &State) -> Result<(), RunnerError> {
    before.validate().map_err(|_| RunnerError::InvalidSetup)?;
    let get = |state: &State, address| {
        state
            .account(address)
            .map_err(|_| RunnerError::PredicateFailed)
            .cloned()
    };
    let t0 = get(before, target())?;
    let a0 = get(before, attacker())?;
    let v0 = get(before, victim())?;
    let t1 = get(after, target())?;
    let a1 = get(after, attacker())?;
    let v1 = get(after, victim())?;
    if a1.balance <= a0.balance || t1.balance >= t0.balance {
        return Err(RunnerError::PredicateFailed);
    }
    let gain = a1
        .balance
        .checked_sub(a0.balance)
        .ok_or(RunnerError::PredicateFailed)?;
    let loss = t0
        .balance
        .checked_sub(t1.balance)
        .ok_or(RunnerError::PredicateFailed)?;
    let total = t1
        .balance
        .checked_add(v1.balance)
        .and_then(|n| n.checked_add(a1.balance));
    let extra_account = after.accounts.iter().any(|a| {
        ![target(), victim(), attacker()].contains(&a.address)
            && (!a.balance.is_zero() || !a.code.is_empty())
    });
    if !credit(&t0, attacker()).is_zero()
        || !credit(&t1, attacker()).is_zero()
        || credit(&t1, victim()) != credit(&t0, victim())
        || credit(&t1, victim()) != U256::from(DEPOSIT_WEI)
        || v1.balance != v0.balance
        || !v1.balance.is_zero()
        || gain != loss
        || gain < U256::one()
        || t1.balance >= credit(&t1, victim())
        || t1.code != t0.code
        || !a1.code.is_empty()
        || !v1.code.is_empty()
        || a1.nonce != 1
        || v1.nonce != 1
        || t1.nonce != 1
        || total != Some(DEPOSIT_WEI.into())
        || extra_account
    {
        return Err(RunnerError::PredicateFailed);
    }
    Ok(())
}

fn selector(signature: &[u8]) -> [u8; 4] {
    use sha3::{Digest, Keccak256};
    Keccak256::digest(signature)[..4]
        .try_into()
        .expect("four bytes")
}
/// Known synthetic reference input. Never place its generated file in public artifacts.
pub fn reference_payload(amount: U256) -> Vec<u8> {
    let mut calldata = selector(b"withdraw(uint256)").to_vec();
    calldata.extend_from_slice(&word(amount));
    calldata
}
