//! Strict public JSON transport. Canonical binary encodings remain the hash authority.
use crate::{Account, Environment, H160, H256, ModelError, State, U256, attacker, target, victim};
use serde::{Deserialize, Serialize};
pub const MAX_JSON: usize = 64 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StorageJson {
    key: String,
    value: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountJson {
    address: String,
    nonce: String,
    balance: String,
    code: String,
    storage: Vec<StorageJson>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateJson {
    format: String,
    accounts: Vec<AccountJson>,
}
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct EnvironmentJson {
    format: String,
    hardfork: String,
    chain_id: String,
    origin: String,
    gas_price: String,
    block_number: String,
    coinbase: String,
    timestamp: String,
    difficulty: String,
    gas_limit: String,
    base_fee: String,
    block_randomness: String,
    block_hashes: Vec<String>,
}

pub fn parse_json<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ModelError> {
    if bytes.len() > MAX_JSON {
        return Err(ModelError::InvalidEncoding);
    }
    serde_json::from_slice(bytes).map_err(|_| ModelError::InvalidEncoding)
}
pub fn decimal(text: &str) -> Result<U256, ModelError> {
    if text.is_empty()
        || text.len() > 78
        || text.bytes().any(|b| !b.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return Err(ModelError::InvalidEncoding);
    }
    U256::from_dec_str(text).map_err(|_| ModelError::InvalidEncoding)
}
pub fn fixed_hex<const N: usize>(text: &str, prefix: bool) -> Result<[u8; N], ModelError> {
    let text = if prefix {
        text.strip_prefix("0x").ok_or(ModelError::InvalidEncoding)?
    } else {
        text
    };
    if text.len() != N * 2 || !lower_hex(text) {
        return Err(ModelError::InvalidEncoding);
    }
    let mut bytes = [0; N];
    hex::decode_to_slice(text, &mut bytes).map_err(|_| ModelError::InvalidEncoding)?;
    Ok(bytes)
}
fn lower_hex(text: &str) -> bool {
    text.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn state_from_json(bytes: &[u8]) -> Result<State, ModelError> {
    let json: StateJson = parse_json(bytes)?;
    if json.format != "proofsphere-state-v1" || json.accounts.len() != 3 {
        return Err(ModelError::InvalidState);
    }
    let mut accounts = Vec::with_capacity(3);
    for a in json.accounts {
        let nonce = decimal(&a.nonce)?;
        if nonce > U256::from(u64::MAX) {
            return Err(ModelError::InvalidState);
        }
        let code = a
            .code
            .strip_prefix("0x")
            .ok_or(ModelError::InvalidEncoding)?;
        if code.len() > crate::MAX_CODE * 2 || code.len() % 2 != 0 || !lower_hex(code) {
            return Err(ModelError::InvalidEncoding);
        }
        if a.storage.len() > 1 {
            return Err(ModelError::InvalidState);
        }
        let storage = a
            .storage
            .into_iter()
            .map(|s| {
                Ok((
                    H256(fixed_hex(&s.key, true)?),
                    H256(fixed_hex(&s.value, true)?),
                ))
            })
            .collect::<Result<_, ModelError>>()?;
        accounts.push(Account {
            address: H160(fixed_hex(&a.address, true)?),
            nonce: nonce.as_u64(),
            balance: decimal(&a.balance)?,
            code: hex::decode(code).map_err(|_| ModelError::InvalidEncoding)?,
            storage,
        });
    }
    let state = State { accounts };
    state.validate()?;
    Ok(state)
}
pub fn state_to_json(state: &State) -> Result<Vec<u8>, ModelError> {
    state.validate()?;
    let json = StateJson {
        format: "proofsphere-state-v1".into(),
        accounts: state
            .accounts
            .iter()
            .map(|a| AccountJson {
                address: format!("0x{}", hex::encode(a.address)),
                nonce: a.nonce.to_string(),
                balance: a.balance.to_string(),
                code: format!("0x{}", hex::encode(&a.code)),
                storage: a
                    .storage
                    .iter()
                    .map(|(k, v)| StorageJson {
                        key: format!("0x{}", hex::encode(k)),
                        value: format!("0x{}", hex::encode(v)),
                    })
                    .collect(),
            })
            .collect(),
    };
    serde_json::to_vec_pretty(&json).map_err(|_| ModelError::InvalidEncoding)
}
fn environment_json() -> EnvironmentJson {
    EnvironmentJson {
        format: "proofsphere-environment-v1".into(),
        hardfork: "cancun".into(),
        chain_id: "31337".into(),
        origin: format!("0x{}", hex::encode(attacker())),
        gas_price: "0".into(),
        block_number: "1".into(),
        coinbase: format!("0x{}", "0".repeat(40)),
        timestamp: "1".into(),
        difficulty: "0".into(),
        gas_limit: crate::GAS_LIMIT.to_string(),
        base_fee: "0".into(),
        block_randomness: format!("0x{}", "0".repeat(64)),
        block_hashes: vec![],
    }
}
pub fn environment_from_json(bytes: &[u8]) -> Result<Environment, ModelError> {
    if parse_json::<EnvironmentJson>(bytes)? != environment_json() {
        return Err(ModelError::InvalidEnvironment);
    }
    Ok(Environment)
}
pub fn environment_to_json() -> Result<Vec<u8>, ModelError> {
    serde_json::to_vec_pretty(&environment_json()).map_err(|_| ModelError::InvalidEncoding)
}

/// Display names are presentation only; addresses remain defined by the model.
pub fn fixed_addresses() -> [H160; 3] {
    [target(), victim(), attacker()]
}
