use crate::{
    DEPOSIT_WEI, Decoder, ENVIRONMENT_LEN, GAS_LIMIT, H160, H256, MAX_CODE, MAX_STATE, ModelError,
    U256, attacker, credit_slot, sha256, target, victim, word,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub address: H160,
    pub nonce: u64,
    pub balance: U256,
    pub code: Vec<u8>,
    pub storage: Vec<(H256, H256)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub accounts: Vec<Account>,
}

impl State {
    pub fn account(&self, address: H160) -> Result<&Account, ModelError> {
        self.accounts
            .iter()
            .find(|a| a.address == address)
            .ok_or(ModelError::InvalidState)
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        if self.accounts.len() != 3 {
            return Err(ModelError::InvalidState);
        }
        let addresses = [target(), victim(), attacker()];
        for (account, expected) in self.accounts.iter().zip(addresses) {
            if account.address != expected {
                return Err(ModelError::InvalidState);
            }
        }
        let t = self.account(target())?;
        let v = self.account(victim())?;
        let a = self.account(attacker())?;
        if t.nonce != 1
            || t.balance != U256::from(DEPOSIT_WEI)
            || t.code.is_empty()
            || t.code.len() > MAX_CODE
            || t.storage != vec![(credit_slot(victim()), H256(word(U256::from(DEPOSIT_WEI))))]
            || v.nonce != 1
            || a.nonce != 0
            || !v.balance.is_zero()
            || !a.balance.is_zero()
            || !v.code.is_empty()
            || !a.code.is_empty()
            || !v.storage.is_empty()
            || !a.storage.is_empty()
        {
            return Err(ModelError::InvalidState);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, ModelError> {
        self.validate()?;
        let mut out = b"PSPHS001".to_vec();
        out.extend_from_slice(&3_u32.to_le_bytes());
        for a in &self.accounts {
            out.extend_from_slice(a.address.as_bytes());
            out.extend_from_slice(&a.nonce.to_le_bytes());
            out.extend_from_slice(&word(a.balance));
            out.extend_from_slice(&(a.code.len() as u32).to_le_bytes());
            out.extend_from_slice(&a.code);
            out.extend_from_slice(&(a.storage.len() as u32).to_le_bytes());
            for (key, value) in &a.storage {
                out.extend_from_slice(key.as_bytes());
                out.extend_from_slice(value.as_bytes());
            }
        }
        if out.len() > MAX_STATE {
            return Err(ModelError::InvalidState);
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ModelError> {
        if bytes.len() > MAX_STATE {
            return Err(ModelError::InvalidEncoding);
        }
        let mut d = Decoder::new(bytes);
        if d.take(8)? != b"PSPHS001" || d.u32()? != 3 {
            return Err(ModelError::InvalidEncoding);
        }
        let mut accounts = Vec::with_capacity(3);
        for _ in 0..3 {
            let address = H160(d.array()?);
            let nonce = d.u64()?;
            let balance = U256::from_big_endian(d.take(32)?);
            let code_len = d.u32()? as usize;
            if code_len > MAX_CODE {
                return Err(ModelError::InvalidEncoding);
            }
            let code = d.take(code_len)?.to_vec();
            let storage_len = d.u32()?;
            if storage_len > 1 {
                return Err(ModelError::InvalidEncoding);
            }
            let mut storage = Vec::with_capacity(storage_len as usize);
            for _ in 0..storage_len {
                storage.push((H256(d.array()?), H256(d.array()?)));
            }
            accounts.push(Account {
                address,
                nonce,
                balance,
                code,
                storage,
            });
        }
        d.finish()?;
        let state = Self { accounts };
        state.validate()?;
        Ok(state)
    }
}

/// All fields are fixed; only the exact committed environment can construct this value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Environment;
impl Environment {
    pub fn encode(self) -> Vec<u8> {
        let mut out = b"PSPHE001".to_vec();
        out.push(1);
        out.extend_from_slice(&word(31337.into()));
        out.extend_from_slice(attacker().as_bytes());
        out.extend_from_slice(&word(U256::zero()));
        out.extend_from_slice(&word(U256::one()));
        out.extend_from_slice(H160::zero().as_bytes());
        out.extend_from_slice(&word(U256::one()));
        out.extend_from_slice(&word(U256::zero()));
        out.extend_from_slice(&word(GAS_LIMIT.into()));
        out.extend_from_slice(&word(U256::zero()));
        out.push(1);
        out.extend_from_slice(H256::zero().as_bytes());
        out.extend_from_slice(&0_u32.to_le_bytes());
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ModelError> {
        if bytes.len() != ENVIRONMENT_LEN || bytes != Self.encode() {
            return Err(ModelError::InvalidEnvironment);
        }
        Ok(Self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commitments {
    pub code: [u8; 32],
    pub state: [u8; 32],
    pub environment: [u8; 32],
    pub claim: [u8; 32],
    pub scenario: [u8; 32],
}
impl Commitments {
    pub fn compute(state: &State, env: Environment) -> Result<Self, ModelError> {
        let code = sha256(&state.account(target())?.code);
        let state = sha256(&state.encode()?);
        let environment = sha256(&env.encode());
        let claim = sha256(&crate::claim::descriptor());
        let mut descriptor = b"PSPHSC01".to_vec();
        for address in [target(), victim(), attacker()] {
            descriptor.extend_from_slice(address.as_bytes());
        }
        for digest in [code, state, environment, claim] {
            descriptor.extend_from_slice(&digest);
        }
        let scenario = sha256(&descriptor);
        Ok(Self {
            code,
            state,
            environment,
            claim,
            scenario,
        })
    }
}
