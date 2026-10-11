use crate::{ENVIRONMENT_LEN, Environment, MAX_CALLDATA, MAX_STATE, ModelError, State};
use std::io::Read;

// No Debug: this type contains the private witness.
pub struct GuestInput {
    pub state: State,
    pub environment: Environment,
    pub nonce: [u8; 32],
    pub calldata: Vec<u8>,
}
fn read<const N: usize>(r: &mut impl Read) -> Result<[u8; N], ModelError> {
    let mut bytes = [0; N];
    r.read_exact(&mut bytes)
        .map_err(|_| ModelError::InvalidInput)?;
    Ok(bytes)
}
impl GuestInput {
    pub fn encode(&self) -> Result<Vec<u8>, ModelError> {
        if self.calldata.len() > MAX_CALLDATA {
            return Err(ModelError::InvalidInput);
        }
        let state = self.state.encode()?;
        let env = self.environment.encode();
        let mut out = b"PSPHI001".to_vec();
        out.extend_from_slice(&(state.len() as u32).to_le_bytes());
        out.extend_from_slice(&state);
        out.extend_from_slice(&(env.len() as u32).to_le_bytes());
        out.extend_from_slice(&env);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&(self.calldata.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.calldata);
        Ok(out)
    }
    pub fn read(mut r: impl Read) -> Result<Self, ModelError> {
        if read::<8>(&mut r)? != *b"PSPHI001" {
            return Err(ModelError::InvalidInput);
        }
        let length = u32::from_le_bytes(read(&mut r)?) as usize;
        if length > MAX_STATE {
            return Err(ModelError::InvalidInput);
        }
        let mut state = vec![0; length];
        r.read_exact(&mut state)
            .map_err(|_| ModelError::InvalidInput)?;
        let state = State::decode(&state)?;
        let length = u32::from_le_bytes(read(&mut r)?) as usize;
        if length != ENVIRONMENT_LEN {
            return Err(ModelError::InvalidInput);
        }
        let environment = Environment::decode(&read::<ENVIRONMENT_LEN>(&mut r)?)?;
        let nonce = read(&mut r)?;
        let length = u16::from_le_bytes(read(&mut r)?) as usize;
        if length > MAX_CALLDATA {
            return Err(ModelError::InvalidInput);
        }
        let mut calldata = vec![0; length];
        r.read_exact(&mut calldata)
            .map_err(|_| ModelError::InvalidInput)?;
        let mut extra = [0];
        if r.read(&mut extra).map_err(|_| ModelError::InvalidInput)? != 0 {
            return Err(ModelError::InvalidInput);
        }
        Ok(Self {
            state,
            environment,
            nonce,
            calldata,
        })
    }
}
