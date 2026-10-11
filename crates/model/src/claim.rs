use crate::{GAS_LIMIT, MAX_CALLDATA, U256, word};

pub const LABEL: &str = "Unauthorized withdrawal demonstrated";
pub fn descriptor() -> Vec<u8> {
    let mut bytes = b"ProofSphere/unauthorized-withdrawal/v1".to_vec();
    bytes.extend_from_slice(&(MAX_CALLDATA as u16).to_le_bytes());
    bytes.extend_from_slice(&GAS_LIMIT.to_le_bytes());
    bytes.extend_from_slice(&word(U256::one()));
    bytes
}
