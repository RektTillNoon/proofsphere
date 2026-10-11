//! The single owner of the synthetic scenario and all committed encodings.
pub mod claim;
pub mod input;
pub mod journal;
pub mod scenario;
#[cfg(feature = "json")]
pub mod transport;

pub use primitive_types::{H160, H256, U256};
pub use scenario::{Account, Environment, State};

pub const GAS_LIMIT: u64 = 500_000;
pub const MAX_CALLDATA: usize = 256;
pub const MAX_STATE: usize = 32_768;
pub const MAX_CODE: usize = 24_576;
pub const ENVIRONMENT_LEN: usize = 310;
pub const DEPOSIT_WEI: u64 = 10_000_000_000_000_000_000;

pub fn target() -> H160 {
    H160::from_low_u64_be(0x1001)
}
pub fn victim() -> H160 {
    H160::from_low_u64_be(0x2001)
}
pub fn attacker() -> H160 {
    H160::from_low_u64_be(0x3001)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModelError {
    InvalidEncoding,
    InvalidState,
    InvalidEnvironment,
    InvalidJournal,
    InvalidInput,
}

impl std::fmt::Display for ModelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidEncoding => "invalid canonical encoding",
            Self::InvalidState => "invalid fixed scenario state",
            Self::InvalidEnvironment => "invalid fixed environment",
            Self::InvalidJournal => "invalid claim journal",
            Self::InvalidInput => "invalid bounded guest input",
        })
    }
}
impl std::error::Error for ModelError {}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).into()
}

pub fn word(value: U256) -> [u8; 32] {
    let mut result = [0; 32];
    value.to_big_endian(&mut result);
    result
}

pub fn credit_slot(address: H160) -> H256 {
    use sha3::{Digest, Keccak256};
    let mut preimage = [0; 64];
    preimage[12..32].copy_from_slice(address.as_bytes());
    H256::from_slice(&Keccak256::digest(preimage))
}

pub(crate) struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Decoder<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    pub fn take(&mut self, length: usize) -> Result<&'a [u8], ModelError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(ModelError::InvalidEncoding)?;
        let result = self
            .bytes
            .get(self.offset..end)
            .ok_or(ModelError::InvalidEncoding)?;
        self.offset = end;
        Ok(result)
    }
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], ModelError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ModelError::InvalidEncoding)
    }
    pub fn u32(&mut self) -> Result<u32, ModelError> {
        Ok(u32::from_le_bytes(self.array()?))
    }
    pub fn u64(&mut self) -> Result<u64, ModelError> {
        Ok(u64::from_le_bytes(self.array()?))
    }
    pub fn finish(self) -> Result<(), ModelError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(ModelError::InvalidEncoding)
        }
    }
}
