use crate::{Decoder, ModelError};
pub const JOURNAL_LEN: usize = 73;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Journal {
    pub scenario: [u8; 32],
    pub nonce: [u8; 32],
}
impl Journal {
    pub fn encode(self) -> [u8; JOURNAL_LEN] {
        let mut out = [0; JOURNAL_LEN];
        out[..8].copy_from_slice(b"PSPHJ001");
        out[8..40].copy_from_slice(&self.scenario);
        out[40..72].copy_from_slice(&self.nonce);
        out[72] = 1;
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ModelError> {
        if bytes.len() != JOURNAL_LEN {
            return Err(ModelError::InvalidJournal);
        }
        let mut d = Decoder::new(bytes);
        if d.take(8)? != b"PSPHJ001" {
            return Err(ModelError::InvalidJournal);
        }
        let scenario = d.array()?;
        let nonce = d.array()?;
        if d.take(1)? != [1] {
            return Err(ModelError::InvalidJournal);
        }
        d.finish()?;
        Ok(Self { scenario, nonce })
    }
}
