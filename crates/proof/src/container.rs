use bincode::Options;
use risc0_zkvm::Receipt;

pub const MAX_PAYLOAD: usize = 8 * 1024 * 1024;
pub const HEADER_LEN: usize = 16;
pub const MAX_FILE: usize = MAX_PAYLOAD + HEADER_LEN;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContainerError {
    TooLarge,
    UnsupportedFormat,
}

fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .with_limit(MAX_PAYLOAD as u64)
        .reject_trailing_bytes()
}
pub fn encode(receipt: &Receipt) -> Result<Vec<u8>, ContainerError> {
    let size = options()
        .serialized_size(receipt)
        .map_err(|_| ContainerError::UnsupportedFormat)?;
    if size > MAX_PAYLOAD as u64 {
        return Err(ContainerError::TooLarge);
    }
    let payload = options()
        .serialize(receipt)
        .map_err(|_| ContainerError::UnsupportedFormat)?;
    let mut bytes = b"PSPHP001".to_vec();
    bytes.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}
pub fn decode(bytes: &[u8]) -> Result<Receipt, ContainerError> {
    if bytes.len() > MAX_FILE {
        return Err(ContainerError::TooLarge);
    }
    if bytes.len() < HEADER_LEN || &bytes[..8] != b"PSPHP001" {
        return Err(ContainerError::UnsupportedFormat);
    }
    let length = u64::from_le_bytes(
        bytes[8..16]
            .try_into()
            .map_err(|_| ContainerError::UnsupportedFormat)?,
    );
    if length > MAX_PAYLOAD as u64 {
        return Err(ContainerError::TooLarge);
    }
    if length as usize != bytes.len() - HEADER_LEN {
        return Err(ContainerError::UnsupportedFormat);
    }
    options()
        .deserialize(&bytes[HEADER_LEN..])
        .map_err(|_| ContainerError::UnsupportedFormat)
}
