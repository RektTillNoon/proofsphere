//! Production-only receipt verification; local proving is an optional dependency boundary.
pub mod container;
pub mod files;
#[cfg(feature = "prove")]
pub mod prover;
pub mod setup;
pub mod verify;
