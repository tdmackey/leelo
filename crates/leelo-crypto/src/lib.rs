#![forbid(unsafe_code)]
//! Leelo uses these fixed cryptographic primitives. It does not negotiate algorithms.
//!
//! This crate is a prototype. It has not had an independent cryptographic audit.
//! Its private wrappers do not expose the upstream library implementations of `Debug`, `Clone`, or general-purpose serialization.

mod aead;
mod operation_rng;
mod signing;
mod voprf;

pub use aead::{WrappedKey, derive_secret_key, derive_wrap_key, open_key, seal_key};
pub use signing::{SecretSigningKey, verify};
pub use voprf::{BlindState, Evaluation, SecretServer, ServerPublicKey, blind};

use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha384};
use std::fmt;
use zeroize::Zeroizing;

pub const POINT_BYTES: usize = 49;
pub const PROOF_BYTES: usize = 96;
pub const OUTPUT_BYTES: usize = 48;
pub const KEY_BYTES: usize = 32;
pub const MAX_INPUT_BYTES: usize = 1024;
pub const MAX_CONTEXT_BYTES: usize = 65_536;

/// Errors contain no caller data, keys, intermediate points, or library dumps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidInput,
    InvalidEncoding,
    InvalidProof,
    Authentication,
    Randomness,
    CryptographicOperation,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "cryptographic input exceeds bounds or is invalid",
            Self::InvalidEncoding => "invalid cryptographic encoding",
            Self::InvalidProof => "VOPRF evaluation proof did not verify",
            Self::Authentication => "cryptographic authentication failed",
            Self::Randomness => "operating system randomness unavailable",
            Self::CryptographicOperation => "cryptographic operation failed",
        })
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// Request OS randomness. This operation can fail. The returned storage is zeroized on drop.
pub fn random_bytes<const N: usize>() -> Result<Zeroizing<[u8; N]>> {
    let mut result = Zeroizing::new([0; N]);
    OsRng
        .try_fill_bytes(result.as_mut())
        .map_err(|_| Error::Randomness)?;
    Ok(result)
}

/// Compute a SHA-384 digest for the application context with explicit framing.
pub fn hash_context(bytes: &[u8]) -> [u8; 48] {
    Sha384::digest(bytes).into()
}
