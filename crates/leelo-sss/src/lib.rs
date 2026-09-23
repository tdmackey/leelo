//! This crate supplies fixed-size Shamir sharing for an authenticated policy tree with size limits.
//!
//! Shamir **does not authenticate** shares or reconstructed secrets.
//! Callers must authenticate leaf wrappers before reconstruction.
//! Callers must authenticate the final root payload before they release a credential.
//! Consistency checks on extra shares detect some corruption. They do not establish authenticity.
//!
//! A Verus refinement proof checks the production field multiplier against polynomial multiplication modulo 0x11b.
//! Tests cover all field inversions.
//! These checks are not a complete Shamir secrecy proof or constant-time audit.
//! The RNG must be an initialized cryptographic generator that operates correctly.
//! Trait bounds cannot establish these RNG properties.
//!
//! Share bytes do not implement Copy, Clone, Debug, or serialization:
//! ```compile_fail
//! use leelo_sss::Share;
//! fn accidental_log(share: &Share) { println!("{share:?}"); }
//! ```
//! ```compile_fail
//! use leelo_sss::Share;
//! fn accidental_copy(share: &Share) -> Share { *share }
//! ```

#![forbid(unsafe_code)]

mod gf256;

use core::fmt;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

/// The secret and share payloads have this fixed length in bytes.
pub const SECRET_LEN: usize = 32;
/// The policy format permits this maximum number of shares at one node.
pub const MAX_SHARES: u8 = 31;

/// This share pairs a public coordinate with a secret value that zeroizes on drop.
///
/// Explicit access to `value()` supports the limited authenticated wrapper codec of the caller.
/// That access does not prevent the caller from copying bytes.
pub struct Share {
    index: u8,
    value: Zeroizing<[u8; SECRET_LEN]>,
}

impl Share {
    /// Import a share whose outer cryptographic wrapper was authenticated.
    ///
    /// The coordinate can be any nonzero field element.
    /// A subset of a larger share set does not need the consecutive indices that `split` generates.
    /// The supplied value is zeroized on drop if this operation fails.
    pub fn from_parts(index: u8, value: Zeroizing<[u8; SECRET_LEN]>) -> Result<Self, Error> {
        if index == 0 {
            return Err(Error::ZeroIndex);
        }
        Ok(Self { index, value })
    }

    /// Return the public, nonzero interpolation coordinate.
    pub fn index(&self) -> u8 {
        self.index
    }

    /// Borrow the sensitive share bytes for explicit wrapping or unwrapping.
    pub fn value(&self) -> &[u8; SECRET_LEN] {
        &self.value
    }
}

/// Errors contain only public validation information, never share bytes.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidThreshold { threshold: u8 },
    InvalidShareCount { count: usize },
    InsufficientShares { required: u8, provided: usize },
    ZeroIndex,
    DuplicateIndex { index: u8 },
    EntropyUnavailable,
    InconsistentShares,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidThreshold { threshold } => write!(f, "invalid threshold {threshold}"),
            Self::InvalidShareCount { count } => write!(f, "invalid share count {count}"),
            Self::InsufficientShares { required, provided } => {
                write!(f, "need {required} shares, received {provided}")
            }
            Self::ZeroIndex => f.write_str("share coordinate must be nonzero"),
            Self::DuplicateIndex { index } => write!(f, "duplicate share coordinate {index}"),
            Self::EntropyUnavailable => f.write_str("cryptographic randomness unavailable"),
            Self::InconsistentShares => {
                f.write_str("shares disagree with the threshold polynomial")
            }
        }
    }
}

impl std::error::Error for Error {}

fn validate_threshold(threshold: u8) -> Result<(), Error> {
    if threshold == 0 || threshold > MAX_SHARES {
        return Err(Error::InvalidThreshold { threshold });
    }
    Ok(())
}

/// Share a secret using independent bytewise polynomials over GF(256).
///
/// Coordinates are 1 through `count`.
/// Each nonconstant coefficient is an independent uniform byte. Zero is a possible value.
/// No rejection sampling changes that distribution. The caller remains responsible for its input secret.
pub fn split<R: CryptoRng + RngCore + ?Sized>(
    secret: &[u8; SECRET_LEN],
    threshold: u8,
    count: u8,
    rng: &mut R,
) -> Result<Vec<Share>, Error> {
    validate_threshold(threshold)?;
    if count == 0 || count > MAX_SHARES {
        return Err(Error::InvalidShareCount {
            count: usize::from(count),
        });
    }
    if threshold > count {
        return Err(Error::InsufficientShares {
            required: threshold,
            provided: usize::from(count),
        });
    }

    let mut shares: Vec<Share> = (1..=count)
        .map(|index| Share {
            index,
            value: Zeroizing::new([0; SECRET_LEN]),
        })
        .collect();
    let degree = usize::from(threshold - 1);
    let mut coefficients = Zeroizing::new([0_u8; MAX_SHARES as usize - 1]);
    for (byte, secret_byte) in secret.iter().enumerate() {
        rng.try_fill_bytes(&mut coefficients[..degree])
            .map_err(|_| Error::EntropyUnavailable)?;
        for share in &mut shares {
            // Horner's rule intentionally multiplies zero first.
            // This keeps the same public loop shape for each coefficient.
            let mut value = 0;
            for coefficient in coefficients[..degree].iter().rev() {
                value = gf256::mul(value, share.index) ^ coefficient;
            }
            share.value[byte] = gf256::mul(value, share.index) ^ secret_byte;
        }
    }
    Ok(shares)
}

/// Compute the public Lagrange weights for interpolation at `target`.
///
/// Validation has already checked that each coordinate is different from all other coordinates.
/// Thus, each denominator is nonzero. All values in this function are public.
fn weights(shares: &[Share], target: u8) -> Vec<u8> {
    shares
        .iter()
        .enumerate()
        .map(|(i, share)| {
            let mut numerator = 1;
            let mut denominator = 1;
            for (j, other) in shares.iter().enumerate() {
                if i != j {
                    numerator = gf256::mul(numerator, target ^ other.index);
                    denominator = gf256::mul(denominator, share.index ^ other.index);
                }
            }
            gf256::mul(numerator, gf256::inverse_nonzero(denominator))
        })
        .collect()
}

fn interpolate(shares: &[Share], target: u8) -> Zeroizing<[u8; SECRET_LEN]> {
    let coefficients = weights(shares, target);
    let mut result = Zeroizing::new([0; SECRET_LEN]);
    for (share, coefficient) in shares.iter().zip(coefficients) {
        for byte in 0..SECRET_LEN {
            result[byte] ^= gf256::mul(share.value[byte], coefficient);
        }
    }
    result
}

/// Recover a candidate secret from authenticated, distinct shares.
///
/// Validate each supplied coordinate, including coordinates for surplus shares.
/// The first `threshold` shares determine the polynomial. Surplus shares must agree with that polynomial.
/// Exactly `threshold` shares always define a polynomial.
/// Thus, the returned candidate still requires outer AEAD authentication.
pub fn reconstruct(threshold: u8, shares: &[Share]) -> Result<Zeroizing<[u8; SECRET_LEN]>, Error> {
    validate_threshold(threshold)?;
    if shares.len() > usize::from(MAX_SHARES) {
        return Err(Error::InvalidShareCount {
            count: shares.len(),
        });
    }
    if shares.len() < usize::from(threshold) {
        return Err(Error::InsufficientShares {
            required: threshold,
            provided: shares.len(),
        });
    }
    for (i, share) in shares.iter().enumerate() {
        if share.index == 0 {
            return Err(Error::ZeroIndex);
        }
        if shares[..i].iter().any(|other| other.index == share.index) {
            return Err(Error::DuplicateIndex { index: share.index });
        }
    }

    let basis = &shares[..usize::from(threshold)];
    let mut disagreement = 0;
    for share in &shares[usize::from(threshold)..] {
        let expected = interpolate(basis, share.index);
        for byte in 0..SECRET_LEN {
            disagreement |= expected[byte] ^ share.value[byte];
        }
    }
    if disagreement != 0 {
        return Err(Error::InconsistentShares);
    }
    Ok(interpolate(basis, 0))
}
