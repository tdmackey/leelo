//! Bridge fallible OS seeding to the upstream infallible RNG contract.
use crate::{Error, Result};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

/// Private, noncloneable stream for exactly one blind or proof operation.
/// A fresh 256-bit seed makes the fixed zero nonce a distinct stream each time.
/// The cipher's zeroize feature erases its owned state and buffered output on drop.
pub(super) struct OperationRng(ChaCha20);

impl OperationRng {
    pub(super) fn from_entropy(entropy: &mut (impl CryptoRng + RngCore)) -> Result<Self> {
        let mut seed = Zeroizing::new([0; 32]);
        entropy
            .try_fill_bytes(seed.as_mut())
            .map_err(|_| Error::Randomness)?;
        Ok(Self(ChaCha20::new((&*seed).into(), (&[0; 12]).into())))
    }
}

impl RngCore for OperationRng {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, output: &mut [u8]) {
        // ChaCha20's finite 32-bit block counter must not wrap. Exceeding the
        // stream bound is an invariant failure, not permission to repeat bytes.
        self.try_fill_bytes(output)
            .expect("VOPRF operation exhausted its random stream");
    }

    fn try_fill_bytes(&mut self, output: &mut [u8]) -> core::result::Result<(), rand_core::Error> {
        output.fill(0);
        self.0.try_apply_keystream(output).map_err(|_| {
            rand_core::Error::from(
                core::num::NonZeroU32::new(rand_core::Error::CUSTOM_START).unwrap(),
            )
        })
    }
}

// Uses the established 20-round ChaCha20 construction with a fresh OS seed;
// the adapter adds no new cipher, reseeding, shared state, or fallback source.
impl CryptoRng for OperationRng {}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20::cipher::StreamCipherSeek;

    #[test]
    fn rfc8439_block_vector_and_mixed_reads_preserve_byte_order() {
        // RFC 8439 section 2.3.2, counter 1 (byte offset 64).
        let key: [u8; 32] = std::array::from_fn(|index| index as u8);
        let nonce = [0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let mut rng = OperationRng(ChaCha20::new((&key).into(), (&nonce).into()));
        rng.0.seek(64_u64);
        let mut actual = [0; 64];
        actual[..4].copy_from_slice(&rng.next_u32().to_le_bytes());
        rng.fill_bytes(&mut actual[4..9]);
        actual[9..17].copy_from_slice(&rng.next_u64().to_le_bytes());
        rng.try_fill_bytes(&mut actual[17..]).unwrap();
        assert_eq!(
            hex::encode(actual),
            concat!(
                "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e",
                "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
            )
        );
    }

    #[test]
    fn stream_exhaustion_is_reported_without_reusing_output() {
        let mut rng = OperationRng(ChaCha20::new((&[1; 32]).into(), (&[0; 12]).into()));
        rng.0.seek((u64::from(u32::MAX) - 1) * 64);
        let mut output = [0; 128];
        assert!(rng.try_fill_bytes(&mut output).is_err());
        assert_eq!(output, [0; 128]);
    }
}
