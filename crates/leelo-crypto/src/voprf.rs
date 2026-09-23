use crate::operation_rng::OperationRng;
use crate::{Error, MAX_INPUT_BYTES, OUTPUT_BYTES, POINT_BYTES, PROOF_BYTES, Result, random_bytes};
use p384::NistP384;
use rand_core::{CryptoRng, OsRng, RngCore};
use voprf::{BlindedElement, EvaluationElement, Group, Proof, VoprfClient, VoprfServer};
use zeroize::{Zeroize, Zeroizing};

/// This validated public key uses canonical compressed SEC1 encoding for the fixed P384 suite.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerPublicKey([u8; POINT_BYTES]);

impl ServerPublicKey {
    pub fn from_bytes(bytes: [u8; POINT_BYTES]) -> Result<Self> {
        let point = NistP384::deserialize_elem(&bytes).map_err(|_| Error::InvalidEncoding)?;
        if NistP384::serialize_elem(point).as_slice() != bytes {
            return Err(Error::InvalidEncoding);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; POINT_BYTES] {
        &self.0
    }
}

/// These public response bytes are untrusted. `finalize` validates them before use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evaluation {
    pub element: [u8; POINT_BYTES],
    pub proof: [u8; PROOF_BYTES],
}

/// This evaluation key has no formatting, cloning, or blanket serialization.
/// The upstream type zeroizes its scalar on drop.
///
/// ```compile_fail
/// fn log_key(key: &leelo_crypto::SecretServer) { println!("{key:?}"); }
/// ```
///
/// ```compile_fail
/// fn clone_key(key: leelo_crypto::SecretServer) { let duplicate = key.clone(); }
/// ```
pub struct SecretServer {
    inner: VoprfServer<NistP384>,
}

impl SecretServer {
    pub fn generate() -> Result<Self> {
        let seed = random_bytes::<48>()?;
        let inner = VoprfServer::new_from_seed(seed.as_ref(), b"leelo/v1/evaluation-key")
            .map_err(|_| Error::CryptographicOperation)?;
        Ok(Self { inner })
    }

    /// Import only a private scalar and derive the public key internally.
    /// Do not trust a stored key pair with an independently supplied public key.
    pub fn from_secret_bytes(bytes: &[u8; 48]) -> Result<Self> {
        let inner = VoprfServer::new_with_key(bytes).map_err(|_| Error::InvalidEncoding)?;
        Ok(Self { inner })
    }

    /// Export bytes for storage. The caller must write them atomically with private permissions.
    /// Do not pass the returned bytes to a network encoder.
    pub fn export_secret_bytes(&self) -> Zeroizing<[u8; 48]> {
        let mut encoded = self.inner.serialize();
        let mut result = Zeroizing::new([0; 48]);
        result.copy_from_slice(&encoded[..48]);
        encoded.as_mut_slice().zeroize();
        result
    }

    pub fn public_key(&self) -> ServerPublicKey {
        let encoded = NistP384::serialize_elem(self.inner.get_public_key());
        let mut result = [0; POINT_BYTES];
        result.copy_from_slice(&encoded);
        ServerPublicKey(result)
    }

    /// Evaluate one validated point and generate an RFC 9497 DLEQ proof.
    pub fn evaluate(&self, blinded: &[u8; POINT_BYTES]) -> Result<Evaluation> {
        self.evaluate_with_entropy(blinded, &mut OsRng)
    }

    fn evaluate_with_entropy(
        &self,
        blinded: &[u8; POINT_BYTES],
        entropy: &mut (impl CryptoRng + RngCore),
    ) -> Result<Evaluation> {
        let message =
            BlindedElement::<NistP384>::deserialize(blinded).map_err(|_| Error::InvalidEncoding)?;
        let mut rng = OperationRng::from_entropy(entropy)?;
        let result = self.inner.blind_evaluate(&mut rng, &message);
        let mut element = [0; POINT_BYTES];
        element.copy_from_slice(&result.message.serialize());
        let mut proof = [0; PROOF_BYTES];
        proof.copy_from_slice(&result.proof.serialize());
        Ok(Evaluation { element, proof })
    }
}

/// This local blinding state permits one use. It cannot be serialized or cloned.
pub struct BlindState {
    inner: VoprfClient<NistP384>,
    input: Zeroizing<Vec<u8>>,
}

/// The input remains local. The returned wire message never contains the input.
pub fn blind(input: &[u8]) -> Result<(BlindState, [u8; POINT_BYTES])> {
    blind_with_entropy(input, &mut OsRng)
}

fn blind_with_entropy(
    input: &[u8],
    entropy: &mut (impl CryptoRng + RngCore),
) -> Result<(BlindState, [u8; POINT_BYTES])> {
    if input.is_empty() || input.len() > MAX_INPUT_BYTES {
        return Err(Error::InvalidInput);
    }
    let mut rng = OperationRng::from_entropy(entropy)?;
    let result = VoprfClient::<NistP384>::blind(input, &mut rng)
        .map_err(|_| Error::CryptographicOperation)?;
    let mut message = [0; POINT_BYTES];
    message.copy_from_slice(&result.message.serialize());
    Ok((
        BlindState {
            inner: result.state,
            input: Zeroizing::new(input.to_vec()),
        },
        message,
    ))
}

impl BlindState {
    /// Verify against an independently trusted pin. Then unblind.
    /// This method consumes the state. This API cannot accidentally reuse a blind.
    pub fn finalize(
        self,
        response: &Evaluation,
        pin: &ServerPublicKey,
    ) -> Result<Zeroizing<[u8; OUTPUT_BYTES]>> {
        let message = EvaluationElement::<NistP384>::deserialize(&response.element)
            .map_err(|_| Error::InvalidEncoding)?;
        let proof =
            Proof::<NistP384>::deserialize(&response.proof).map_err(|_| Error::InvalidEncoding)?;
        let public =
            NistP384::deserialize_elem(pin.as_bytes()).map_err(|_| Error::InvalidEncoding)?;
        let mut output = self
            .inner
            .finalize(&self.input, &message, &proof, public)
            .map_err(|_| Error::InvalidProof)?;
        let mut result = Zeroizing::new([0; OUTPUT_BYTES]);
        result.copy_from_slice(&output);
        output.as_mut_slice().zeroize();
        Ok(result)
    }
}

#[cfg(test)]
mod tests;
