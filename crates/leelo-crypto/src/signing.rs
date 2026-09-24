use crate::{Error, MAX_CONTEXT_BYTES, Result, random_bytes};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

/// This Ed25519 signing seed has no generic serialization or formatting.
pub struct SecretSigningKey(SigningKey);

impl SecretSigningKey {
    pub fn generate() -> Result<Self> {
        let seed = random_bytes::<32>()?;
        Ok(Self::from_seed(&seed))
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    /// Export bytes for storage. Protect these bytes as private key data.
    pub fn export_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    /// Sign exactly these bytes.
    /// The application supplies a canonical manifest frame with domain separation.
    /// This wrapper never re-encodes messages.
    pub fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        if message.len() > MAX_CONTEXT_BYTES {
            return Err(Error::InvalidInput);
        }
        Ok(self.0.sign(message).to_bytes())
    }
}

pub fn verify(public: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<()> {
    if message.len() > MAX_CONTEXT_BYTES {
        return Err(Error::InvalidInput);
    }
    let public = VerifyingKey::from_bytes(public).map_err(|_| Error::InvalidEncoding)?;
    public
        .verify_strict(message, &Signature::from_bytes(signature))
        .map_err(|_| Error::Authentication)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detached_signature_rejects_wrong_pin_and_modified_message() {
        let key = SecretSigningKey::from_seed(&[5; 32]);
        let sig = key.sign(b"leelo/v1/manifest:example").unwrap();
        verify(&key.public_key(), b"leelo/v1/manifest:example", &sig).unwrap();
        assert!(verify(&key.public_key(), b"leelo/v1/manifest:modified", &sig).is_err());
        assert!(
            verify(
                &SecretSigningKey::from_seed(&[6; 32]).public_key(),
                b"leelo/v1/manifest:example",
                &sig
            )
            .is_err()
        );
        let mut identity = [0; 32];
        identity[0] = 1;
        assert!(verify(&identity, b"leelo/v1/manifest:example", &sig).is_err());
    }

    #[test]
    fn rfc8032_empty_message_vector() {
        let seed: [u8; 32] =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap()
                .try_into()
                .unwrap();
        let key = SecretSigningKey::from_seed(&seed);
        assert_eq!(
            hex::encode(key.public_key()),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        assert_eq!(
            hex::encode(key.sign(b"").unwrap()),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        );
    }
}
