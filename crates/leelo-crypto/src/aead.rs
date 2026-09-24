use crate::{Error, MAX_CONTEXT_BYTES, Result, random_bytes};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce, Tag};
use hkdf::Hkdf;
use sha2::Sha384;
use zeroize::Zeroizing;

/// This ciphertext contains one encrypted 32-byte secret and a 16-byte authentication tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedKey {
    pub nonce: [u8; 12],
    pub ciphertext: [u8; 48],
}

/// This HKDF uses prefix-free framing for the purpose and context.
/// The caller supplies a different purpose for the root, TPM, and each other role.
/// This is not a password KDF.
pub fn derive_secret_key(
    ikm: &[u8],
    context: &[u8],
    purpose: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    if ikm.len() < 32
        || ikm.len() > MAX_CONTEXT_BYTES
        || context.len() > MAX_CONTEXT_BYTES
        || purpose.is_empty()
        || purpose.len() > 128
    {
        return Err(Error::InvalidInput);
    }
    let hkdf = Hkdf::<Sha384>::new(Some(b"leelo/v1/hkdf-sha384"), ikm);
    let purpose_len = (purpose.len() as u32).to_be_bytes();
    let context_len = (context.len() as u32).to_be_bytes();
    let mut key = Zeroizing::new([0; 32]);
    hkdf.expand_multi_info(
        &[
            b"leelo/v1/key",
            &purpose_len,
            purpose,
            &context_len,
            context,
        ],
        key.as_mut(),
    )
    .map_err(|_| Error::CryptographicOperation)?;
    Ok(key)
}

pub fn derive_wrap_key(output: &[u8; 48], context: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    derive_secret_key(output, context, b"voprf-leaf-wrap")
}

pub fn seal_key(key: &[u8; 32], plaintext: &[u8; 32], aad: &[u8]) -> Result<WrappedKey> {
    if aad.len() > MAX_CONTEXT_BYTES {
        return Err(Error::InvalidInput);
    }
    let nonce = *random_bytes::<12>()?;
    let cipher = ChaCha20Poly1305::new(key.into());
    // This temporary zeroizes the plaintext even if encryption fails.
    let mut body = Zeroizing::new(*plaintext);
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), aad, body.as_mut())
        .map_err(|_| Error::CryptographicOperation)?;
    let mut ciphertext = [0; 48];
    ciphertext[..32].copy_from_slice(body.as_ref());
    ciphertext[32..].copy_from_slice(&tag);
    Ok(WrappedKey { nonce, ciphertext })
}

pub fn open_key(key: &[u8; 32], wrapped: &WrappedKey, aad: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if aad.len() > MAX_CONTEXT_BYTES {
        return Err(Error::InvalidInput);
    }
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut plaintext = Zeroizing::new([0; 32]);
    plaintext.copy_from_slice(&wrapped.ciphertext[..32]);
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&wrapped.nonce),
            aad,
            plaintext.as_mut(),
            Tag::from_slice(&wrapped.ciphertext[32..]),
        )
        .map_err(|_| Error::Authentication)?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_and_purpose_separate_keys() {
        let a = derive_secret_key(&[7; 48], b"volume-a", b"root").unwrap();
        let b = derive_secret_key(&[7; 48], b"volume-b", b"root").unwrap();
        let c = derive_secret_key(&[7; 48], b"volume-a", b"leaf").unwrap();
        assert_ne!(*a, *b);
        assert_ne!(*a, *c);
        assert_ne!(
            *derive_secret_key(&[7; 48], b"bc", b"a").unwrap(),
            *derive_secret_key(&[7; 48], b"c", b"ab").unwrap()
        );
    }

    #[test]
    fn aead_authenticates_key_ciphertext_and_context() {
        let wrapped = seal_key(&[1; 32], &[2; 32], b"context").unwrap();
        assert_eq!(*open_key(&[1; 32], &wrapped, b"context").unwrap(), [2; 32]);
        assert_eq!(
            open_key(&[3; 32], &wrapped, b"context").err(),
            Some(Error::Authentication)
        );
        assert_eq!(
            open_key(&[1; 32], &wrapped, b"other").err(),
            Some(Error::Authentication)
        );
        for i in 0..48 {
            let mut modified = wrapped.clone();
            modified.ciphertext[i] ^= 1;
            assert_eq!(
                open_key(&[1; 32], &modified, b"context").err(),
                Some(Error::Authentication)
            );
        }
        let mut modified = wrapped;
        modified.nonce[0] ^= 1;
        assert_eq!(
            open_key(&[1; 32], &modified, b"context").err(),
            Some(Error::Authentication)
        );
    }
}
