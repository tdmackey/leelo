#![forbid(unsafe_code)]
//! The client and evaluator share this fixed network-bound protocol.

pub mod wire;

/// Derive the public key identifier from the compressed P-384 public key.
pub fn key_id(public: &[u8; 49]) -> [u8; 32] {
    let digest = leelo_crypto::hash_context(public);
    let mut id = [0; 32];
    id.copy_from_slice(&digest[..32]);
    id
}

#[cfg(test)]
mod tests {
    #[test]
    fn key_identifier_uses_first_32_sha384_bytes() {
        let public = [2; 49];
        assert_eq!(
            super::key_id(&public),
            [
                0xf7, 0x8e, 0x56, 0x3e, 0x86, 0xfa, 0x03, 0x81, 0xbc, 0x80, 0x6b, 0x75, 0xc5, 0x89,
                0x3f, 0x92, 0xf5, 0x1a, 0x70, 0x08, 0xf4, 0x13, 0x2d, 0x5b, 0x4d, 0x7c, 0x7c, 0xce,
                0x97, 0xb6, 0xd8, 0xe4,
            ]
        );
    }
}
