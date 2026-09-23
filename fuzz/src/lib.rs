//! Shared adversarial harnesses for libFuzzer and reproducible seed/regression tests.
//! All fixed keys here are public test fixtures. No harness accesses disks or a TPM.
#![forbid(unsafe_code)]

use leelo_crypto::{SecretServer, SecretSigningKey, ServerPublicKey};
use leelo_envelope::{EnvelopeBody, MAX_ENVELOPE};
use leelo_policy::{Mode, NetworkNode, ProductionPolicy};
use minicbor::{Decoder, Encoder};
use std::collections::BTreeSet;
use std::sync::LazyLock;

static SIGNER: LazyLock<SecretSigningKey> =
    LazyLock::new(|| SecretSigningKey::from_seed(&[0x5a; 32]));

/// Fixed-length framing must have a unique encoding for every accepted message.
pub fn wire(data: &[u8]) {
    use leelo_protocol::wire::*;
    if let Ok(message) = decode_request(data) {
        assert_eq!(encode_request(&message.key_id, &message.point), data);
    }
    if let Ok(message) = decode_response(data) {
        assert_eq!(encode_response(&message), data);
    }
}

/// Exercise production public-key/scalar wrappers and the exact pinned decoders
/// used for blinded points, evaluation points, and proof scalars. No entropy API
/// is called, so malformed input is reproducible.
pub fn crypto_encodings(data: &[u8]) {
    use p384::NistP384;
    use voprf::{BlindedElement, EvaluationElement, Proof};
    if let Ok(bytes) = <&[u8; 48]>::try_from(data)
        && let Ok(server) = SecretServer::from_secret_bytes(bytes)
    {
        assert_eq!(server.export_secret_bytes().as_ref(), data);
        assert!(ServerPublicKey::from_bytes(*server.public_key().as_bytes()).is_ok());
    }
    if let Ok(bytes) = <[u8; 49]>::try_from(data)
        && let Ok(key) = ServerPublicKey::from_bytes(bytes)
    {
        assert_eq!(key.as_bytes(), data);
    }
    if let Ok(value) = BlindedElement::<NistP384>::deserialize(data)
        && data.len() == leelo_crypto::POINT_BYTES
    {
        assert_eq!(value.serialize().as_slice(), data);
    }
    if let Ok(value) = EvaluationElement::<NistP384>::deserialize(data)
        && data.len() == leelo_crypto::POINT_BYTES
    {
        assert_eq!(value.serialize().as_slice(), data);
    }
    if let Ok(value) = Proof::<NistP384>::deserialize(data)
        && data.len() == leelo_crypto::PROOF_BYTES
    {
        assert_eq!(value.serialize().as_slice(), data);
    }
}

/// JSON may contain whitespace; accepted token *values* must roundtrip to one
/// canonical encoder output and retain the slot and exact bounded envelope.
pub fn luks_token(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data)
        && let Ok(token) = leelo_luks::decode_token(text)
    {
        assert!(token.slot < 32);
        assert!(!token.bytes.is_empty() && token.bytes.len() <= MAX_ENVELOPE);
        let encoded = leelo_luks::encode_token(token.slot, &token.bytes).unwrap();
        let decoded = leelo_luks::decode_token(&encoded).unwrap();
        assert_eq!(decoded.slot, token.slot);
        assert_eq!(decoded.bytes, token.bytes);
        assert_eq!(
            leelo_luks::encode_token(decoded.slot, &decoded.bytes).unwrap(),
            encoded
        );
    }
}

fn check_authenticated(bytes: &[u8]) {
    if let Ok(envelope) = leelo_envelope::authenticate(bytes, &SIGNER.public_key()) {
        assert_eq!(
            leelo_envelope::sign(envelope.body(), &SIGNER).unwrap(),
            bytes
        );
        assert_eq!(
            &leelo_envelope::context_hash(&envelope.body().descriptor).unwrap(),
            envelope.context()
        );
    }
}

fn sign_unparsed_body(body: &[u8]) -> Vec<u8> {
    // Exact public format domain, deliberately independent of the production
    // body encoder: this gets malformed/deep CBOR past the signature gate.
    let mut message = b"leelo/v1/envelope\0".to_vec();
    message.extend_from_slice(body);
    let signature = SIGNER.sign(&message).unwrap();
    let mut encoded = Encoder::new(Vec::new());
    encoded
        .array(2)
        .unwrap()
        .bytes(body)
        .unwrap()
        .bytes(&signature)
        .unwrap();
    encoded.into_writer()
}

/// Fuzz the outer unauthenticated frame and separately an arbitrarily malformed
/// body signed with a public test key. The latter reaches depth/count/canonical
/// parsing and policy validation without weakening any production API.
pub fn envelope(data: &[u8]) {
    check_authenticated(data);
    if data.len() <= MAX_ENVELOPE - 128 {
        check_authenticated(&sign_unparsed_body(data));
    }
}

struct Input<'a> {
    data: &'a [u8],
    offset: usize,
}
impl Input<'_> {
    fn byte(&mut self) -> u8 {
        let value = self.data.get(self.offset).copied().unwrap_or(0);
        self.offset += 1;
        value
    }
}

fn generated_node(input: &mut Input<'_>, depth: usize, budget: &mut usize) -> Option<NetworkNode> {
    if *budget == 0 {
        return None;
    }
    *budget -= 1;
    let kind = input.byte();
    let id = input.byte();
    if kind & 1 == 0 || depth >= 6 {
        Some(NetworkNode::Leaf {
            id,
            provider_id: [input.byte(); 32],
        })
    } else {
        let required = input.byte();
        let count = usize::from(input.byte() % 9);
        let children = (0..count)
            .filter_map(|_| generated_node(input, depth + 1, budget))
            .collect();
        Some(NetworkNode::Threshold {
            id,
            required,
            children,
        })
    }
}

fn reference(node: &NetworkNode, available: &BTreeSet<u8>) -> bool {
    match node {
        NetworkNode::Leaf { id, .. } => available.contains(id),
        NetworkNode::Threshold {
            required, children, ..
        } => {
            children
                .iter()
                .filter(|child| reference(child, available))
                .count()
                >= usize::from(*required)
        }
    }
}

/// Generate bounded trees, including invalid thresholds, duplicate identities,
/// duplicate providers, excessive depth and size. For accepted policies compare
/// production decisions with direct recursive source-tree semantics.
pub fn policy(data: &[u8]) {
    let mut input = Input { data, offset: 0 };
    let mode = if input.byte() & 1 == 0 {
        Mode::NetworkBound
    } else {
        Mode::Attested
    };
    let tpm_id = input.byte();
    let source = generated_node(&mut input, 0, &mut 64).unwrap();
    if let Ok(policy) = ProductionPolicy::new(mode, tpm_id, source.clone()) {
        let ids = policy.network_leaf_ids();
        assert!(policy.node_count() <= leelo_policy::MAX_NODES);
        assert_eq!(ids.iter().collect::<BTreeSet<_>>().len(), ids.len());
        let selected: Vec<u8> = ids
            .iter()
            .copied()
            .filter(|_| input.byte() & 1 != 0)
            .collect();
        for mut available in [Vec::new(), selected, ids.clone()] {
            let expected = reference(&source, &available.iter().copied().collect());
            assert_eq!(policy.network_satisfied(&available).unwrap(), expected);
            available.reverse();
            assert_eq!(policy.network_satisfied(&available).unwrap(), expected);
        }
        if let Some(first) = ids.first() {
            assert!(policy.network_satisfied(&[*first, *first]).is_err());
        }
        let unknown = (0..=255)
            .find(|candidate| !ids.contains(candidate))
            .unwrap();
        assert!(policy.network_satisfied(&[unknown]).is_err());
    }
}

fn example_body() -> EnvelopeBody {
    use leelo_crypto::WrappedKey;
    use leelo_envelope::{Descriptor, NetworkBinding, TpmBlob, WrappedLeaf};
    let server = SecretServer::from_secret_bytes(&[7; 48]).unwrap();
    let public_key = *server.public_key().as_bytes();
    let wrapped = WrappedKey {
        nonce: [3; 12],
        ciphertext: [4; 48],
    };
    EnvelopeBody {
        descriptor: Descriptor {
            binding_id: [1; 32],
            volume_uuid: [2; 16],
            slot: 3,
            generation: 1,
            policy: ProductionPolicy::new(
                Mode::NetworkBound,
                1,
                NetworkNode::Leaf {
                    id: 2,
                    provider_id: [9; 32],
                },
            )
            .unwrap(),
            networks: vec![NetworkBinding {
                node_id: 2,
                provider_id: [9; 32],
                key_id: leelo_protocol::key_id(&public_key),
                public_key,
                input_seed: [10; 32],
            }],
            tpm_pcr_mask: 1 << 7,
            tpm_pcr_digest: [11; 32],
        },
        tpm: TpmBlob {
            public: vec![1],
            private: vec![2],
            name: vec![3],
            parent_name: vec![4],
        },
        leaves: vec![
            WrappedLeaf {
                node_id: 1,
                value: wrapped.clone(),
            },
            WrappedLeaf {
                node_id: 2,
                value: wrapped.clone(),
            },
        ],
        payload: wrapped,
    }
}

/// Stable starting points kept in version control; no generated private material.
pub fn seeds() -> Vec<(&'static str, &'static str, Vec<u8>)> {
    let signed = leelo_envelope::sign(&example_body(), &SIGNER).unwrap();
    let mut decoder = Decoder::new(&signed);
    decoder.array().unwrap();
    let body = decoder.bytes().unwrap().to_vec();
    let point = *SecretServer::from_secret_bytes(&[7; 48])
        .unwrap()
        .public_key()
        .as_bytes();
    let response = leelo_crypto::Evaluation {
        element: point,
        proof: [1; 96],
    };
    vec![
        ("envelope", "valid-frame", signed),
        ("envelope", "valid-body", body),
        (
            "envelope",
            "huge-array",
            vec![0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ),
        (
            "wire",
            "request",
            leelo_protocol::wire::encode_request(&[1; 32], &point).to_vec(),
        ),
        (
            "wire",
            "response",
            leelo_protocol::wire::encode_response(&response).to_vec(),
        ),
        ("crypto_encodings", "point", point.to_vec()),
        ("crypto_encodings", "scalar", vec![7; 48]),
        ("crypto_encodings", "proof", vec![1; 96]),
        ("crypto_encodings", "zero-proof", vec![0; 96]),
        (
            "luks_token",
            "valid-token",
            leelo_luks::encode_token(3, b"public-test-envelope")
                .unwrap()
                .into_bytes(),
        ),
        (
            "luks_token",
            "duplicate-field",
            br#"{"type":"leelo","type":"leelo","keyslots":["3"],"envelope":"AA"}"#.to_vec(),
        ),
        ("policy", "valid-leaf", vec![0, 1, 0, 2, 3, 1]),
        (
            "policy",
            "valid-threshold",
            vec![0, 1, 1, 2, 1, 2, 0, 3, 3, 0, 4, 4, 1, 0],
        ),
        (
            "policy",
            "invalid-threshold",
            vec![0, 1, 1, 2, 0, 2, 0, 3, 3, 0, 4, 4],
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(target: &str, data: &[u8]) {
        match target {
            "envelope" => envelope(data),
            "wire" => wire(data),
            "crypto_encodings" => crypto_encodings(data),
            "luks_token" => luks_token(data),
            "policy" => policy(data),
            _ => panic!("unknown target"),
        }
    }

    #[test]
    fn corpus_seeds_and_generated_mutations() {
        for (target, _, seed) in seeds() {
            run(target, &seed);
            for length in [0, 1, 2, 7, 8, 47, 48, 49, 88, 89, 95, 96, 152, 153] {
                run(target, &seed[..length.min(seed.len())]);
            }
            // Deterministic mutations keep this a regression suite, not a claim
            // about coverage-guided fuzzing time or statistical randomness.
            for index in (0..seed.len()).step_by((seed.len() / 24).max(1)) {
                let mut mutation = seed.clone();
                mutation[index] ^= 0xff;
                run(target, &mutation);
            }
        }
        for size in [
            MAX_ENVELOPE - 128,
            MAX_ENVELOPE,
            MAX_ENVELOPE + 1,
            90 * 1024 + 1,
        ] {
            let data = vec![0xff; size];
            envelope(&data);
            luks_token(&data);
        }
        let mut state = 0x7ac9_e124_d568_903bu64;
        for length in 0..256 {
            let mut data = vec![0; length];
            for byte in &mut data {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = state as u8;
            }
            wire(&data);
            crypto_encodings(&data);
            luks_token(&data);
            policy(&data);
        }
    }
}
