use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce};
use leelo_crypto::{Evaluation, SecretServer, SecretSigningKey, WrappedKey};
use leelo_envelope::{Descriptor, EnvelopeBody, NetworkBinding, TpmBlob, WrappedLeaf};
use leelo_policy::{Mode, NetworkNode, ProductionPolicy};
use p384::NistP384;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde_json::{Value, json};
use voprf::{Group, VoprfClient, VoprfServer};

pub fn array<const N: usize>(value: &Value, name: &str) -> [u8; N] {
    hex::decode(value[name].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn wrap(key: &[u8; 32], plaintext: &[u8; 32], aad: &[u8], byte: u8) -> WrappedKey {
    // Fixed nonces and keys belong only to this public fixture generator.
    let nonce = [byte; 12];
    let mut body = *plaintext;
    let tag = ChaCha20Poly1305::new(key.into())
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), aad, &mut body)
        .unwrap();
    let mut ciphertext = [0; 48];
    ciphertext[..32].copy_from_slice(&body);
    ciphertext[32..].copy_from_slice(&tag);
    WrappedKey { nonce, ciphertext }
}

struct Coefficients;
impl rand_core::RngCore for Coefficients {
    fn next_u32(&mut self) -> u32 {
        u32::from_le_bytes([0xa5; 4])
    }
    fn next_u64(&mut self) -> u64 {
        u64::from_le_bytes([0xa5; 8])
    }
    fn fill_bytes(&mut self, out: &mut [u8]) {
        out.fill(0xa5);
    }
    fn try_fill_bytes(&mut self, out: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(out);
        Ok(())
    }
}
// This test double is not a source of production randomness.
impl rand_core::CryptoRng for Coefficients {}

pub fn vector() -> Value {
    let secret = [0x11; 48];
    let signer_seed = [0x12; 32];
    let seed = [0x13; 32];
    let root = [0x14; 32];
    let credential = [0x15; 32];
    let signing = SecretSigningKey::from_seed(&signer_seed);
    let server = SecretServer::from_secret_bytes(&secret).unwrap();
    let public = *server.public_key().as_bytes();
    let key_id = leelo_protocol::key_id(&public);
    let descriptor = Descriptor {
        binding_id: [0x21; 32],
        volume_uuid: [0x22; 16],
        slot: 3,
        generation: 7,
        policy: ProductionPolicy::new(
            Mode::NetworkBound,
            0,
            NetworkNode::Leaf {
                id: 1,
                provider_id: [0x23; 32],
            },
        )
        .unwrap(),
        networks: vec![NetworkBinding {
            node_id: 1,
            provider_id: [0x23; 32],
            key_id,
            public_key: public,
            input_seed: [0x24; 32],
        }],
        tpm_pcr_mask: 1 << 7,
        tpm_pcr_digest: [0x25; 32],
    };
    let context = leelo_envelope::context_hash(&descriptor).unwrap();
    let tpm_context = leelo_envelope::leaf_context(&context, 0);
    let net_context = leelo_envelope::leaf_context(&context, 1);
    let input = leelo_envelope::network_input(&descriptor, &descriptor.networks[0]);
    let mut rng = ChaCha20Rng::from_seed([0x31; 32]);
    let blinded = VoprfClient::<NistP384>::blind(&input, &mut rng).unwrap();
    let evaluator = VoprfServer::<NistP384>::new_with_key(&secret).unwrap();
    let evaluated = evaluator.blind_evaluate(&mut rng, &blinded.message);
    let output = blinded
        .state
        .finalize(
            &input,
            &evaluated.message,
            &evaluated.proof,
            NistP384::deserialize_elem(&public).unwrap(),
        )
        .unwrap();
    let request = leelo_protocol::wire::encode_request(
        &key_id,
        &blinded.message.serialize().as_slice().try_into().unwrap(),
    );
    let response = leelo_protocol::wire::encode_response(&Evaluation {
        element: evaluated.message.serialize().as_slice().try_into().unwrap(),
        proof: evaluated.proof.serialize().as_slice().try_into().unwrap(),
    });
    let shares = leelo_sss::split(&root, 2, 2, &mut Coefficients).unwrap();
    let tpm_key =
        leelo_crypto::derive_secret_key(&seed, &tpm_context, b"leelo/v1/tpm-wrap").unwrap();
    let network_key =
        leelo_crypto::derive_wrap_key(output.as_slice().try_into().unwrap(), &net_context).unwrap();
    let payload_key =
        leelo_crypto::derive_secret_key(&root, &context, b"leelo/v1/luks-slot").unwrap();
    let body = EnvelopeBody {
        descriptor,
        tpm: TpmBlob {
            public: b"test-public".to_vec(),
            private: b"test-private".to_vec(),
            name: b"test-name".to_vec(),
            parent_name: b"test-parent".to_vec(),
        },
        leaves: vec![
            WrappedLeaf {
                node_id: 0,
                value: wrap(&tpm_key, shares[0].value(), &tpm_context, 0x41),
            },
            WrappedLeaf {
                node_id: 1,
                value: wrap(&network_key, shares[1].value(), &net_context, 0x42),
            },
        ],
        payload: wrap(&payload_key, &credential, &context, 0x43),
    };
    let envelope = leelo_envelope::sign(&body, &signing).unwrap();
    json!({
        "schema_version": 1, "profile": "leelo-v1-network-bound-p384-sha384",
        "warning": "PUBLIC TEST SECRETS. DO NOT USE FOR ENROLLMENT.",
        "evaluation_secret": hex::encode(secret), "evaluation_public": hex::encode(public),
        "key_id": hex::encode(key_id), "signing_seed": hex::encode(signer_seed),
        "signing_public": hex::encode(signing.public_key()), "tpm_seed": hex::encode(seed),
        "root_secret": hex::encode(root), "root_coefficient": hex::encode([0xa5; 32]),
        "credential": hex::encode(credential), "tpm_share": hex::encode(shares[0].value()),
        "network_share": hex::encode(shares[1].value()),
        "descriptor": hex::encode(leelo_envelope::descriptor_bytes(&body.descriptor).unwrap()),
        "context": hex::encode(context), "tpm_context": hex::encode(tpm_context),
        "network_context": hex::encode(net_context), "network_input": hex::encode(input),
        "voprf_output": hex::encode(output), "tpm_key": hex::encode(tpm_key.as_ref()),
        "network_key": hex::encode(network_key.as_ref()), "payload_key": hex::encode(payload_key.as_ref()),
        "request": hex::encode(request), "response": hex::encode(response),
        "envelope": hex::encode(&envelope), "luks_token": leelo_luks::encode_token(3, &envelope).unwrap(),
        "rejections": ["outer_signature", "generation", "binding", "input_seed", "provider_pin", "tpm_object", "payload_authentication"]
    })
}
