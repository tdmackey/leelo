mod support;

use leelo_crypto::{Evaluation, SecretServer, SecretSigningKey};
use leelo_engine::{
    Error, NetworkFailure, NetworkProvider, TpmAuthorization, TpmProvider, UnsealedSeed,
};
use leelo_envelope::{AuthenticatedEnvelope, Descriptor, NetworkBinding, TpmBlob};
use leelo_policy::Mode;
use serde_json::Value;
use std::cell::Cell;
use std::time::Instant;
use zeroize::Zeroizing;

fn fixture() -> Value {
    serde_json::from_str(include_str!("../../../test-vectors/network-bound-v1.json")).unwrap()
}

struct Network {
    server: SecretServer,
    calls: Cell<usize>,
}
impl NetworkProvider for Network {
    async fn evaluate(
        &self,
        _: &NetworkBinding,
        point: &[u8; 49],
        _: Instant,
    ) -> Result<Evaluation, NetworkFailure> {
        self.calls.set(self.calls.get() + 1);
        self.server
            .evaluate(point)
            .map_err(|_| NetworkFailure::Cryptography)
    }
}
struct Tpm {
    seed: [u8; 32],
    calls: usize,
}
impl TpmProvider for Tpm {
    fn supports_mode(&self, mode: Mode) -> bool {
        mode == Mode::NetworkBound
    }
    fn seal(&mut self, _: &Descriptor, _: &[u8; 32]) -> Result<TpmBlob, Error> {
        panic!("recovery fixture cannot enroll")
    }
    fn unseal(&mut self, envelope: &AuthenticatedEnvelope) -> Result<UnsealedSeed, Error> {
        self.calls += 1;
        let blob = &envelope.body().tpm;
        if blob.public != b"test-public"
            || blob.private != b"test-private"
            || blob.name != b"test-name"
            || blob.parent_name != b"test-parent"
        {
            return Err(Error::Provider("fixture object mismatch"));
        }
        Ok(UnsealedSeed {
            seed: Zeroizing::new(self.seed),
            authorization: TpmAuthorization::LocalMeasuredBoot,
        })
    }
}
fn adapters(v: &Value) -> (Network, Tpm) {
    (
        Network {
            server: SecretServer::from_secret_bytes(&support::array(v, "evaluation_secret"))
                .unwrap(),
            calls: Cell::new(0),
        },
        Tpm {
            seed: support::array(v, "tpm_seed"),
            calls: 0,
        },
    )
}

#[test]
fn encoded_protocol_and_all_derived_values_match_the_frozen_vector() {
    assert_eq!(support::vector(), fixture());
}

#[test]
fn production_recovery_uses_fresh_blinds_and_returns_the_pinned_credential() {
    let v = fixture();
    let raw = hex::decode(v["envelope"].as_str().unwrap()).unwrap();
    let signer = support::array(&v, "signing_public");
    let (mut network, mut tpm) = adapters(&v);
    for _ in 0..3 {
        let recovered =
            leelo_engine::unlock(&raw, &signer, &[0x22; 16], 3, &mut network, &mut tpm).unwrap();
        assert_eq!(
            *recovered.credential,
            support::array::<32>(&v, "credential")
        );
        assert!(recovered.diagnostics.is_empty());
    }
    assert_eq!(network.calls.get(), 3);
    assert_eq!(tpm.calls, 3);
    let token = leelo_luks::decode_token(v["luks_token"].as_str().unwrap()).unwrap();
    assert_eq!(token.slot, 3);
    assert_eq!(token.bytes, raw);
}

#[test]
fn valid_signatures_cannot_mix_contexts_factors_or_payloads() {
    let v = fixture();
    let raw = hex::decode(v["envelope"].as_str().unwrap()).unwrap();
    let signer = SecretSigningKey::from_seed(&support::array(&v, "signing_seed"));
    for (case, expected_tpm_calls) in [
        ("generation", 0),
        ("binding", 0),
        ("input_seed", 0),
        ("provider_pin", 0),
        ("tpm_object", 1),
        ("payload_authentication", 1),
    ] {
        let mut body = leelo_envelope::authenticate(&raw, &signer.public_key())
            .unwrap()
            .body()
            .clone();
        match case {
            "generation" => body.descriptor.generation += 1,
            "binding" => body.descriptor.binding_id[0] ^= 1,
            "input_seed" => body.descriptor.networks[0].input_seed[0] ^= 1,
            "provider_pin" => {
                let other = SecretServer::from_secret_bytes(&[0x16; 48]).unwrap();
                body.descriptor.networks[0].public_key = *other.public_key().as_bytes();
                body.descriptor.networks[0].key_id =
                    leelo_protocol::key_id(other.public_key().as_bytes());
            }
            "tpm_object" => body.tpm.name[0] ^= 1,
            "payload_authentication" => body.payload.ciphertext[0] ^= 1,
            _ => unreachable!(),
        }
        let changed = leelo_envelope::sign(&body, &signer).unwrap();
        let (mut network, mut tpm) = adapters(&v);
        let error = leelo_engine::unlock(
            &changed,
            &signer.public_key(),
            &[0x22; 16],
            3,
            &mut network,
            &mut tpm,
        )
        .err()
        .unwrap();
        assert_eq!(tpm.calls, expected_tpm_calls, "{case}");
        if expected_tpm_calls == 0 {
            assert!(matches!(error, Error::InsufficientFactors { .. }), "{case}");
        } else if case == "tpm_object" {
            assert!(matches!(error, Error::Provider(_)));
        } else {
            assert!(matches!(error, Error::Crypto));
        }
    }
    let mut changed = raw;
    *changed.last_mut().unwrap() ^= 1;
    let (mut network, mut tpm) = adapters(&v);
    assert!(matches!(
        leelo_engine::unlock(
            &changed,
            &signer.public_key(),
            &[0x22; 16],
            3,
            &mut network,
            &mut tpm
        ),
        Err(Error::Envelope(_))
    ));
    assert_eq!((network.calls.get(), tpm.calls), (0, 0));
}
