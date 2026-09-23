use leelo_crypto::{Evaluation, SecretServer, SecretSigningKey};
use leelo_engine::{Error, NetworkProvider, TpmAuthorization, TpmProvider, UnsealedSeed};
use leelo_envelope::{AuthenticatedEnvelope, Descriptor, NetworkBinding, TpmBlob};
use leelo_policy::{Mode, NetworkNode, ProductionPolicy};
use zeroize::Zeroizing;

struct TestNetwork {
    keys: Vec<SecretServer>,
    offline: Vec<u8>,
    calls: usize,
}
impl NetworkProvider for TestNetwork {
    fn evaluate(&mut self, b: &NetworkBinding, blinded: &[u8; 49]) -> Result<Evaluation, Error> {
        self.calls += 1;
        if self.offline.contains(&b.node_id) {
            return Err(Error::Provider("test offline"));
        }
        self.keys[(b.node_id - 2) as usize]
            .evaluate(blinded)
            .map_err(|_| Error::Crypto)
    }
}
/// This test double is synthetic. Production code does not export a software-TPM fallback.
struct TestTpm {
    wrapping_key: Zeroizing<[u8; 32]>,
    calls: usize,
    available: bool,
    live: bool,
    supports_attested: bool,
}
impl TpmProvider for TestTpm {
    fn supports_mode(&self, mode: Mode) -> bool {
        mode == Mode::NetworkBound || self.supports_attested
    }
    fn seal(&mut self, _: &Descriptor, seed: &[u8; 32]) -> Result<TpmBlob, Error> {
        let wrapped = leelo_crypto::seal_key(&self.wrapping_key, seed, b"test-only")
            .map_err(|_| Error::Crypto)?;
        let mut private = wrapped.nonce.to_vec();
        private.extend(wrapped.ciphertext);
        Ok(TpmBlob {
            public: b"test-only".to_vec(),
            private,
            name: vec![1],
            parent_name: vec![2],
        })
    }
    fn unseal(&mut self, e: &AuthenticatedEnvelope) -> Result<UnsealedSeed, Error> {
        self.calls += 1;
        if !self.available {
            return Err(Error::Provider("test TPM absent"));
        }
        let blob = &e.body().tpm;
        if blob.private.len() != 60 || blob.name != [1] || blob.parent_name != [2] {
            return Err(Error::Provider("test blob invalid"));
        }
        let wrapped = leelo_crypto::WrappedKey {
            nonce: blob.private[..12].try_into().unwrap(),
            ciphertext: blob.private[12..].try_into().unwrap(),
        };
        let seed = leelo_crypto::open_key(&self.wrapping_key, &wrapped, b"test-only")
            .map_err(|_| Error::Crypto)?;
        Ok(UnsealedSeed {
            seed,
            authorization: if self.live {
                TpmAuthorization::FreshSessionAuthorization
            } else {
                TpmAuthorization::LocalMeasuredBoot
            },
        })
    }
}

fn fixture(mode: Mode, required: u8) -> (Descriptor, SecretSigningKey, TestNetwork, TestTpm) {
    let keys = vec![
        SecretServer::generate().unwrap(),
        SecretServer::generate().unwrap(),
    ];
    let node = NetworkNode::Threshold {
        id: 1,
        required,
        children: vec![
            NetworkNode::Leaf {
                id: 2,
                provider_id: [2; 32],
            },
            NetworkNode::Leaf {
                id: 3,
                provider_id: [3; 32],
            },
        ],
    };
    let policy = ProductionPolicy::new(mode, 0, node).unwrap();
    let networks = keys
        .iter()
        .enumerate()
        .map(|(i, k)| NetworkBinding {
            node_id: (i + 2) as u8,
            provider_id: [(i + 2) as u8; 32],
            key_id: [(i + 12) as u8; 32],
            public_key: *k.public_key().as_bytes(),
            input_seed: [(i + 22) as u8; 32],
        })
        .collect();
    (
        Descriptor {
            binding_id: [42; 32],
            volume_uuid: [43; 16],
            slot: 1,
            generation: 1,
            policy,
            networks,
            tpm_pcr_mask: 1 << 7,
            tpm_pcr_digest: [44; 32],
        },
        SecretSigningKey::from_seed(&[45; 32]),
        TestNetwork {
            keys,
            offline: vec![],
            calls: 0,
        },
        TestTpm {
            wrapping_key: Zeroizing::new([46; 32]),
            calls: 0,
            available: true,
            live: false,
            supports_attested: true,
        },
    )
}

#[test]
fn either_network_but_always_tpm() {
    let (desc, signer, mut net, mut tpm) = fixture(Mode::NetworkBound, 1);
    let prepared = leelo_engine::prepare(desc, &signer, &mut net, &mut tpm).unwrap();
    for offline in [vec![], vec![2], vec![3]] {
        net.offline = offline;
        let key = leelo_engine::unlock(
            &prepared.envelope,
            &signer.public_key(),
            &[43; 16],
            1,
            &mut net,
            &mut tpm,
        )
        .unwrap();
        assert_eq!(*key, *prepared.credential);
    }
    net.offline = vec![2, 3];
    assert!(
        leelo_engine::unlock(
            &prepared.envelope,
            &signer.public_key(),
            &[43; 16],
            1,
            &mut net,
            &mut tpm
        )
        .is_err()
    );
    net.offline.clear();
    tpm.available = false;
    assert!(
        leelo_engine::unlock(
            &prepared.envelope,
            &signer.public_key(),
            &[43; 16],
            1,
            &mut net,
            &mut tpm
        )
        .is_err()
    );
}

#[test]
fn two_network_threshold_does_not_degrade() {
    let (desc, signer, mut net, mut tpm) = fixture(Mode::NetworkBound, 2);
    let prepared = leelo_engine::prepare(desc, &signer, &mut net, &mut tpm).unwrap();
    assert!(
        leelo_engine::unlock(
            &prepared.envelope,
            &signer.public_key(),
            &[43; 16],
            1,
            &mut net,
            &mut tpm
        )
        .is_ok()
    );
    net.offline = vec![2];
    assert!(
        leelo_engine::unlock(
            &prepared.envelope,
            &signer.public_key(),
            &[43; 16],
            1,
            &mut net,
            &mut tpm
        )
        .is_err()
    );
}

#[test]
fn attested_requires_live_adapter_evidence() {
    let (desc, signer, mut net, mut tpm) = fixture(Mode::Attested, 1);
    let prepared = leelo_engine::prepare(desc, &signer, &mut net, &mut tpm).unwrap();
    assert!(matches!(
        leelo_engine::unlock(
            &prepared.envelope,
            &signer.public_key(),
            &[43; 16],
            1,
            &mut net,
            &mut tpm
        ),
        Err(Error::UnsupportedMode)
    ));
    tpm.live = true;
    assert!(
        leelo_engine::unlock(
            &prepared.envelope,
            &signer.public_key(),
            &[43; 16],
            1,
            &mut net,
            &mut tpm
        )
        .is_ok()
    );
}

#[test]
fn unsupported_mode_rejects_before_provider_io() {
    let (desc, signer, mut net, mut tpm) = fixture(Mode::Attested, 1);
    let prepared = leelo_engine::prepare(desc.clone(), &signer, &mut net, &mut tpm).unwrap();
    net.calls = 0;
    tpm.calls = 0;
    tpm.supports_attested = false;
    assert!(matches!(
        leelo_engine::unlock(
            &prepared.envelope,
            &signer.public_key(),
            &[43; 16],
            1,
            &mut net,
            &mut tpm
        ),
        Err(Error::UnsupportedMode)
    ));
    assert!(matches!(
        leelo_engine::prepare(desc, &signer, &mut net, &mut tpm),
        Err(Error::UnsupportedMode)
    ));
    assert_eq!(net.calls, 0);
    assert_eq!(tpm.calls, 0);
}

#[test]
fn every_byte_tamper_and_wrong_target_reject_before_provider_io() {
    let (desc, signer, mut net, mut tpm) = fixture(Mode::NetworkBound, 1);
    let prepared = leelo_engine::prepare(desc, &signer, &mut net, &mut tpm).unwrap();
    net.calls = 0;
    tpm.calls = 0;
    for i in 0..prepared.envelope.len() {
        let mut modified = prepared.envelope.clone();
        modified[i] ^= 1;
        assert!(
            leelo_engine::unlock(
                &modified,
                &signer.public_key(),
                &[43; 16],
                1,
                &mut net,
                &mut tpm
            )
            .is_err(),
            "mutation {i}"
        );
    }
    for (uuid, slot) in [([99; 16], 1), ([43; 16], 2)] {
        assert!(
            leelo_engine::unlock(
                &prepared.envelope,
                &signer.public_key(),
                &uuid,
                slot,
                &mut net,
                &mut tpm
            )
            .is_err()
        );
    }
    assert!(
        leelo_engine::unlock(
            &prepared.envelope,
            &SecretSigningKey::from_seed(&[99; 32]).public_key(),
            &[43; 16],
            1,
            &mut net,
            &mut tpm
        )
        .is_err()
    );
    assert_eq!((net.calls, tpm.calls), (0, 0));
}

#[test]
fn valid_signature_cannot_replace_payload_authentication() {
    let (desc, signer, mut net, mut tpm) = fixture(Mode::NetworkBound, 1);
    let prepared = leelo_engine::prepare(desc, &signer, &mut net, &mut tpm).unwrap();
    let authenticated =
        leelo_envelope::authenticate(&prepared.envelope, &signer.public_key()).unwrap();
    let mut body = authenticated.body().clone();
    body.payload.ciphertext[0] ^= 1;
    let resigned = leelo_envelope::sign(&body, &signer).unwrap();
    assert!(
        leelo_engine::unlock(
            &resigned,
            &signer.public_key(),
            &[43; 16],
            1,
            &mut net,
            &mut tpm
        )
        .is_err()
    );
}

#[test]
fn extra_bytes_and_noncanonical_framing_reject() {
    let (desc, signer, mut net, mut tpm) = fixture(Mode::NetworkBound, 1);
    let prepared = leelo_engine::prepare(desc, &signer, &mut net, &mut tpm).unwrap();
    let mut trailing = prepared.envelope.clone();
    trailing.push(0);
    assert!(leelo_envelope::authenticate(&trailing, &signer.public_key()).is_err());
    let mut noncanonical = vec![0x98, 2];
    noncanonical.extend_from_slice(&prepared.envelope[1..]);
    assert!(matches!(
        leelo_envelope::authenticate(&noncanonical, &signer.public_key()),
        Err(leelo_envelope::Error::NonCanonical)
    ));
    for len in [0, 1, 2, 8, 64, prepared.envelope.len() - 1] {
        assert!(
            leelo_envelope::authenticate(&prepared.envelope[..len], &signer.public_key()).is_err()
        );
    }
}
