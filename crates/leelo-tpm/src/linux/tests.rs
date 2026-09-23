use super::*;
use leelo_crypto::{Evaluation, SecretServer, SecretSigningKey};
use leelo_engine::NetworkProvider;
use leelo_envelope::{NetworkBinding, authenticate, sign};
use leelo_policy::{NetworkNode, ProductionPolicy};
use tss_esapi::{handles::PcrHandle, structures::DigestValues};

struct LocalNetwork(SecretServer);
impl NetworkProvider for LocalNetwork {
    fn evaluate(&mut self, _: &NetworkBinding, blinded: &[u8; 49]) -> Result<Evaluation, Error> {
        self.0.evaluate(blinded).map_err(|_| Error::Crypto)
    }
}

fn simulator() -> String {
    let transport = std::env::var("LEELO_TEST_SWTPM").expect("run scripts/test-tpm.sh");
    let port = transport
        .strip_prefix("swtpm:host=127.0.0.1,port=")
        .expect("tests only accept an explicitly supplied loopback software TPM");
    assert!(port.parse::<u16>().is_ok());
    transport
}

#[test]
fn invalid_pcr_mask_is_rejected_before_connecting() {
    let mut provider = Tpm2Provider::new("swtpm:host=127.0.0.1,port=1").unwrap();
    assert!(provider.pcr_digest(0).is_err());
    assert!(provider.pcr_digest(1 << 24).is_err());
}

#[test]
#[ignore = "requires the isolated swtpm created by scripts/test-tpm.sh"]
fn swtpm_real_sealing_engine_unlock_and_negative_policies() {
    let transport = simulator();
    let mut provider = Tpm2Provider::new(&transport).unwrap();
    let mut network = LocalNetwork(SecretServer::generate().unwrap());
    let signer = SecretSigningKey::generate().unwrap();
    let mask = (1 << 7) | (1 << 11) | (1 << 16);
    let descriptor = Descriptor {
        binding_id: [11; 32],
        volume_uuid: [12; 16],
        slot: 3,
        generation: 1,
        policy: ProductionPolicy::new(
            Mode::NetworkBound,
            1,
            NetworkNode::Leaf {
                id: 2,
                provider_id: [13; 32],
            },
        )
        .unwrap(),
        networks: vec![NetworkBinding {
            node_id: 2,
            provider_id: [13; 32],
            key_id: [14; 32],
            public_key: *network.0.public_key().as_bytes(),
            input_seed: [15; 32],
        }],
        tpm_pcr_mask: mask,
        tpm_pcr_digest: provider.pcr_digest(mask).unwrap(),
    };
    let enrollment =
        leelo_engine::prepare(descriptor.clone(), &signer, &mut network, &mut provider)
            .expect("salted encrypted seed creation");
    drop(provider);

    // A different ESAPI context recreates the same deterministic primary.
    let mut provider = Tpm2Provider::new(&transport).unwrap();
    let credential = leelo_engine::unlock(
        &enrollment.envelope,
        &signer.public_key(),
        &descriptor.volume_uuid,
        descriptor.slot,
        &mut network,
        &mut provider,
    )
    .expect("encrypted response and engine reconstruction");
    assert!(credential.as_ref() == enrollment.credential.as_ref());
    let envelope = authenticate(&enrollment.envelope, &signer.public_key()).unwrap();

    // The TPM itself rejects password-only authorization to the sealed object.
    let mut context = provider.context().unwrap();
    let (parent, _) = create_parent(&mut context).unwrap();
    let object = context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.load(
                parent,
                Private::try_from(envelope.body().tpm.private.as_slice()).unwrap(),
                Public::unmarshall(&envelope.body().tpm.public).unwrap(),
            )
        })
        .unwrap();
    assert!(
        context
            .execute_with_session(Some(AuthSession::Password), |ctx| ctx.unseal(object.into()))
            .is_err()
    );
    drop(context);

    let mut altered = envelope.body().clone();
    altered.tpm.parent_name[33] ^= 1;
    let bytes = sign(&altered, &signer).unwrap();
    assert!(
        provider
            .unseal(&authenticate(&bytes, &signer.public_key()).unwrap())
            .is_err()
    );

    let mut altered = envelope.body().clone();
    altered.tpm.name[33] ^= 1;
    let bytes = sign(&altered, &signer).unwrap();
    assert!(
        provider
            .unseal(&authenticate(&bytes, &signer.public_key()).unwrap())
            .is_err()
    );

    let mut altered = envelope.body().clone();
    altered.descriptor.tpm_pcr_digest[0] ^= 1;
    let bytes = sign(&altered, &signer).unwrap();
    assert!(
        provider
            .unseal(&authenticate(&bytes, &signer.public_key()).unwrap())
            .is_err()
    );

    let mut altered = envelope.body().clone();
    altered.tpm.private[0] ^= 1;
    let bytes = sign(&altered, &signer).unwrap();
    assert!(
        provider
            .unseal(&authenticate(&bytes, &signer.public_key()).unwrap())
            .is_err()
    );

    // The adapter rejects attested mode even when the transport cannot connect.
    let mut attested = descriptor.clone();
    attested.policy =
        ProductionPolicy::new(Mode::Attested, 1, descriptor.policy.network().clone()).unwrap();
    let mut disconnected = Tpm2Provider::new("swtpm:host=127.0.0.1,port=1").unwrap();
    assert!(matches!(
        disconnected.seal(&attested, &[0; 32]),
        Err(Error::UnsupportedMode)
    ));
    let mut altered = envelope.body().clone();
    altered.descriptor = attested;
    let bytes = sign(&altered, &signer).unwrap();
    assert!(matches!(
        disconnected.unseal(&authenticate(&bytes, &signer.public_key()).unwrap()),
        Err(Error::UnsupportedMode)
    ));

    // Change a selected PCR through the TPM command API. Do not use a subprocess.
    let mut context = provider.context().unwrap();
    let mut digests = DigestValues::new();
    digests.set(
        HashingAlgorithm::Sha256,
        Digest::try_from([0x42_u8; 32].as_slice()).unwrap(),
    );
    context
        .execute_with_session(Some(AuthSession::Password), |ctx| {
            ctx.pcr_extend(PcrHandle::Pcr16, digests)
        })
        .unwrap();
    drop(context);
    assert!(
        leelo_engine::unlock(
            &enrollment.envelope,
            &signer.public_key(),
            &descriptor.volume_uuid,
            descriptor.slot,
            &mut network,
            &mut provider
        )
        .is_err()
    );
}
