//! This crate controls enrollment and recovery. Providers are explicit trusted adapters.
#![forbid(unsafe_code)]

use leelo_crypto::{Evaluation, SecretSigningKey, ServerPublicKey};
use leelo_envelope::{
    AuthenticatedEnvelope, Descriptor, EnvelopeBody, NetworkBinding, TpmBlob, WrappedLeaf,
};
use leelo_policy::{Mode, NetworkNode, PolicySession};
use leelo_sss::Share;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

#[derive(Debug)]
pub enum Error {
    Envelope(leelo_envelope::Error),
    Crypto,
    Sharing,
    Policy,
    Provider(&'static str),
    InsufficientFactors,
    TargetMismatch,
    UnsupportedMode,
}
impl From<leelo_envelope::Error> for Error {
    fn from(e: leelo_envelope::Error) -> Self {
        Self::Envelope(e)
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "leelo: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Only a trusted TPM adapter can assert live authorization.
/// The adapter must implement PolicySigned under the enrolled authority.
/// A userspace boolean is not authorization evidence.
pub enum TpmAuthorization {
    LocalMeasuredBoot,
    FreshSessionAuthorization,
}
pub struct UnsealedSeed {
    pub seed: Zeroizing<[u8; 32]>,
    pub authorization: TpmAuthorization,
}

pub trait NetworkProvider {
    fn evaluate(
        &mut self,
        binding: &NetworkBinding,
        blinded: &[u8; 49],
    ) -> Result<Evaluation, Error>;
}
pub trait TpmProvider {
    /// Check capability without TPM or network I/O.
    /// Support for a mode is not authorization evidence. It does not bypass recovery checks.
    fn supports_mode(&self, mode: Mode) -> bool;
    fn seal(&mut self, descriptor: &Descriptor, seed: &[u8; 32]) -> Result<TpmBlob, Error>;
    /// Call this method only with a structurally valid envelope that has an authenticated signature.
    fn unseal(&mut self, envelope: &AuthenticatedEnvelope) -> Result<UnsealedSeed, Error>;
}

/// The caller passes this credential directly to libcryptsetup. Do not put the credential in a log or string.
pub struct PreparedEnrollment {
    pub envelope: Vec<u8>,
    pub credential: Zeroizing<[u8; 32]>,
}

fn fresh_secret() -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut secret = Zeroizing::new([0u8; 32]);
    OsRng
        .try_fill_bytes(secret.as_mut())
        .map_err(|_| Error::Crypto)?;
    Ok(secret)
}
fn derive(ikm: &[u8], context: &[u8], purpose: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
    leelo_crypto::derive_secret_key(ikm, context, purpose).map_err(|_| Error::Crypto)
}
fn network_key(
    d: &Descriptor,
    b: &NetworkBinding,
    context: &[u8; 48],
    net: &mut impl NetworkProvider,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let input = leelo_envelope::network_input(d, b);
    let (state, blinded) = leelo_crypto::blind(&input).map_err(|_| Error::Crypto)?;
    let evaluation = net.evaluate(b, &blinded)?;
    let pk = ServerPublicKey::from_bytes(b.public_key).map_err(|_| Error::Crypto)?;
    let output = state
        .finalize(&evaluation, &pk)
        .map_err(|_| Error::Crypto)?;
    leelo_crypto::derive_wrap_key(&output, &leelo_envelope::leaf_context(context, b.node_id))
        .map_err(|_| Error::Crypto)
}

fn split_network(
    node: &NetworkNode,
    secret: &[u8; 32],
    outputs: &mut Vec<(u8, Zeroizing<[u8; 32]>)>,
) -> Result<(), Error> {
    match node {
        NetworkNode::Leaf { id, .. } => outputs.push((*id, Zeroizing::new(*secret))),
        NetworkNode::Threshold {
            required, children, ..
        } => {
            let shares = leelo_sss::split(secret, *required, children.len() as u8, &mut OsRng)
                .map_err(|_| Error::Sharing)?;
            for (child, share) in children.iter().zip(&shares) {
                split_network(child, share.value(), outputs)?;
            }
        }
    }
    Ok(())
}

pub fn prepare(
    descriptor: Descriptor,
    signer: &SecretSigningKey,
    net: &mut impl NetworkProvider,
    tpm: &mut impl TpmProvider,
) -> Result<PreparedEnrollment, Error> {
    let context = leelo_envelope::context_hash(&descriptor)?;
    if !tpm.supports_mode(descriptor.policy.mode()) {
        return Err(Error::UnsupportedMode);
    }
    let credential = fresh_secret()?;
    let root = fresh_secret()?;
    let root_shares = leelo_sss::split(&root, 2, 2, &mut OsRng).map_err(|_| Error::Sharing)?;
    let tpm_seed = fresh_secret()?;
    let blob = tpm.seal(&descriptor, &tpm_seed)?;
    let tpm_context = leelo_envelope::leaf_context(&context, descriptor.policy.tpm_node_id());
    let tpm_key = derive(tpm_seed.as_ref(), &tpm_context, b"leelo/v1/tpm-wrap")?;
    let mut leaves = vec![WrappedLeaf {
        node_id: descriptor.policy.tpm_node_id(),
        value: leelo_crypto::seal_key(&tpm_key, root_shares[0].value(), &tpm_context)
            .map_err(|_| Error::Crypto)?,
    }];
    let mut network_shares = Vec::new();
    split_network(
        descriptor.policy.network(),
        root_shares[1].value(),
        &mut network_shares,
    )?;
    for ((id, secret), binding) in network_shares.iter().zip(&descriptor.networks) {
        if *id != binding.node_id {
            return Err(Error::Policy);
        }
        let key = network_key(&descriptor, binding, &context, net)?;
        leaves.push(WrappedLeaf {
            node_id: *id,
            value: leelo_crypto::seal_key(
                &key,
                secret,
                &leelo_envelope::leaf_context(&context, *id),
            )
            .map_err(|_| Error::Crypto)?,
        });
    }
    let payload_key = derive(root.as_ref(), &context, b"leelo/v1/luks-slot")?;
    let payload =
        leelo_crypto::seal_key(&payload_key, &credential, &context).map_err(|_| Error::Crypto)?;
    let body = EnvelopeBody {
        descriptor,
        tpm: blob,
        leaves,
        payload,
    };
    let envelope = leelo_envelope::sign(&body, signer)?;
    Ok(PreparedEnrollment {
        envelope,
        credential,
    })
}

fn recover_node(
    node: &NetworkNode,
    recovered: &[(u8, Zeroizing<[u8; 32]>)],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    match node {
        NetworkNode::Leaf { id, .. } => recovered
            .iter()
            .find(|(n, _)| n == id)
            .map(|(_, v)| Zeroizing::new(**v))
            .ok_or(Error::InsufficientFactors),
        NetworkNode::Threshold {
            required, children, ..
        } => {
            let mut shares = Vec::new();
            for (i, child) in children.iter().enumerate() {
                if let Ok(secret) = recover_node(child, recovered) {
                    shares.push(
                        Share::from_parts((i + 1) as u8, secret).map_err(|_| Error::Sharing)?,
                    );
                    if shares.len() == *required as usize {
                        break;
                    }
                }
            }
            leelo_sss::reconstruct(*required, &shares).map_err(|_| Error::InsufficientFactors)
        }
    }
}

/// Verify the envelope and target before the first provider action.
/// Do not return a partial credential after failure. Availability failures never change the mode.
pub fn unlock(
    raw: &[u8],
    trusted_signer: &[u8; 32],
    expected_volume: &[u8; 16],
    expected_slot: u8,
    net: &mut impl NetworkProvider,
    tpm: &mut impl TpmProvider,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let envelope = leelo_envelope::authenticate(raw, trusted_signer)?;
    let body = envelope.body();
    let descriptor = &body.descriptor;
    if &descriptor.volume_uuid != expected_volume || descriptor.slot != expected_slot {
        return Err(Error::TargetMismatch);
    }
    if !tpm.supports_mode(descriptor.policy.mode()) {
        return Err(Error::UnsupportedMode);
    }
    let mut session = PolicySession::new(&descriptor.policy);
    session.authenticate_envelope().map_err(|_| Error::Policy)?;
    let context = envelope.context();
    let mut network_shares = Vec::new();
    for binding in &descriptor.networks {
        let Ok(key) = network_key(descriptor, binding, context, net) else {
            continue;
        };
        let wrapped = &body
            .leaves
            .iter()
            .find(|l| l.node_id == binding.node_id)
            .ok_or(Error::Policy)?
            .value;
        let Ok(share) = leelo_crypto::open_key(
            &key,
            wrapped,
            &leelo_envelope::leaf_context(context, binding.node_id),
        ) else {
            continue;
        };
        session
            .accept_network(binding.node_id)
            .map_err(|_| Error::Policy)?;
        network_shares.push((binding.node_id, share));
    }
    let network_share = recover_node(descriptor.policy.network(), &network_shares)?;
    let unsealed = tpm.unseal(&envelope)?;
    if descriptor.policy.mode() == Mode::Attested {
        if !matches!(
            unsealed.authorization,
            TpmAuthorization::FreshSessionAuthorization
        ) {
            return Err(Error::UnsupportedMode);
        }
        session
            .confirm_live_authorization()
            .map_err(|_| Error::Policy)?;
    }
    let tpm_context = leelo_envelope::leaf_context(context, descriptor.policy.tpm_node_id());
    let tpm_key = derive(unsealed.seed.as_ref(), &tpm_context, b"leelo/v1/tpm-wrap")?;
    let tpm_share = leelo_crypto::open_key(&tpm_key, &body.leaves[0].value, &tpm_context)
        .map_err(|_| Error::Crypto)?;
    session.confirm_tpm().map_err(|_| Error::Policy)?;
    let shares = [
        Share::from_parts(1, tpm_share).map_err(|_| Error::Sharing)?,
        Share::from_parts(2, network_share).map_err(|_| Error::Sharing)?,
    ];
    let root = leelo_sss::reconstruct(2, &shares).map_err(|_| Error::Sharing)?;
    let payload_key = derive(root.as_ref(), context, b"leelo/v1/luks-slot")?;
    let credential =
        leelo_crypto::open_key(&payload_key, &body.payload, context).map_err(|_| Error::Crypto)?;
    session.authenticate_root().map_err(|_| Error::Policy)?;
    session.release().map_err(|_| Error::Policy)?;
    Ok(credential)
}
