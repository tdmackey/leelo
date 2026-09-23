//! This crate owns enrollment and recovery. Providers are explicit trusted adapters.
#![forbid(unsafe_code)]
use futures_util::{StreamExt, stream::FuturesUnordered};
use leelo_crypto::{Evaluation, SecretSigningKey, ServerPublicKey};
use leelo_envelope::{
    AuthenticatedEnvelope, Descriptor, EnvelopeBody, NetworkBinding, TpmBlob, WrappedLeaf,
};
use leelo_policy::{Mode, PolicyError};
use rand_core::OsRng;
use std::cell::Cell;
use std::future::Future;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;
const OPERATION_BUDGET: Duration = Duration::from_secs(30);
const MAX_NETWORK_OPERATIONS: usize = 4;

pub mod observation;
mod recovery;
mod release;
use observation::{MAX_PROVIDER_OBSERVATIONS, OperationReport, Phase, ProviderOutcome, Stage};

#[cfg(test)]
mod tests;

/// These categories contain no secrets or response bodies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkFailure {
    Configuration,
    Unavailable,
    Timeout,
    RemoteRejected,
    InvalidResponse,
    InvalidProof,
    Authentication,
    Cryptography,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderFailure {
    pub provider_id: [u8; 32],
    pub kind: NetworkFailure,
}
#[derive(Debug)]
pub enum Error {
    Envelope(leelo_envelope::Error),
    Crypto,
    Sharing,
    Policy,
    Provider(&'static str),
    Tpm {
        operation: &'static str,
        detail: String,
    },
    InsufficientFactors {
        failures: Vec<ProviderFailure>,
    },
    DeadlineExceeded {
        failures: Vec<ProviderFailure>,
    },
    InconsistentShares,
    TargetMismatch,
    UnsupportedMode,
    Runtime,
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
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Envelope(error) => Some(error),
            _ => None,
        }
    }
}
/// Only a trusted TPM adapter can assert live authorization.
/// The adapter must implement PolicySigned under the enrolled authority.
pub enum TpmAuthorization {
    LocalMeasuredBoot,
    FreshSessionAuthorization,
}
pub struct UnsealedSeed {
    pub seed: Zeroizing<[u8; 32]>,
    pub authorization: TpmAuthorization,
}
pub trait NetworkProvider {
    /// Stop I/O when the future is dropped. Enforce the complete-response deadline.
    /// Do not block the executor or start detached work.
    fn evaluate(
        &self,
        binding: &NetworkBinding,
        blinded: &[u8; 49],
        deadline: Instant,
    ) -> impl Future<Output = Result<Evaluation, NetworkFailure>>;
}
pub trait TpmProvider {
    /// Check capability without TPM or network I/O.
    fn supports_mode(&self, mode: Mode) -> bool;
    fn seal(&mut self, descriptor: &Descriptor, seed: &[u8; 32]) -> Result<TpmBlob, Error>;
    fn unseal(&mut self, envelope: &AuthenticatedEnvelope) -> Result<UnsealedSeed, Error>;
}
/// Pass the credential to libcryptsetup. Do not log it or convert it to a string.
pub struct PreparedEnrollment {
    pub envelope: Vec<u8>,
    pub credential: Zeroizing<[u8; 32]>,
}
pub struct UnlockResult {
    pub credential: Zeroizing<[u8; 32]>,
    pub diagnostics: Vec<ProviderFailure>,
}
fn runtime() -> Result<tokio::runtime::Runtime, Error> {
    // The public operations are synchronous. Reject nested runtime use without a panic.
    if tokio::runtime::Handle::try_current().is_ok() {
        return Err(Error::Runtime);
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| Error::Runtime)
}
fn check_deadline(deadline: Instant) -> Result<(), Error> {
    if Instant::now() >= deadline {
        Err(Error::DeadlineExceeded {
            failures: Vec::new(),
        })
    } else {
        Ok(())
    }
}
fn fresh_secret() -> Result<Zeroizing<[u8; 32]>, Error> {
    leelo_crypto::random_bytes().map_err(|_| Error::Crypto)
}
fn derive(ikm: &[u8], context: &[u8], purpose: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
    leelo_crypto::derive_secret_key(ikm, context, purpose).map_err(|_| Error::Crypto)
}
async fn network_key(
    d: &Descriptor,
    b: &NetworkBinding,
    context: &[u8; 48],
    net: &impl NetworkProvider,
    deadline: Instant,
) -> Result<Zeroizing<[u8; 32]>, NetworkFailure> {
    let input = leelo_envelope::network_input(d, b);
    let (state, blinded) = leelo_crypto::blind(&input).map_err(|_| NetworkFailure::Cryptography)?;
    let evaluation = net.evaluate(b, &blinded, deadline).await?;
    let pk =
        ServerPublicKey::from_bytes(b.public_key).map_err(|_| NetworkFailure::Configuration)?;
    let output = state
        .finalize(&evaluation, &pk)
        .map_err(|_| NetworkFailure::InvalidProof)?;
    leelo_crypto::derive_wrap_key(&output, &leelo_envelope::leaf_context(context, b.node_id))
        .map_err(|_| NetworkFailure::Cryptography)
}
fn policy_error(error: PolicyError) -> Error {
    match error {
        PolicyError::FactorsNotSatisfied => Error::InsufficientFactors {
            failures: Vec::new(),
        },
        PolicyError::Sharing(leelo_sss::Error::InconsistentShares) => Error::InconsistentShares,
        _ => Error::Policy,
    }
}
pub fn prepare(
    descriptor: Descriptor,
    signer: &SecretSigningKey,
    net: &mut impl NetworkProvider,
    tpm: &mut impl TpmProvider,
) -> Result<PreparedEnrollment, Error> {
    prepare_observed(
        descriptor,
        signer,
        net,
        tpm,
        &mut OperationReport::default(),
    )
}
pub fn prepare_observed(
    descriptor: Descriptor,
    signer: &SecretSigningKey,
    net: &mut impl NetworkProvider,
    tpm: &mut impl TpmProvider,
    report: &mut OperationReport,
) -> Result<PreparedEnrollment, Error> {
    let started = Instant::now();
    report.begin(Phase::Prepare);
    let result = prepare_inner(descriptor, signer, net, tpm, report);
    report.finish(
        started,
        result.as_ref().err().map(observation::Failure::from_error),
    );
    result
}
fn prepare_inner(
    descriptor: Descriptor,
    signer: &SecretSigningKey,
    net: &mut impl NetworkProvider,
    tpm: &mut impl TpmProvider,
    report: &mut OperationReport,
) -> Result<PreparedEnrollment, Error> {
    let deadline = Instant::now() + OPERATION_BUDGET;
    let context = leelo_envelope::context_hash(&descriptor)?;
    report.configure(descriptor.policy.mode(), &descriptor.networks);
    if !tpm.supports_mode(descriptor.policy.mode()) {
        return Err(Error::UnsupportedMode);
    }
    let executor = runtime()?;
    let credential = fresh_secret()?;
    let root = fresh_secret()?;
    let root_shares = leelo_sss::split(&root, 2, 2, &mut OsRng).map_err(|_| Error::Sharing)?;
    let tpm_seed = fresh_secret()?;
    report.enter(Stage::TpmSeal);
    let blob = tpm.seal(&descriptor, &tpm_seed)?;
    check_deadline(deadline)?;
    report.enter(Stage::ShareGeneration);
    let tpm_context = leelo_envelope::leaf_context(&context, descriptor.policy.tpm_node_id());
    let tpm_key = derive(tpm_seed.as_ref(), &tpm_context, b"leelo/v1/tpm-wrap")?;
    let mut leaves = vec![WrappedLeaf {
        node_id: descriptor.policy.tpm_node_id(),
        value: leelo_crypto::seal_key(&tpm_key, root_shares[0].value(), &tpm_context)
            .map_err(|_| Error::Crypto)?,
    }];
    let network_shares = descriptor
        .policy
        .split_network(root_shares[1].value(), &mut OsRng)
        .map_err(policy_error)?;
    // Check every generated share before signing the enrollment.
    let reconstructed = descriptor
        .policy
        .recover_network(&network_shares)
        .map_err(policy_error)?;
    if *reconstructed != *root_shares[1].value() {
        return Err(Error::InconsistentShares);
    }
    report.enter(Stage::Network);
    for (index, ((id, secret), binding)) in
        network_shares.iter().zip(&descriptor.networks).enumerate()
    {
        if *id != binding.node_id {
            return Err(Error::Policy);
        }
        let provider_started = Instant::now();
        let key_result = executor.block_on(async {
            tokio::time::timeout_at(
                deadline.into(),
                network_key(&descriptor, binding, &context, net, deadline),
            )
            .await
        });
        let key = match key_result {
            Err(_) => {
                report.provider(
                    index,
                    ProviderOutcome::CanceledDeadline,
                    provider_started.elapsed(),
                );
                return Err(Error::DeadlineExceeded {
                    failures: vec![ProviderFailure {
                        provider_id: binding.provider_id,
                        kind: NetworkFailure::Timeout,
                    }],
                });
            }
            Ok(Err(kind)) => {
                report.provider(
                    index,
                    ProviderOutcome::Failed(kind),
                    provider_started.elapsed(),
                );
                return Err(Error::InsufficientFactors {
                    failures: vec![ProviderFailure {
                        provider_id: binding.provider_id,
                        kind,
                    }],
                });
            }
            Ok(Ok(key)) => key,
        };
        let leaf_context = leelo_envelope::leaf_context(&context, *id);
        let value = leelo_crypto::seal_key(&key, secret, &leaf_context).map_err(|_| {
            report.provider(
                index,
                ProviderOutcome::Failed(NetworkFailure::Cryptography),
                provider_started.elapsed(),
            );
            Error::Crypto
        })?;
        let checked = leelo_crypto::open_key(&key, &value, &leaf_context).map_err(|_| {
            report.provider(
                index,
                ProviderOutcome::Failed(NetworkFailure::Authentication),
                provider_started.elapsed(),
            );
            Error::Crypto
        })?;
        if *checked != **secret {
            report.provider(
                index,
                ProviderOutcome::Failed(NetworkFailure::Authentication),
                provider_started.elapsed(),
            );
            return Err(Error::InconsistentShares);
        }
        report.provider(
            index,
            ProviderOutcome::Authenticated,
            provider_started.elapsed(),
        );
        leaves.push(WrappedLeaf {
            node_id: *id,
            value,
        });
    }
    report.enter(Stage::PreparePayload);
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
    check_deadline(deadline)?;
    Ok(PreparedEnrollment {
        envelope,
        credential,
    })
}
async fn recover_leaf(
    envelope: &AuthenticatedEnvelope,
    binding: &NetworkBinding,
    net: &impl NetworkProvider,
    deadline: Instant,
) -> (u8, [u8; 32], Result<Zeroizing<[u8; 32]>, NetworkFailure>) {
    let result = async {
        let key = network_key(
            &envelope.body().descriptor,
            binding,
            envelope.context(),
            net,
            deadline,
        )
        .await?;
        let wrapped = envelope
            .body()
            .leaves
            .iter()
            .find(|leaf| leaf.node_id == binding.node_id)
            .ok_or(NetworkFailure::Configuration)?;
        leelo_crypto::open_key(
            &key,
            &wrapped.value,
            &leelo_envelope::leaf_context(envelope.context(), binding.node_id),
        )
        .map_err(|_| NetworkFailure::Authentication)
    }
    .await;
    (binding.node_id, binding.provider_id, result)
}
#[cfg(test)]
async fn recover_network(
    envelope: &AuthenticatedEnvelope,
    net: &impl NetworkProvider,
    deadline: Instant,
) -> Result<(Zeroizing<[u8; 32]>, Vec<ProviderFailure>, Vec<u8>), Error> {
    let mut report = OperationReport::default();
    report.configure(
        envelope.body().descriptor.policy.mode(),
        &envelope.body().descriptor.networks,
    );
    recover_network_observed(envelope, net, deadline, &mut report).await
}
async fn started_leaf(
    envelope: &AuthenticatedEnvelope,
    binding: &NetworkBinding,
    net: &impl NetworkProvider,
    deadline: Instant,
    started: &Cell<Option<Instant>>,
) -> (u8, [u8; 32], Result<Zeroizing<[u8; 32]>, NetworkFailure>) {
    started.set(Some(Instant::now()));
    recover_leaf(envelope, binding, net, deadline).await
}
fn cancel_observations(
    report: &mut OperationReport,
    starts: &[Cell<Option<Instant>>; MAX_PROVIDER_OBSERVATIONS],
    outcome: ProviderOutcome,
) {
    for (index, start) in starts.iter().enumerate() {
        if report.pending(index)
            && let Some(start) = start.get()
        {
            report.provider(index, outcome, start.elapsed());
        }
    }
}
async fn recover_network_observed(
    envelope: &AuthenticatedEnvelope,
    net: &impl NetworkProvider,
    deadline: Instant,
    report: &mut OperationReport,
) -> Result<(Zeroizing<[u8; 32]>, Vec<ProviderFailure>, Vec<u8>), Error> {
    let descriptor = &envelope.body().descriptor;
    let mut remaining = descriptor.networks.iter().enumerate();
    let starts = [const { Cell::new(None) }; MAX_PROVIDER_OBSERVATIONS];
    let mut pending = FuturesUnordered::new();
    let mut recovered = Vec::new();
    let mut available = Vec::new();
    let mut failures = Vec::new();
    for (index, binding) in remaining.by_ref().take(MAX_NETWORK_OPERATIONS) {
        pending.push(started_leaf(
            envelope,
            binding,
            net,
            deadline,
            &starts[index],
        ));
    }
    while !pending.is_empty() {
        let next = match tokio::time::timeout_at(deadline.into(), pending.next()).await {
            Ok(next) => next,
            Err(_) => {
                let queued = descriptor.networks.len() - remaining.len();
                for binding in &descriptor.networks[..queued] {
                    if !available.contains(&binding.node_id)
                        && !failures.iter().any(|failure: &ProviderFailure| {
                            failure.provider_id == binding.provider_id
                        })
                    {
                        failures.push(ProviderFailure {
                            provider_id: binding.provider_id,
                            kind: NetworkFailure::Timeout,
                        });
                    }
                }
                drop(pending);
                cancel_observations(report, &starts, ProviderOutcome::CanceledDeadline);
                return Err(Error::DeadlineExceeded { failures });
            }
        };
        let Some((node_id, provider_id, result)) = next else {
            break;
        };
        if let Some(index) = descriptor
            .networks
            .iter()
            .position(|binding| binding.node_id == node_id)
        {
            let outcome = match &result {
                Ok(_) => ProviderOutcome::Authenticated,
                Err(kind) => ProviderOutcome::Failed(*kind),
            };
            report.provider(
                index,
                outcome,
                starts[index]
                    .get()
                    .map_or(Duration::ZERO, |start| start.elapsed()),
            );
        }
        match result {
            Ok(share) => {
                recovered.push((node_id, share));
                available.push(node_id);
            }
            Err(kind) => failures.push(ProviderFailure { provider_id, kind }),
        }
        let satisfied = descriptor
            .policy
            .network_satisfied(&available)
            .map_err(policy_error);
        let satisfied = match satisfied {
            Ok(value) => value,
            Err(error) => {
                drop(pending);
                cancel_observations(report, &starts, ProviderOutcome::CanceledOperation);
                return Err(error);
            }
        };
        if satisfied {
            // No pending network operation survives the recovery phase.
            drop(pending);
            cancel_observations(report, &starts, ProviderOutcome::CanceledQuorum);
            let share = descriptor
                .policy
                .recover_network(&recovered)
                .map_err(policy_error)?;
            return Ok((share, failures, available));
        }
        if let Some((index, binding)) = remaining.next() {
            pending.push(started_leaf(
                envelope,
                binding,
                net,
                deadline,
                &starts[index],
            ));
        }
    }
    Err(Error::InsufficientFactors { failures })
}
/// Authenticate the envelope and target before provider I/O.
/// Network I/O has one deadline. TPM calls are synchronous; check the deadline after
/// each call and before release. This cannot interrupt a blocked TPM driver call.
pub fn unlock(
    raw: &[u8],
    trusted_signer: &[u8; 32],
    expected_volume: &[u8; 16],
    expected_slot: u8,
    net: &mut impl NetworkProvider,
    tpm: &mut impl TpmProvider,
) -> Result<UnlockResult, Error> {
    unlock_observed(
        raw,
        trusted_signer,
        expected_volume,
        expected_slot,
        net,
        tpm,
        &mut OperationReport::default(),
    )
}
pub fn unlock_observed(
    raw: &[u8],
    trusted_signer: &[u8; 32],
    expected_volume: &[u8; 16],
    expected_slot: u8,
    net: &mut impl NetworkProvider,
    tpm: &mut impl TpmProvider,
    report: &mut OperationReport,
) -> Result<UnlockResult, Error> {
    let started = Instant::now();
    report.begin(Phase::Recover);
    let result = unlock_before_observed(
        raw,
        trusted_signer,
        expected_volume,
        expected_slot,
        net,
        tpm,
        UnlockObservation {
            deadline: started + OPERATION_BUDGET,
            report,
        },
    );
    report.finish(
        started,
        result.as_ref().err().map(observation::Failure::from_error),
    );
    result
}
struct UnlockObservation<'a> {
    deadline: Instant,
    report: &'a mut OperationReport,
}
fn unlock_before_observed(
    raw: &[u8],
    trusted_signer: &[u8; 32],
    expected_volume: &[u8; 16],
    expected_slot: u8,
    net: &mut impl NetworkProvider,
    tpm: &mut impl TpmProvider,
    observation: UnlockObservation<'_>,
) -> Result<UnlockResult, Error> {
    let UnlockObservation { deadline, report } = observation;
    recovery::UnlockOperation::begin(
        raw,
        trusted_signer,
        expected_volume,
        expected_slot,
        tpm,
        deadline,
        report,
    )?
    .run(net, tpm, report)
}
