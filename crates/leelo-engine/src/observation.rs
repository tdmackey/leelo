//! Bounded, secret-free observations. This module performs no I/O and invokes no observers.
use crate::{Error, NetworkFailure};
use leelo_envelope::NetworkBinding;
use leelo_policy::Mode;
use std::time::{Duration, Instant};

pub const MAX_PROVIDER_OBSERVATIONS: usize = leelo_policy::MAX_NODES;
const MAX_STAGES: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Prepare,
    Recover,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Validate,
    TpmSeal,
    ShareGeneration,
    Network,
    TpmUnseal,
    PreparePayload,
    AuthenticatePayload,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    Envelope,
    Cryptography,
    Sharing,
    Policy,
    Tpm,
    InsufficientFactors,
    Deadline,
    InconsistentShares,
    TargetMismatch,
    UnsupportedMode,
    Runtime,
}
impl Failure {
    pub fn from_error(error: &Error) -> Self {
        match error {
            Error::Envelope(_) => Self::Envelope,
            Error::Crypto => Self::Cryptography,
            Error::Sharing => Self::Sharing,
            Error::Policy => Self::Policy,
            Error::Provider(_) | Error::Tpm { .. } => Self::Tpm,
            Error::InsufficientFactors { .. } => Self::InsufficientFactors,
            Error::DeadlineExceeded { .. } => Self::Deadline,
            Error::InconsistentShares => Self::InconsistentShares,
            Error::TargetMismatch => Self::TargetMismatch,
            Error::UnsupportedMode => Self::UnsupportedMode,
            Error::Runtime => Self::Runtime,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderOutcome {
    NotStarted,
    /// The VOPRF proof and the wrapped share have both been authenticated.
    Authenticated,
    Failed(NetworkFailure),
    CanceledQuorum,
    CanceledDeadline,
    CanceledOperation,
}
#[derive(Clone, Copy, Debug)]
pub struct ProviderObservation {
    pub provider_id: [u8; 32],
    pub outcome: ProviderOutcome,
    pub duration: Duration,
}
#[derive(Clone, Copy, Debug)]
pub struct StageObservation {
    pub stage: Stage,
    pub duration: Duration,
    pub failure: Option<Failure>,
}

/// Caller-owned report survives both successful and failed operations. Fixed arrays bound
/// memory independently of provider input. No secret-bearing value is accepted by this type.
#[derive(Debug)]
pub struct OperationReport {
    pub phase: Phase,
    pub mode: Option<Mode>,
    pub duration: Duration,
    pub failure: Option<Failure>,
    providers: [Option<ProviderObservation>; MAX_PROVIDER_OBSERVATIONS],
    stages: [Option<StageObservation>; MAX_STAGES],
    active_stage: Option<(Stage, Instant)>,
}
impl Default for OperationReport {
    fn default() -> Self {
        Self::new(Phase::Recover)
    }
}
impl OperationReport {
    fn new(phase: Phase) -> Self {
        Self {
            phase,
            mode: None,
            duration: Duration::ZERO,
            failure: None,
            providers: [None; MAX_PROVIDER_OBSERVATIONS],
            stages: [None; MAX_STAGES],
            active_stage: None,
        }
    }
    pub fn providers(&self) -> impl Iterator<Item = &ProviderObservation> {
        self.providers.iter().flatten()
    }
    pub fn stages(&self) -> impl Iterator<Item = &StageObservation> {
        self.stages.iter().flatten()
    }
    pub fn degraded(&self) -> bool {
        self.providers()
            .any(|p| matches!(p.outcome, ProviderOutcome::Failed(_)))
    }
    pub(crate) fn begin(&mut self, phase: Phase) {
        *self = Self::new(phase);
        self.enter(Stage::Validate);
    }
    pub(crate) fn configure(&mut self, mode: Mode, providers: &[NetworkBinding]) {
        self.mode = Some(mode);
        for (entry, binding) in self.providers.iter_mut().zip(providers) {
            *entry = Some(ProviderObservation {
                provider_id: binding.provider_id,
                outcome: ProviderOutcome::NotStarted,
                duration: Duration::ZERO,
            });
        }
    }
    fn close_stage(&mut self, failure: Option<Failure>) {
        if let Some((stage, started)) = self.active_stage.take()
            && let Some(slot) = self.stages.iter_mut().find(|slot| slot.is_none())
        {
            *slot = Some(StageObservation {
                stage,
                duration: started.elapsed(),
                failure,
            });
        }
    }
    pub(crate) fn enter(&mut self, stage: Stage) {
        self.close_stage(None);
        self.active_stage = Some((stage, Instant::now()));
    }
    pub(crate) fn finish(&mut self, started: Instant, failure: Option<Failure>) {
        self.failure = failure;
        self.close_stage(self.failure);
        self.duration = started.elapsed();
    }
    pub(crate) fn provider(&mut self, index: usize, outcome: ProviderOutcome, duration: Duration) {
        if let Some(Some(entry)) = self.providers.get_mut(index) {
            entry.outcome = outcome;
            entry.duration = duration;
        }
    }
    pub(crate) fn pending(&self, index: usize) -> bool {
        self.providers
            .get(index)
            .and_then(Option::as_ref)
            .is_some_and(|p| p.outcome == ProviderOutcome::NotStarted)
    }
}
