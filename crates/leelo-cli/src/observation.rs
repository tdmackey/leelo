//! CLI observations contain only explicit classifications, never formatted errors or secrets.
use crate::Result;
use leelo_engine::observation::{
    Failure, MAX_PROVIDER_OBSERVATIONS, OperationReport, Phase, ProviderObservation,
    ProviderOutcome, Stage,
};
use leelo_telemetry::{Emitter, Event};
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StorageState {
    NotApplicable,
    NotMutated,
    PendingReconciliation,
    Committed,
    Unknown,
}
impl StorageState {
    fn name(self) -> &'static str {
        match self {
            Self::NotApplicable => "not_applicable",
            Self::NotMutated => "not_mutated",
            Self::PendingReconciliation => "pending_reconciliation",
            Self::Committed => "committed",
            Self::Unknown => "unknown",
        }
    }
}
pub(super) struct Operation {
    emitter: Emitter,
    operation: &'static str,
    started: Instant,
    stage_started: Instant,
    stage: &'static str,
    mode: &'static str,
    storage: StorageState,
    awaiting_boot_test: bool,
    degraded: bool,
    configured_providers: [Option<[u8; 32]>; MAX_PROVIDER_OBSERVATIONS],
}
impl Operation {
    pub fn new(operation: &'static str, emitter: Emitter) -> Self {
        let now = Instant::now();
        let value = Self {
            emitter,
            operation,
            started: now,
            stage_started: now,
            stage: "preflight",
            mode: "unknown",
            storage: match operation {
                "enroll" => StorageState::NotMutated,
                "resume" => StorageState::Unknown,
                _ => StorageState::NotApplicable,
            },
            awaiting_boot_test: false,
            degraded: false,
            configured_providers: [None; MAX_PROVIDER_OBSERVATIONS],
        };
        value.emit(
            "operation_started",
            "preflight",
            "started",
            "none",
            std::time::Duration::ZERO,
        );
        value
    }
    fn event(
        &self,
        event: &'static str,
        stage: &'static str,
        outcome: &'static str,
        reason: &'static str,
    ) -> Event {
        let mut event = Event::new("client", event, self.operation, stage, outcome, reason);
        event.mode = self.mode;
        event.storage_state = self.storage.name();
        event.awaiting_boot_test = self.awaiting_boot_test;
        event.degraded = self.degraded;
        event
    }
    fn emit(
        &self,
        event: &'static str,
        stage: &'static str,
        outcome: &'static str,
        reason: &'static str,
        duration: std::time::Duration,
    ) {
        let mut event = self.event(event, stage, outcome, reason);
        event.duration = duration;
        let _ = self.emitter.emit(event);
    }
    pub fn stage(&mut self, stage: &'static str) {
        self.emit(
            "phase_completed",
            self.stage,
            "success",
            "none",
            self.stage_started.elapsed(),
        );
        self.stage = stage;
        self.stage_started = Instant::now();
        self.emit(
            "phase_started",
            self.stage,
            "started",
            "none",
            std::time::Duration::ZERO,
        );
    }
    pub fn milestone(&self, stage: &'static str) {
        self.emit(
            "enrollment_state",
            stage,
            "observed",
            "none",
            self.started.elapsed(),
        );
    }
    pub fn storage(&mut self, storage: StorageState) {
        self.storage = storage;
    }
    pub fn committed(&mut self) {
        self.storage = StorageState::Committed;
        self.awaiting_boot_test = true;
        self.milestone("storage_committed");
    }
    pub fn configure_providers(&mut self, providers: impl Iterator<Item = [u8; 32]>) {
        self.configured_providers.fill(None);
        for (slot, provider) in self.configured_providers.iter_mut().zip(providers) {
            *slot = Some(provider);
        }
    }
    fn provider_event(&self, phase: &'static str, provider: &ProviderObservation) -> Event {
        let (outcome, reason) = match provider.outcome {
            ProviderOutcome::NotStarted => ("not_started", "none"),
            ProviderOutcome::Authenticated => ("authenticated", "none"),
            ProviderOutcome::Failed(reason) => ("failed", network_reason(reason)),
            ProviderOutcome::CanceledQuorum => ("canceled_quorum", "none"),
            ProviderOutcome::CanceledDeadline => ("canceled_deadline", "deadline"),
            ProviderOutcome::CanceledOperation => ("canceled_operation", "none"),
        };
        let mut event = self.event("provider_completed", phase, outcome, reason);
        // The policy's leaf order can differ from the trusted endpoint configuration.
        // Only a bounded configuration position leaves this process, never the identity.
        event.provider_index = self
            .configured_providers
            .iter()
            .position(|configured| *configured == Some(provider.provider_id))
            .map(|index| (index + 1) as u8);
        event.duration = provider.duration;
        event
    }
    pub fn engine(&mut self, report: &OperationReport) {
        self.mode = match report.mode {
            Some(leelo_policy::Mode::NetworkBound) => "network_bound",
            Some(leelo_policy::Mode::Attested) => "attested",
            None => "unknown",
        };
        self.degraded |= report.degraded();
        let phase = match report.phase {
            Phase::Prepare => "prepare",
            Phase::Recover => "recover",
        };
        for provider in report.providers() {
            let _ = self.emitter.emit(self.provider_event(phase, provider));
        }
        for stage in report.stages() {
            self.emit(
                "phase_completed",
                match stage.stage {
                    Stage::Validate => "validate",
                    Stage::TpmSeal => "tpm_seal",
                    Stage::ShareGeneration => "share_generation",
                    Stage::Network => "network",
                    Stage::TpmUnseal => "tpm_unseal",
                    Stage::PreparePayload => "prepare_payload",
                    Stage::AuthenticatePayload => "authenticate_payload",
                },
                if stage.failure.is_some() {
                    "failure"
                } else {
                    "success"
                },
                stage.failure.map_or("none", engine_reason),
                stage.duration,
            );
        }
    }
    pub fn finish(&self, result: &Result<()>) {
        let event = self.completion_event(result);
        self.emit(
            "phase_completed",
            self.stage,
            event.outcome,
            event.reason,
            self.stage_started.elapsed(),
        );
        let _ = self.emitter.emit(event);
    }
    fn completion_event(&self, result: &Result<()>) -> Event {
        let (reason, native_code) = result
            .as_ref()
            .err()
            .map_or(("none", None), |error| classify(error.as_ref()));
        let mut event = self.event(
            "operation_completed",
            self.stage,
            if result.is_ok() { "success" } else { "failure" },
            reason,
        );
        event.duration = self.started.elapsed();
        event.native_code = native_code;
        event
    }
}
fn engine_reason(failure: Failure) -> &'static str {
    match failure {
        Failure::Envelope => "envelope",
        Failure::Cryptography => "cryptography",
        Failure::Sharing => "sharing",
        Failure::Policy => "policy",
        Failure::Tpm => "tpm",
        Failure::InsufficientFactors => "insufficient_factors",
        Failure::Deadline => "deadline",
        Failure::InconsistentShares => "inconsistent_shares",
        Failure::TargetMismatch => "target_mismatch",
        Failure::UnsupportedMode => "unsupported_mode",
        Failure::Runtime => "runtime",
    }
}
fn network_reason(failure: leelo_engine::NetworkFailure) -> &'static str {
    match failure {
        leelo_engine::NetworkFailure::Configuration => "configuration",
        leelo_engine::NetworkFailure::Unavailable => "unavailable",
        leelo_engine::NetworkFailure::Timeout => "timeout",
        leelo_engine::NetworkFailure::RemoteRejected => "remote_rejected",
        leelo_engine::NetworkFailure::InvalidResponse => "invalid_response",
        leelo_engine::NetworkFailure::InvalidProof => "invalid_proof",
        leelo_engine::NetworkFailure::Authentication => "authentication",
        leelo_engine::NetworkFailure::Cryptography => "cryptography",
    }
}
fn classify(error: &(dyn std::error::Error + 'static)) -> (&'static str, Option<i64>) {
    if let Some(error) = error.downcast_ref::<leelo_engine::Error>() {
        return (engine_reason(Failure::from_error(error)), None);
    }
    if error.is::<leelo_envelope::Error>() {
        return ("envelope", None);
    }
    if error.is::<std::io::Error>() {
        return ("io", None);
    }
    if let Some(error) = error.downcast_ref::<leelo_luks::Error>() {
        return match error {
            leelo_luks::Error::Cryptsetup { code, .. } => ("cryptsetup", Some(i64::from(*code))),
            leelo_luks::Error::PartialEnrollment { .. } => ("partial_enrollment", None),
            leelo_luks::Error::WriterBusy => ("writer_busy", None),
            leelo_luks::Error::MetadataChanged => ("metadata_changed", None),
            leelo_luks::Error::OccupiedSlot => ("occupied_slot", None),
            leelo_luks::Error::NoTokenSpace | leelo_luks::Error::MetadataSpace { .. } => {
                ("metadata_capacity", None)
            }
            leelo_luks::Error::InvalidToken => ("invalid_token", None),
            leelo_luks::Error::WrongVolume => ("wrong_volume", None),
            _ => ("storage", None),
        };
    }
    if let Some(source) = error.source() {
        return classify(source);
    }
    ("configuration_or_operation", None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_labels_follow_trusted_configuration_not_signed_policy_order() {
        let mut observed = Operation::new("check", Emitter::new(None));
        observed.configure_providers([[1; 32], [2; 32]].into_iter());
        let second = ProviderObservation {
            provider_id: [2; 32],
            outcome: ProviderOutcome::Authenticated,
            duration: std::time::Duration::ZERO,
        };
        let first = ProviderObservation {
            provider_id: [1; 32],
            ..second
        };
        assert_eq!(
            observed.provider_event("recover", &second).provider_index,
            Some(2)
        );
        assert_eq!(
            observed.provider_event("recover", &first).provider_index,
            Some(1)
        );
        let missing = ProviderObservation {
            provider_id: [3; 32],
            ..second
        };
        assert_eq!(
            observed.provider_event("recover", &missing).provider_index,
            None
        );
    }

    #[test]
    fn failed_activation_after_recovery_is_not_an_unlock_success() {
        let mut observed = Operation::new("activate", Emitter::new(None));
        observed.engine(&OperationReport::default());
        observed.stage("activate");
        let result: Result<()> = Err(leelo_luks::Error::Cryptsetup {
            operation: "private arbitrary text",
            code: -22,
        }
        .into());
        let event = observed.completion_event(&result);
        assert_eq!(
            (event.operation, event.stage, event.outcome, event.reason),
            ("activate", "activate", "failure", "cryptsetup")
        );
        assert_eq!(event.native_code, Some(-22));
        assert_eq!(event.storage_state, "not_applicable");
        observed.finish(&result);
    }

    #[test]
    fn failed_final_journal_preserves_committed_and_awaiting_boot_test() {
        let mut observed = Operation::new("enroll", Emitter::new(None));
        observed.storage(StorageState::PendingReconciliation);
        observed.committed();
        observed.stage("final_journal");
        let result: Result<()> = Err(std::io::Error::other("private path and diagnostic").into());
        let event = observed.completion_event(&result);
        assert_eq!(event.outcome, "failure");
        assert_eq!(event.reason, "io");
        assert_eq!(event.storage_state, "committed");
        assert!(event.awaiting_boot_test);
        let resume = Operation::new("resume", Emitter::new(None));
        assert_eq!(resume.completion_event(&result).storage_state, "unknown");
    }

    #[cfg(unix)]
    struct Sink {
        path: std::path::PathBuf,
        socket: std::os::unix::net::UnixDatagram,
    }
    #[cfg(unix)]
    impl Sink {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "leelo-events-{}-{}.sock",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            let socket = std::os::unix::net::UnixDatagram::bind(&path).unwrap();
            socket.set_nonblocking(true).unwrap();
            Self { path, socket }
        }
        fn records(&self) -> Vec<leelo_telemetry::Record> {
            let mut records = Vec::new();
            let mut bytes = [0; leelo_telemetry::MAX_EVENT_BYTES];
            while let Ok(length) = self.socket.recv(&mut bytes) {
                records.push(leelo_telemetry::Record::decode(&bytes[..length]).unwrap());
            }
            records
        }
    }
    #[cfg(unix)]
    impl Drop for Sink {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    #[cfg(unix)]
    #[test]
    fn terminal_datagram_follows_requested_action_and_contains_only_safe_error_fields() {
        let sink = Sink::new();
        let mut observed = Operation::new("check", Emitter::new(Some(&sink.path)));
        observed.stage("check");
        assert!(
            !sink
                .records()
                .iter()
                .any(|event| event.event == "operation_completed")
        );
        let result: Result<()> = Err(leelo_luks::Error::Cryptsetup {
            operation: "do-not-export",
            code: -5,
        }
        .into());
        observed.finish(&result);
        let records = sink.records();
        let terminal = records
            .iter()
            .filter(|event| event.event == "operation_completed")
            .collect::<Vec<_>>();
        assert_eq!(terminal.len(), 1);
        assert_eq!(terminal[0].outcome, "failure");
        assert_eq!(terminal[0].native_code, Some(-5));
        assert!(
            !serde_json::to_string(&records)
                .unwrap()
                .contains("do-not-export")
        );
    }

    #[cfg(unix)]
    #[test]
    fn full_or_absent_collector_cannot_change_success_or_block_command_completion() {
        let sink = Sink::new();
        let mut observed = Operation::new("activate", Emitter::new(Some(&sink.path)));
        let started = Instant::now();
        for _ in 0..512 {
            observed.stage("activate");
        }
        observed.finish(&Ok(()));
        assert!(observed.emitter.dropped() > 0);
        assert_eq!(observed.completion_event(&Ok(())).outcome, "success");
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        let path = sink.path.clone();
        drop(sink);
        let observed = Operation::new("check", Emitter::new(Some(&path)));
        observed.finish(&Ok(()));
        assert!(observed.emitter.dropped() > 0);
    }
}
