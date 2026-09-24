use super::*;
use leelo_crypto::SecretServer;
use leelo_policy::{NetworkNode, ProductionPolicy};
use std::cell::Cell;

#[derive(Clone, Copy)]
enum Action {
    Ready,
    Wait,
    Fail,
    InvalidProof,
}

struct Network {
    keys: Vec<SecretServer>,
    actions: Vec<Action>,
    active: Cell<usize>,
    peak: Cell<usize>,
    started: Cell<usize>,
}
struct Active<'a>(&'a Cell<usize>);
impl Drop for Active<'_> {
    fn drop(&mut self) {
        self.0.set(self.0.get() - 1);
    }
}
impl NetworkProvider for Network {
    async fn evaluate(
        &self,
        binding: &NetworkBinding,
        point: &[u8; 49],
        _: Instant,
    ) -> Result<Evaluation, NetworkFailure> {
        self.started.set(self.started.get() + 1);
        self.active.set(self.active.get() + 1);
        self.peak.set(self.peak.get().max(self.active.get()));
        let _active = Active(&self.active);
        let index = usize::from(binding.node_id - 2);
        match self.actions[index] {
            Action::Wait => std::future::pending::<()>().await,
            Action::Fail => return Err(NetworkFailure::Unavailable),
            Action::Ready => tokio::time::sleep(Duration::from_millis(1)).await,
            Action::InvalidProof => {
                return self.keys[(index + 1) % self.keys.len()]
                    .evaluate(point)
                    .map_err(|_| NetworkFailure::Cryptography);
            }
        }
        self.keys[index]
            .evaluate(point)
            .map_err(|_| NetworkFailure::Cryptography)
    }
}
struct Tpm;
impl TpmProvider for Tpm {
    fn supports_mode(&self, mode: Mode) -> bool {
        mode == Mode::NetworkBound
    }
    fn seal(&mut self, _: &Descriptor, _: &[u8; 32]) -> Result<TpmBlob, Error> {
        // This fixture tests only network recovery. No test calls TPM unseal.
        Ok(TpmBlob {
            public: vec![1],
            private: vec![2],
            name: vec![3],
            parent_name: vec![4],
        })
    }
    fn unseal(&mut self, _: &AuthenticatedEnvelope) -> Result<UnsealedSeed, Error> {
        panic!("network-phase test must not unseal")
    }
}
fn fixture(count: u8, required: u8) -> (AuthenticatedEnvelope, Network) {
    let mut network = Network {
        keys: (0..count)
            .map(|_| SecretServer::generate().unwrap())
            .collect(),
        actions: vec![Action::Ready; usize::from(count)],
        active: Cell::new(0),
        peak: Cell::new(0),
        started: Cell::new(0),
    };
    let bindings: Vec<_> = network
        .keys
        .iter()
        .enumerate()
        .map(|(i, key)| {
            let public_key = *key.public_key().as_bytes();
            NetworkBinding {
                node_id: i as u8 + 2,
                provider_id: [i as u8 + 2; 32],
                key_id: leelo_protocol::key_id(&public_key),
                public_key,
                input_seed: [7; 32],
            }
        })
        .collect();
    let children = bindings
        .iter()
        .map(|binding| NetworkNode::Leaf {
            id: binding.node_id,
            provider_id: binding.provider_id,
        })
        .collect();
    let descriptor = Descriptor {
        binding_id: [1; 32],
        volume_uuid: [2; 16],
        slot: 1,
        generation: 1,
        policy: ProductionPolicy::new(
            Mode::NetworkBound,
            0,
            NetworkNode::Threshold {
                id: 1,
                required,
                children,
            },
        )
        .unwrap(),
        networks: bindings,
        tpm_pcr_mask: 1 << 7,
        tpm_pcr_digest: [3; 32],
    };
    let signer = SecretSigningKey::from_seed(&[8; 32]);
    let prepared = prepare(descriptor, &signer, &mut network, &mut Tpm).unwrap();
    let envelope = leelo_envelope::authenticate(&prepared.envelope, &signer.public_key()).unwrap();
    network.started.set(0);
    network.peak.set(0);
    (envelope, network)
}

#[test]
fn healthy_quorum_cancels_hung_factors_and_limits_concurrency() {
    let (envelope, mut network) = fixture(6, 2);
    network.actions = vec![
        Action::Wait,
        Action::Ready,
        Action::Ready,
        Action::Wait,
        Action::Wait,
        Action::Wait,
    ];
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut report = configured_report(&envelope);
    let result = runtime()
        .unwrap()
        .block_on(recover_network_observed(
            &envelope,
            &network,
            deadline,
            &mut report,
        ))
        .unwrap();
    assert_eq!(result.2.len(), 2);
    assert_eq!(network.peak.get(), MAX_NETWORK_OPERATIONS);
    assert!((MAX_NETWORK_OPERATIONS..=MAX_NETWORK_OPERATIONS + 1).contains(&network.started.get()));
    assert_eq!(network.active.get(), 0);
    let outcomes: Vec<_> = report.providers().map(|p| p.outcome).collect();
    assert_eq!(
        outcomes
            .iter()
            .filter(|&&p| p == ProviderOutcome::Authenticated)
            .count(),
        2
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|&&p| p == ProviderOutcome::CanceledQuorum)
            .count(),
        network.started.get() - 2
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|&&p| p == ProviderOutcome::NotStarted)
            .count(),
        6 - network.started.get()
    );
    assert!(!report.degraded());
}

#[test]
fn total_deadline_cancels_all_pending_factors() {
    let (envelope, mut network) = fixture(3, 2);
    network.actions.fill(Action::Wait);
    let started = Instant::now();
    let result = runtime().unwrap().block_on(recover_network(
        &envelope,
        &network,
        started + Duration::from_millis(20),
    ));
    match result {
        Err(Error::DeadlineExceeded { failures }) => {
            assert_eq!(failures.len(), 3);
            assert!(
                failures
                    .iter()
                    .all(|failure| failure.kind == NetworkFailure::Timeout)
            );
        }
        _ => panic!("deadline must report each pending provider"),
    }
    assert_eq!(network.active.get(), 0);
    assert!(started.elapsed() < Duration::from_secs(1));
}

fn configured_report(envelope: &AuthenticatedEnvelope) -> OperationReport {
    let mut report = OperationReport::default();
    report.configure(
        envelope.body().descriptor.policy.mode(),
        &envelope.body().descriptor.networks,
    );
    report
}

#[test]
fn deadline_observations_distinguish_canceled_from_unstarted() {
    let (envelope, mut network) = fixture(6, 2);
    network.actions.fill(Action::Wait);
    let mut report = configured_report(&envelope);
    let result = runtime().unwrap().block_on(recover_network_observed(
        &envelope,
        &network,
        Instant::now() + Duration::from_millis(20),
        &mut report,
    ));
    assert!(matches!(result, Err(Error::DeadlineExceeded { .. })));
    assert_eq!(network.active.get(), 0);
    assert_eq!(
        report
            .providers()
            .filter(|p| p.outcome == ProviderOutcome::CanceledDeadline)
            .count(),
        4
    );
    assert_eq!(
        report
            .providers()
            .filter(|p| p.outcome == ProviderOutcome::NotStarted)
            .count(),
        2
    );
    assert!(!report.degraded());
}

#[test]
fn proof_failure_is_not_provider_success_and_degraded_quorum_is_preserved() {
    let (envelope, mut network) = fixture(2, 1);
    network.actions[0] = Action::InvalidProof;
    let mut report = configured_report(&envelope);
    let result = runtime().unwrap().block_on(recover_network_observed(
        &envelope,
        &network,
        Instant::now() + Duration::from_secs(2),
        &mut report,
    ));
    assert!(result.is_ok());
    assert_eq!(
        report.providers().next().unwrap().outcome,
        ProviderOutcome::Failed(NetworkFailure::InvalidProof)
    );
    assert!(report.degraded());
}

#[test]
fn valid_proof_is_not_success_until_share_authentication() {
    let (envelope, network) = fixture(2, 2);
    let mut body = envelope.body().clone();
    body.leaves[1].value.ciphertext[0] ^= 1;
    let signer = SecretSigningKey::from_seed(&[8; 32]);
    let raw = leelo_envelope::sign(&body, &signer).unwrap();
    let envelope = leelo_envelope::authenticate(&raw, &signer.public_key()).unwrap();
    let mut report = configured_report(&envelope);
    let result = runtime().unwrap().block_on(recover_network_observed(
        &envelope,
        &network,
        Instant::now() + Duration::from_secs(2),
        &mut report,
    ));
    assert!(matches!(result, Err(Error::InsufficientFactors { .. })));
    assert_eq!(
        report.providers().next().unwrap().outcome,
        ProviderOutcome::Failed(NetworkFailure::Authentication)
    );
}

#[test]
fn preparation_failure_keeps_unattempted_leaves_and_report_resets_before_authentication() {
    let (envelope, mut network) = fixture(3, 1);
    network.actions[0] = Action::Fail;
    let signer = SecretSigningKey::from_seed(&[8; 32]);
    let mut report = OperationReport::default();
    let result = prepare_observed(
        envelope.body().descriptor.clone(),
        &signer,
        &mut network,
        &mut Tpm,
        &mut report,
    );
    assert!(result.is_err());
    assert_eq!(report.phase, Phase::Prepare);
    assert_eq!(
        report
            .providers()
            .filter(|p| p.outcome == ProviderOutcome::NotStarted)
            .count(),
        2
    );
    assert_eq!(report.stages().last().unwrap().stage, Stage::Network);
    assert!(report.stages().last().unwrap().failure.is_some());
    let result = unlock_observed(
        b"unauthenticated",
        &signer.public_key(),
        &[0; 16],
        0,
        &mut network,
        &mut Tpm,
        &mut report,
    );
    assert!(result.is_err());
    assert_eq!(report.providers().count(), 0);
    assert_eq!(report.mode, None);
    assert_eq!(report.stages().count(), 1);
    assert_eq!(report.stages().next().unwrap().stage, Stage::Validate);
}

#[test]
fn preparation_reports_building_payload_separately_from_authentication_and_tpm_work() {
    let (envelope, mut network) = fixture(2, 1);
    let signer = SecretSigningKey::from_seed(&[8; 32]);
    let mut report = OperationReport::default();
    prepare_observed(
        envelope.body().descriptor.clone(),
        &signer,
        &mut network,
        &mut Tpm,
        &mut report,
    )
    .unwrap();
    let stages: Vec<_> = report
        .stages()
        .map(|observation| observation.stage)
        .collect();
    assert_eq!(
        stages,
        [
            Stage::Validate,
            Stage::TpmSeal,
            Stage::ShareGeneration,
            Stage::Network,
            Stage::PreparePayload
        ]
    );
    assert!(!stages.contains(&Stage::AuthenticatePayload));
}

#[test]
fn degraded_quorum_preserves_safe_provider_diagnostics() {
    let (envelope, mut network) = fixture(2, 1);
    network.actions[0] = Action::Fail;
    let (_, failures, _) = runtime()
        .unwrap()
        .block_on(recover_network(
            &envelope,
            &network,
            Instant::now() + Duration::from_secs(2),
        ))
        .unwrap();
    assert_eq!(
        failures,
        vec![ProviderFailure {
            provider_id: [2; 32],
            kind: NetworkFailure::Unavailable
        }]
    );
    network.actions[1] = Action::Fail;
    let result = runtime().unwrap().block_on(recover_network(
        &envelope,
        &network,
        Instant::now() + Duration::from_secs(2),
    ));
    match result {
        Err(Error::InsufficientFactors { failures }) => assert_eq!(failures.len(), 2),
        _ => panic!("unavailable factors must retain diagnostics"),
    }
}
