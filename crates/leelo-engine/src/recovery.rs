//! One private operation owns the envelope, deadline, factors, and final credential.
use super::{
    Error, NetworkProvider, ProviderFailure, TpmAuthorization, TpmProvider, UnlockResult,
    UnsealedSeed, check_deadline, derive, policy_error, recover_network_observed, runtime,
};
use crate::observation::{OperationReport, Stage};
use crate::release::ReleaseState;
use leelo_envelope::AuthenticatedEnvelope;
use leelo_policy::{Mode, PolicySession};
use leelo_sss::Share;
use std::time::Instant;
use zeroize::Zeroizing;

// These values have no public constructor, serializer, Clone, or Debug.
// Each factor is accepted only after its own authentication succeeds.
struct NetworkEvidence {
    context: [u8; 48],
    share: Zeroizing<[u8; 32]>,
    available: Vec<u8>,
    diagnostics: Vec<ProviderFailure>,
}

struct TpmEvidence {
    context: [u8; 48],
    share: Zeroizing<[u8; 32]>,
    live: bool,
}

impl TpmEvidence {
    fn authenticate(
        unsealed: UnsealedSeed,
        envelope: &AuthenticatedEnvelope,
    ) -> Result<Self, Error> {
        let context = *envelope.context();
        let descriptor = &envelope.body().descriptor;
        let live = matches!(
            unsealed.authorization,
            TpmAuthorization::FreshSessionAuthorization
        );
        if descriptor.policy.mode() == Mode::Attested && !live {
            return Err(Error::UnsupportedMode);
        }
        let leaf_context = leelo_envelope::leaf_context(&context, descriptor.policy.tpm_node_id());
        let key = derive(unsealed.seed.as_ref(), &leaf_context, b"leelo/v1/tpm-wrap")?;
        let share = leelo_crypto::open_key(&key, &envelope.body().leaves[0].value, &leaf_context)
            .map_err(|_| Error::Crypto)?;
        Ok(Self {
            context,
            share,
            live,
        })
    }
}

struct PayloadEvidence {
    context: [u8; 48],
    credential: Zeroizing<[u8; 32]>,
}

impl PayloadEvidence {
    fn authenticate(
        root: Zeroizing<[u8; 32]>,
        envelope: &AuthenticatedEnvelope,
    ) -> Result<Self, Error> {
        let context = *envelope.context();
        let key = derive(root.as_ref(), &context, b"leelo/v1/luks-slot")?;
        let credential = leelo_crypto::open_key(&key, &envelope.body().payload, &context)
            .map_err(|_| Error::Crypto)?;
        Ok(Self {
            context,
            credential,
        })
    }
}

pub(super) struct UnlockOperation {
    envelope: AuthenticatedEnvelope,
    deadline: Instant,
    policy: PolicySession,
    release: ReleaseState,
}

impl UnlockOperation {
    pub(super) fn begin(
        raw: &[u8],
        signer: &[u8; 32],
        volume: &[u8; 16],
        slot: u8,
        tpm: &impl TpmProvider,
        deadline: Instant,
        report: &mut OperationReport,
    ) -> Result<Self, Error> {
        let envelope = leelo_envelope::authenticate(raw, signer)?;
        let descriptor = &envelope.body().descriptor;
        report.configure(descriptor.policy.mode(), &descriptor.networks);
        if &descriptor.volume_uuid != volume || descriptor.slot != slot {
            return Err(Error::TargetMismatch);
        }
        if !tpm.supports_mode(descriptor.policy.mode()) {
            return Err(Error::UnsupportedMode);
        }
        check_deadline(deadline)?;
        let mut policy = PolicySession::new(&descriptor.policy);
        policy.authenticate_envelope().map_err(policy_error)?;
        let release = ReleaseState::new(
            *envelope.context(),
            descriptor.policy.mode() == Mode::Attested,
        );
        Ok(Self {
            envelope,
            deadline,
            policy,
            release,
        })
    }

    pub(super) fn run(
        mut self,
        net: &impl NetworkProvider,
        tpm: &mut impl TpmProvider,
        report: &mut OperationReport,
    ) -> Result<UnlockResult, Error> {
        let executor = runtime()?;
        report.enter(Stage::Network);
        let (share, diagnostics, available) = executor.block_on(recover_network_observed(
            &self.envelope,
            net,
            self.deadline,
            report,
        ))?;
        drop(executor);
        let network = NetworkEvidence {
            context: *self.envelope.context(),
            share,
            diagnostics,
            available,
        };
        for id in &network.available {
            self.policy.accept_network(*id).map_err(policy_error)?;
        }
        if !self.release.network(&network.context) {
            return Err(Error::Policy);
        }
        check_deadline(self.deadline)?;
        report.enter(Stage::TpmUnseal);
        let unsealed = tpm.unseal(&self.envelope)?;
        check_deadline(self.deadline)?;
        report.enter(Stage::AuthenticatePayload);
        let tpm = TpmEvidence::authenticate(unsealed, &self.envelope)?;
        if tpm.live {
            self.policy
                .confirm_live_authorization()
                .map_err(policy_error)?;
        }
        self.policy.confirm_tpm().map_err(policy_error)?;
        if !self.release.tpm(&tpm.context, tpm.live) {
            return Err(Error::Policy);
        }
        let shares = [
            Share::from_parts(1, tpm.share).map_err(|_| Error::Sharing)?,
            Share::from_parts(2, network.share).map_err(|_| Error::Sharing)?,
        ];
        let root = leelo_sss::reconstruct(2, &shares).map_err(|_| Error::Sharing)?;
        let payload = PayloadEvidence::authenticate(root, &self.envelope)?;
        self.policy.authenticate_root().map_err(policy_error)?;
        if !self.release.payload(&payload.context) {
            return Err(Error::Policy);
        }
        check_deadline(self.deadline)?;
        self.policy.release().map_err(policy_error)?;
        // The clock observation is outside the proof. The verified gate checks its result.
        if !self
            .release
            .release(&payload.context, Instant::now() < self.deadline)
        {
            check_deadline(self.deadline)?;
            return Err(Error::Policy);
        }
        Ok(UnlockResult {
            credential: payload.credential,
            diagnostics: network.diagnostics,
        })
    }
}
