//! Own the durable enrollment sequence and its explicit resume operation.
use crate::{Command, Result, create_private, read_array, read_bounded, read_secret, sync_parent};
use crate::{
    observation::{Operation, StorageState},
    providers::Providers,
};
use leelo_crypto::SecretSigningKey;
use leelo_engine::observation::OperationReport;
use leelo_envelope::Descriptor;
use leelo_policy::{Mode, NetworkNode, ProductionPolicy};
use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

// This private adapter keeps the same real filesystem operations in production
// and tests. Only the test implementation can inject failures or partial writes.
trait Persistence {
    fn create(&mut self, path: &Path) -> Result<File> {
        create_private(path)
    }
    fn write(&mut self, file: &mut File, bytes: &[u8]) -> Result<()> {
        file.write_all(bytes)?;
        Ok(())
    }
    fn sync_file(&mut self, file: &File) -> Result<()> {
        file.sync_all()?;
        Ok(())
    }
    fn sync_directory(&mut self, path: &Path) -> Result<()> {
        sync_parent(path)
    }
}
struct LocalFiles;
impl Persistence for LocalFiles {}

struct EnrollmentJournal<P> {
    files: P,
    log: File,
    pending_path: PathBuf,
}
impl<P: Persistence> EnrollmentJournal<P> {
    fn begin(
        mut files: P,
        path: &Path,
        descriptor: &Descriptor,
        observed: &mut Operation,
    ) -> Result<Self> {
        let log = files.create(path)?;
        let mut journal = Self {
            files,
            log,
            pending_path: path.with_extension("pending.leelo"),
        };
        journal.phase("preflight", descriptor)?;
        journal.files.sync_directory(path)?;
        observed.milestone("preflight_durable");
        Ok(journal)
    }

    fn record(&mut self, value: serde_json::Value) -> Result<()> {
        let mut bytes = serde_json::to_vec(&value)?;
        bytes.push(b'\n');
        self.files.write(&mut self.log, &bytes)
    }

    fn phase(&mut self, phase: &str, descriptor: &Descriptor) -> Result<()> {
        self.record(serde_json::json!({
            "phase":phase,
            "binding_id":hex::encode(descriptor.binding_id),
            "volume_uuid":uuid::Uuid::from_bytes(descriptor.volume_uuid).to_string(),
            "slot":descriptor.slot
        }))?;
        self.files.sync_file(&self.log)
    }

    fn commit(
        &mut self,
        descriptor: &Descriptor,
        envelope: &[u8],
        observed: &mut Operation,
        add: impl FnOnce() -> std::result::Result<i32, leelo_luks::Error>,
    ) -> Result<i32> {
        // The signed recovery bundle and its directory entry must be durable
        // before the storage adapter can be invoked. Files are never removed on error.
        observed.stage("pending_bundle");
        let mut pending = self.files.create(&self.pending_path)?;
        self.files.write(&mut pending, envelope)?;
        self.files.sync_file(&pending)?;
        self.files.sync_directory(&self.pending_path)?;
        observed.milestone("pending_bundle_durable");
        self.record(serde_json::json!({
            "phase":"pending-bundle-durable", "path":self.pending_path,
            "sha384":hex::encode(leelo_crypto::hash_context(envelope))
        }))?;
        self.phase("prepared-and-recovery-tested", descriptor)?;
        observed.milestone("prepared_and_recovery_tested");
        observed.stage("storage_commit");
        observed.storage(StorageState::PendingReconciliation);
        let token = add().map_err(|error| {
            if !matches!(error, leelo_luks::Error::PartialEnrollment { .. }) {
                observed.storage(StorageState::NotMutated);
            }
            EnrollmentError {
                message: format!(
                    "retain pending bundle {} and the existing recovery credential",
                    self.pending_path.display()
                ),
                source: Box::new(error),
            }
        })?;
        observed.committed();
        observed.stage("final_journal");
        self.phase("token-written-and-slot-tested", descriptor).map_err(|error| EnrollmentError {
            message: format!("enrollment committed to slot {} and token {token}, but journal update failed; retain {}", descriptor.slot, self.pending_path.display()),
            source: error,
        })?;
        observed.milestone("final_journal_durable");
        Ok(token)
    }
}

#[derive(Debug)]
struct EnrollmentError {
    message: String,
    source: Box<dyn std::error::Error>,
}
impl std::fmt::Display for EnrollmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.message, self.source)
    }
}
impl std::error::Error for EnrollmentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

fn attach_recovered(
    luks: &mut leelo_luks::Luks2,
    pending_bundle: &Path,
    slot: u8,
    credential: &[u8; 32],
    raw: &[u8],
    observed: &mut Operation,
) -> Result<i32> {
    observed.storage(StorageState::PendingReconciliation);
    observed.stage("storage_attach");
    let token = luks
        .attach_enrollment(slot, credential, raw)
        .map_err(|error| EnrollmentError {
            message: format!(
                "retain pending bundle {} and the existing recovery credential",
                pending_bundle.display()
            ),
            source: Box::new(error),
        })?;
    observed.committed();
    Ok(token)
}

pub(super) fn run(command: Command, observed: &mut Operation) -> Result<()> {
    match command {
        Command::Enroll {
            device,
            config,
            existing_key_file,
            signing_key,
            journal: journal_path,
            tcti,
            pcr_mask,
            threshold,
        } => {
            let mut providers = Providers::read(&config)?;
            observed.configure_providers(providers.provider_ids());
            let networks = providers.enrollment_bindings()?;
            let mut luks = leelo_luks::Luks2::open(&device, true)?;
            let old = read_secret(&existing_key_file, 8192)?;
            luks.test_credential(None, &old)?;
            let signing_seed = read_secret(&signing_key, 32)?;
            let seed: &[u8; 32] = signing_seed
                .as_slice()
                .try_into()
                .map_err(|_| "signing seed must be 32 bytes")?;
            let signer = SecretSigningKey::from_seed(seed);
            let mut tpm = leelo_tpm::Tpm2Provider::new(&tcti)?;
            let pcr_digest = tpm.pcr_digest(pcr_mask)?;
            let children = networks
                .iter()
                .map(|network| NetworkNode::Leaf {
                    id: network.node_id,
                    provider_id: network.provider_id,
                })
                .collect();
            let policy = ProductionPolicy::new(
                Mode::NetworkBound,
                0,
                NetworkNode::Threshold {
                    id: 1,
                    required: threshold,
                    children,
                },
            )?;
            let descriptor = Descriptor {
                binding_id: *leelo_crypto::random_bytes::<32>()?,
                volume_uuid: luks.uuid(),
                slot: luks.first_free_slot()?,
                generation: 1,
                policy,
                networks,
                tpm_pcr_mask: pcr_mask,
                tpm_pcr_digest: pcr_digest,
            };
            let mut journal =
                EnrollmentJournal::begin(LocalFiles, &journal_path, &descriptor, observed)?;
            observed.stage("prepare");
            let mut report = OperationReport::default();
            let prepared = leelo_engine::prepare_observed(
                descriptor.clone(),
                &signer,
                &mut providers.network,
                &mut tpm,
                &mut report,
            );
            observed.engine(&report);
            let prepared = prepared?;
            // Test the actual providers before any slot change.
            observed.stage("recovery_test");
            let recovered = leelo_engine::unlock_observed(
                &prepared.envelope,
                &signer.public_key(),
                &descriptor.volume_uuid,
                descriptor.slot,
                &mut providers.network,
                &mut tpm,
                &mut report,
            );
            observed.engine(&report);
            let recovered = recovered?;
            if *recovered.credential != *prepared.credential {
                return Err("enrollment round-trip mismatch".into());
            }

            let token = journal.commit(&descriptor, &prepared.envelope, observed, || {
                luks.add_enrollment(
                    descriptor.slot,
                    &old,
                    &prepared.credential,
                    &prepared.envelope,
                )
            })?;
            println!(
                "{}",
                serde_json::json!({
                    "enrolled":true,"token":token,"slot":descriptor.slot,"pending_bundle":journal.pending_path,
                    "production_boot_test_required":true,"old_slots_preserved":true
                })
            );
        }
        Command::ResumeEnrollment {
            device,
            config,
            trust_key,
            pending_bundle,
            tcti,
        } => {
            let trusted = read_array(&trust_key)?;
            let raw = read_bounded(&pending_bundle, leelo_envelope::MAX_ENVELOPE)?;
            let envelope = leelo_envelope::authenticate(&raw, &trusted)?;
            let slot = envelope.body().descriptor.slot;
            let mut luks = leelo_luks::Luks2::open(&device, true)?;
            let mut providers = Providers::read(&config)?;
            observed.configure_providers(providers.provider_ids());
            let mut tpm = leelo_tpm::Tpm2Provider::new(&tcti)?;
            observed.stage("recover");
            let mut report = OperationReport::default();
            let recovered = leelo_engine::unlock_observed(
                &raw,
                &trusted,
                &luks.uuid(),
                slot,
                &mut providers.network,
                &mut tpm,
                &mut report,
            );
            observed.engine(&report);
            let recovered = recovered?;
            let token = attach_recovered(
                &mut luks,
                &pending_bundle,
                slot,
                &recovered.credential,
                &raw,
                observed,
            )?;
            println!(
                "{}",
                serde_json::json!({
                    "enrolled":true,"resumed":true,"token":token,"slot":slot,"old_slots_preserved":true
                })
            );
        }
        _ => return Err("unexpected enrollment command".into()),
    }
    Ok(())
}

#[cfg(test)]
mod tests;
