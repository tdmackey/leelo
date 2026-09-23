use super::*;
use leelo_telemetry::{Emitter, Record};
use std::{
    cell::RefCell,
    fs::{self, DirBuilder},
    io,
    os::unix::{
        fs::{DirBuilderExt, PermissionsExt},
        net::UnixDatagram,
    },
    process::Command as ProcessCommand,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "leelo-enrollment-{}-{nonce}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        DirBuilder::new().mode(0o700).create(&root).unwrap();
        Self { root }
    }
    fn journal(&self) -> PathBuf {
        self.root.join("enrollment.jsonl")
    }
    fn pending(&self) -> PathBuf {
        self.journal().with_extension("pending.leelo")
    }
    fn descriptor(&self) -> Descriptor {
        Descriptor {
            binding_id: [7; 32],
            volume_uuid: [8; 16],
            slot: 1,
            generation: 1,
            policy: ProductionPolicy::new(
                Mode::NetworkBound,
                0,
                NetworkNode::Leaf {
                    id: 2,
                    provider_id: [2; 32],
                },
            )
            .unwrap(),
            networks: vec![],
            tpm_pcr_mask: 1 << 7,
            tpm_pcr_digest: [9; 32],
        }
    }
    fn assert_private(&self, path: &Path) {
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    fn command(&self, args: &[&str]) -> std::process::Output {
        // All cryptsetup callers below name this constructor's regular image.
        let image = self.root.join("volume.luks");
        assert!(fs::symlink_metadata(&image).unwrap().file_type().is_file());
        assert_eq!(
            image.canonicalize().unwrap().parent(),
            Some(self.root.as_path())
        );
        let output = ProcessCommand::new("cryptsetup")
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "cryptsetup failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }
    fn luks(&self) -> leelo_luks::Luks2 {
        let image = self.root.join("volume.luks");
        create_private(&image)
            .unwrap()
            .set_len(64 * 1024 * 1024)
            .unwrap();
        let old_path = self.root.join("old.key");
        create_private(&old_path).unwrap().write_all(&OLD).unwrap();
        self.command(&[
            "luksFormat",
            "--batch-mode",
            "--type",
            "luks2",
            "--pbkdf",
            "pbkdf2",
            "--pbkdf-force-iterations",
            "1000",
            "--key-file",
            old_path.to_str().unwrap(),
            image.to_str().unwrap(),
        ]);
        leelo_luks::Luks2::open(&image, true).unwrap()
    }
    fn metadata(&self) -> serde_json::Value {
        let image = self.root.join("volume.luks");
        serde_json::from_slice(
            &self
                .command(&["luksDump", "--dump-json-metadata", image.to_str().unwrap()])
                .stdout,
        )
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Delete only this constructor's isolated directory, never a user path.
        if self.root.parent() == Some(std::env::temp_dir().as_path())
            && self
                .root
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("leelo-enrollment-"))
            && fs::symlink_metadata(&self.root).is_ok_and(|entry| entry.file_type().is_dir())
        {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

// The record collector runs concurrently so a full datagram queue cannot hide the
// final observation. Tests assert observations emitted by the real orchestration.
fn observed(root: &Path, operation: &'static str) -> (Operation, thread::JoinHandle<Vec<Record>>) {
    let path = root.join(format!("{operation}.sock"));
    let socket = UnixDatagram::bind(&path).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    let reader = thread::spawn(move || {
        let mut result = Vec::new();
        let mut buffer = [0; leelo_telemetry::MAX_EVENT_BYTES];
        loop {
            let length = socket
                .recv(&mut buffer)
                .expect("missing terminal telemetry event");
            let event = Record::decode(&buffer[..length]).unwrap();
            let terminal = event.event == "operation_completed";
            result.push(event);
            if terminal {
                return result;
            }
        }
    });
    (Operation::new(operation, Emitter::new(Some(&path))), reader)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Create,
    Write,
    FileSync,
    DirectorySync,
}
const STEPS: [Step; 13] = [
    Step::Create,
    Step::Write,
    Step::FileSync,
    Step::DirectorySync,
    Step::Create,
    Step::Write,
    Step::FileSync,
    Step::DirectorySync,
    Step::Write,
    Step::Write,
    Step::FileSync,
    Step::Write,
    Step::FileSync,
];
#[derive(Clone, Copy, Debug)]
enum Failure {
    Before,
    PartialWrite,
    After,
}
struct FaultFiles {
    fail: Option<(usize, Failure)>,
    calls: Rc<RefCell<Vec<Step>>>,
    real: LocalFiles,
}
impl FaultFiles {
    fn new(fail: Option<(usize, Failure)>) -> Self {
        Self {
            fail,
            calls: Rc::default(),
            real: LocalFiles,
        }
    }
    fn step(&mut self, step: Step) -> Option<Failure> {
        let position = self.calls.borrow().len();
        self.calls.borrow_mut().push(step);
        self.fail
            .filter(|(index, _)| *index == position)
            .map(|(_, failure)| failure)
    }
    fn error<T>() -> Result<T> {
        Err(io::Error::other("injected persistence failure").into())
    }
}
impl Persistence for FaultFiles {
    fn create(&mut self, path: &Path) -> Result<File> {
        if self.step(Step::Create).is_some() {
            return Self::error();
        }
        self.real.create(path)
    }
    fn write(&mut self, file: &mut File, bytes: &[u8]) -> Result<()> {
        match self.step(Step::Write) {
            Some(Failure::Before) => Self::error(),
            Some(Failure::PartialWrite) => {
                self.real.write(file, &bytes[..bytes.len() / 2])?;
                Self::error()
            }
            Some(Failure::After) => {
                self.real.write(file, bytes)?;
                Self::error()
            }
            None => self.real.write(file, bytes),
        }
    }
    fn sync_file(&mut self, file: &File) -> Result<()> {
        match self.step(Step::FileSync) {
            Some(Failure::After) => {
                self.real.sync_file(file)?;
                Self::error()
            }
            Some(_) => Self::error(),
            None => self.real.sync_file(file),
        }
    }
    fn sync_directory(&mut self, path: &Path) -> Result<()> {
        match self.step(Step::DirectorySync) {
            Some(Failure::After) => {
                self.real.sync_directory(path)?;
                Self::error()
            }
            Some(_) => Self::error(),
            None => self.real.sync_directory(path),
        }
    }
}

#[test]
fn every_persistence_failure_before_commit_keeps_storage_untouched() {
    let bundle = [0x83; 1024];
    for (boundary, step) in STEPS.iter().enumerate().take(11) {
        let modes = if *step == Step::Write {
            vec![Failure::Before, Failure::PartialWrite]
        } else if matches!(step, Step::FileSync | Step::DirectorySync) {
            vec![Failure::Before, Failure::After]
        } else {
            vec![Failure::Before]
        };
        for failure in modes {
            let fixture = Fixture::new();
            let descriptor = fixture.descriptor();
            let (mut observation, records) = observed(&fixture.root, "enroll");
            let files = FaultFiles::new(Some((boundary, failure)));
            let calls = files.calls.clone();
            let marker = fixture.root.join("storage-mutated");
            let result: Result<()> =
                EnrollmentJournal::begin(files, &fixture.journal(), &descriptor, &mut observation)
                    .and_then(|mut journal| {
                        journal.commit(&descriptor, &bundle, &mut observation, || {
                            fs::write(&marker, b"storage was touched").unwrap();
                            Ok(0)
                        })
                    })
                    .map(|_| ());
            assert!(result.is_err(), "{boundary} {failure:?}");
            assert!(
                !marker.exists(),
                "storage invoked at {boundary} {failure:?}"
            );
            assert_eq!(calls.borrow().as_slice(), &STEPS[..=boundary]);
            observation.finish(&result);
            let records = records.join().unwrap();
            let terminal = records.last().unwrap();
            assert_eq!(terminal.storage_state, "not_mutated");
            assert_eq!(terminal.reason, "io");
            assert!(!records.iter().any(|event| event.stage == "storage_commit"));
            if boundary >= 6 {
                assert_eq!(fs::read(fixture.pending()).unwrap(), bundle);
                fixture.assert_private(&fixture.pending());
            }
            if boundary >= 8 {
                assert!(
                    records
                        .iter()
                        .any(|event| event.stage == "pending_bundle_durable")
                );
            } else {
                assert!(
                    !records
                        .iter()
                        .any(|event| event.stage == "pending_bundle_durable")
                );
            }
            if boundary == 5 {
                let persisted = fs::read(fixture.pending()).unwrap();
                match failure {
                    Failure::Before => assert!(persisted.is_empty()),
                    Failure::PartialWrite => assert_eq!(persisted, bundle[..bundle.len() / 2]),
                    Failure::After => unreachable!(),
                }
            }
            // Existing or partial files remain available for diagnosis; retry must
            // use a new journal path rather than overwrite an ambiguous artifact.
            if boundary > 0 {
                assert!(fixture.journal().exists());
            }
        }
    }
}

#[test]
fn successful_commit_occurs_after_both_durable_stages_and_retains_artifacts() {
    let fixture = Fixture::new();
    let descriptor = fixture.descriptor();
    let files = FaultFiles::new(None);
    let calls = files.calls.clone();
    let (mut observation, records) = observed(&fixture.root, "enroll");
    let mut journal =
        EnrollmentJournal::begin(files, &fixture.journal(), &descriptor, &mut observation).unwrap();
    let token = journal
        .commit(
            &descriptor,
            b"signed-encrypted-bundle",
            &mut observation,
            || {
                assert_eq!(calls.borrow().as_slice(), &STEPS[..11]);
                assert_eq!(
                    fs::read(fixture.pending()).unwrap(),
                    b"signed-encrypted-bundle"
                );
                Ok(12)
            },
        )
        .unwrap();
    assert_eq!(token, 12);
    assert_eq!(calls.borrow().as_slice(), &STEPS);
    drop(journal);
    fixture.assert_private(&fixture.pending());
    fixture.assert_private(&fixture.journal());
    let phases: Vec<serde_json::Value> = fs::read_to_string(fixture.journal())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        phases
            .iter()
            .map(|value| value["phase"].as_str().unwrap())
            .collect::<Vec<_>>(),
        [
            "preflight",
            "pending-bundle-durable",
            "prepared-and-recovery-tested",
            "token-written-and-slot-tested"
        ]
    );
    assert_eq!(
        phases[1]["sha384"],
        hex::encode(leelo_crypto::hash_context(b"signed-encrypted-bundle"))
    );
    observation.finish(&Ok(()));
    let records = records.join().unwrap();
    let terminal = records.last().unwrap();
    assert_eq!(terminal.outcome, "success");
    assert_eq!(terminal.storage_state, "committed");
    assert!(terminal.awaiting_boot_test);
}

#[test]
fn existing_journal_or_pending_bundle_is_never_overwritten() {
    for pending in [false, true] {
        let fixture = Fixture::new();
        let path = if pending {
            fixture.pending()
        } else {
            fixture.journal()
        };
        fs::write(&path, b"existing recovery material").unwrap();
        let descriptor = fixture.descriptor();
        let mut observed = Operation::new("enroll", Emitter::new(None));
        let result =
            EnrollmentJournal::begin(LocalFiles, &fixture.journal(), &descriptor, &mut observed)
                .and_then(|mut journal| {
                    journal.commit(&descriptor, b"replacement", &mut observed, || {
                        panic!("storage must not be invoked")
                    })
                });
        assert!(result.is_err());
        assert_eq!(fs::read(path).unwrap(), b"existing recovery material");
    }
}

const OLD: [u8; 32] = [0x39; 32];

#[test]
#[ignore = "requires cryptsetup; creates only a disposable regular-file LUKS2 image"]
fn prepared_journal_sync_failure_preserves_actual_luks_metadata() {
    let fixture = Fixture::new();
    let mut luks = fixture.luks();
    let before = fixture.metadata();
    let mut descriptor = fixture.descriptor();
    descriptor.volume_uuid = luks.uuid();
    let mut observed = Operation::new("enroll", Emitter::new(None));
    let files = FaultFiles::new(Some((10, Failure::Before)));
    let mut journal =
        EnrollmentJournal::begin(files, &fixture.journal(), &descriptor, &mut observed).unwrap();
    let result = journal.commit(&descriptor, b"pending-bundle", &mut observed, || {
        luks.add_enrollment(1, &OLD, &[0x41; 32], b"pending-bundle")
    });
    assert!(result.is_err());
    drop(journal);
    drop(luks);
    assert_eq!(fixture.metadata(), before);
    let mut reopened = leelo_luks::Luks2::open(&fixture.root.join("volume.luks"), false).unwrap();
    assert_eq!(reopened.test_credential(Some(0), &OLD).unwrap(), 0);
    assert_eq!(fs::read(fixture.pending()).unwrap(), b"pending-bundle");
    assert_eq!(fs::read(fixture.root.join("old.key")).unwrap(), OLD);
}

// Synthetic TPM only for constructing an authentic, recoverable envelope. The
// filesystem and libcryptsetup operations in the ignored integration test are real.
struct TestTpm;
impl leelo_engine::TpmProvider for TestTpm {
    fn supports_mode(&self, mode: Mode) -> bool {
        mode == Mode::NetworkBound
    }
    fn seal(
        &mut self,
        _: &Descriptor,
        seed: &[u8; 32],
    ) -> std::result::Result<leelo_envelope::TpmBlob, leelo_engine::Error> {
        let wrapped = leelo_crypto::seal_key(&[0x67; 32], seed, b"test-only").unwrap();
        let mut private = wrapped.nonce.to_vec();
        private.extend(wrapped.ciphertext);
        Ok(leelo_envelope::TpmBlob {
            public: vec![1],
            private,
            name: vec![2],
            parent_name: vec![3],
        })
    }
    fn unseal(
        &mut self,
        envelope: &leelo_envelope::AuthenticatedEnvelope,
    ) -> std::result::Result<leelo_engine::UnsealedSeed, leelo_engine::Error> {
        let private = &envelope.body().tpm.private;
        let wrapped = leelo_crypto::WrappedKey {
            nonce: private[..12].try_into().unwrap(),
            ciphertext: private[12..].try_into().unwrap(),
        };
        Ok(leelo_engine::UnsealedSeed {
            seed: leelo_crypto::open_key(&[0x67; 32], &wrapped, b"test-only").unwrap(),
            authorization: leelo_engine::TpmAuthorization::LocalMeasuredBoot,
        })
    }
}
struct TestNetwork(leelo_crypto::SecretServer);
impl leelo_engine::NetworkProvider for TestNetwork {
    async fn evaluate(
        &self,
        _: &leelo_envelope::NetworkBinding,
        blinded: &[u8; 49],
        _: std::time::Instant,
    ) -> std::result::Result<leelo_crypto::Evaluation, leelo_engine::NetworkFailure> {
        self.0
            .evaluate(blinded)
            .map_err(|_| leelo_engine::NetworkFailure::Cryptography)
    }
}

#[test]
#[ignore = "requires cryptsetup; creates only disposable regular-file LUKS2 images"]
fn committed_enrollment_survives_final_journal_failures_and_resumes() {
    for (boundary, failure) in [
        (11, Failure::Before),
        (11, Failure::PartialWrite),
        (12, Failure::Before),
        (12, Failure::After),
    ] {
        let fixture = Fixture::new();
        let mut luks = fixture.luks();
        let mut network = TestNetwork(leelo_crypto::SecretServer::generate().unwrap());
        let mut tpm = TestTpm;
        let signer = SecretSigningKey::from_seed(&[0x71; 32]);
        let mut descriptor = fixture.descriptor();
        descriptor.volume_uuid = luks.uuid();
        let public_key = *network.0.public_key().as_bytes();
        descriptor.networks.push(leelo_envelope::NetworkBinding {
            node_id: 2,
            provider_id: [2; 32],
            key_id: leelo_net::key_id(&public_key),
            public_key,
            input_seed: [0x81; 32],
        });
        let prepared =
            leelo_engine::prepare(descriptor.clone(), &signer, &mut network, &mut tpm).unwrap();
        let (mut observation, records) = observed(&fixture.root, "enroll");
        let files = FaultFiles::new(Some((boundary, failure)));
        let calls = files.calls.clone();
        let mut journal =
            EnrollmentJournal::begin(files, &fixture.journal(), &descriptor, &mut observation)
                .unwrap();
        let result: Result<()> = journal
            .commit(&descriptor, &prepared.envelope, &mut observation, || {
                assert_eq!(calls.borrow().as_slice(), &STEPS[..11]);
                luks.add_enrollment(
                    descriptor.slot,
                    &OLD,
                    &prepared.credential,
                    &prepared.envelope,
                )
            })
            .map(|_| ());
        assert!(
            result
                .as_ref()
                .unwrap_err()
                .to_string()
                .contains("enrollment committed to slot 1 and token 0, but journal update failed")
        );
        observation.finish(&result);
        let records = records.join().unwrap();
        let terminal = records.last().unwrap();
        assert_eq!(terminal.storage_state, "committed");
        assert_eq!(terminal.outcome, "failure");
        assert_eq!(terminal.reason, "io");
        assert!(terminal.awaiting_boot_test);
        assert!(
            !records
                .iter()
                .any(|event| event.stage == "final_journal_durable")
        );
        drop(journal);
        drop(luks);

        let log = fs::read_to_string(fixture.journal()).unwrap();
        let lines: Vec<_> = log.lines().collect();
        assert!(
            lines[..3]
                .iter()
                .all(|line| serde_json::from_str::<serde_json::Value>(line).is_ok())
        );
        match (boundary, failure) {
            (11, Failure::Before) => assert_eq!(lines.len(), 3),
            (11, Failure::PartialWrite) => {
                assert_eq!(lines.len(), 4);
                assert!(serde_json::from_str::<serde_json::Value>(lines[3]).is_err());
            }
            (12, _) => {
                assert_eq!(lines.len(), 4);
                assert_eq!(
                    serde_json::from_str::<serde_json::Value>(lines[3]).unwrap()["phase"],
                    "token-written-and-slot-tested"
                );
            }
            _ => unreachable!(),
        }

        // Reopen all persisted state; neither the journal nor its final line is
        // needed by resume. Recover through actual envelope authentication/VOPRF.
        let raw = read_bounded(&fixture.pending(), leelo_envelope::MAX_ENVELOPE).unwrap();
        assert_eq!(raw, prepared.envelope);
        let authenticated = leelo_envelope::authenticate(&raw, &signer.public_key()).unwrap();
        let mut reopened =
            leelo_luks::Luks2::open(&fixture.root.join("volume.luks"), true).unwrap();
        let slot = authenticated.body().descriptor.slot;
        let recovered = leelo_engine::unlock(
            &raw,
            &signer.public_key(),
            &reopened.uuid(),
            slot,
            &mut network,
            &mut tpm,
        )
        .unwrap();
        assert_eq!(*recovered.credential, *prepared.credential);
        assert_eq!(reopened.test_credential(Some(0), &OLD).unwrap(), 0);
        assert_eq!(
            reopened
                .test_credential(Some(slot), recovered.credential.as_ref())
                .unwrap(),
            slot
        );
        assert_eq!(reopened.token(0).unwrap().bytes, raw);
        let mut resumed = Operation::new("resume", Emitter::new(None));
        assert_eq!(
            attach_recovered(
                &mut reopened,
                &fixture.pending(),
                slot,
                &recovered.credential,
                &raw,
                &mut resumed
            )
            .unwrap(),
            0
        );
        assert_eq!(
            attach_recovered(
                &mut reopened,
                &fixture.pending(),
                slot,
                &recovered.credential,
                &raw,
                &mut resumed
            )
            .unwrap(),
            0
        );
        let metadata = fixture.metadata();
        assert_eq!(metadata["tokens"].as_object().unwrap().len(), 1);
        assert_eq!(metadata["keyslots"].as_object().unwrap().len(), 2);
        assert_eq!(fs::read(fixture.root.join("old.key")).unwrap(), OLD);
        assert_eq!(fs::read(fixture.pending()).unwrap(), raw);
        fixture.assert_private(&fixture.pending());
    }
}
