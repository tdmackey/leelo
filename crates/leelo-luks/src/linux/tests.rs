use super::*;
use std::{
    fs::{self, DirBuilder},
    io::Write,
    os::unix::fs::{DirBuilderExt, MetadataExt},
    path::PathBuf,
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
const OLD: [u8; 32] = [13; 32];
const NEW: [u8; 32] = [27; 32];

struct Fixture {
    root: PathBuf,
    image: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let sequence = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let root = PathBuf::from(format!(
            "/tmp/leelo-luks-test-{}-{nonce}-{sequence}",
            std::process::id()
        ));
        DirBuilder::new().mode(0o700).create(&root).unwrap();
        let fixture = Self {
            image: root.join("volume.luks"),
            root,
        };
        let image = fixture.create_file("volume.luks", &[]);
        image.set_len(64 * 1024 * 1024).unwrap();
        fixture.create_file("old.key", &OLD);
        fixture.create_file("new.key", &NEW);
        let old = fixture.root.join("old.key");
        fixture.command(&[
            "luksFormat",
            "--batch-mode",
            "--type",
            "luks2",
            "--pbkdf",
            "pbkdf2",
            "--pbkdf-force-iterations",
            "1000",
            "--luks2-metadata-size",
            "16k",
            "--key-file",
            old.to_str().unwrap(),
            fixture.image(),
        ]);
        fixture
    }

    fn create_file(&self, name: &str, bytes: &[u8]) -> File {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(self.root.join(name))
            .unwrap();
        file.write_all(bytes).unwrap();
        file
    }

    fn image(&self) -> &str {
        self.image.to_str().unwrap()
    }

    fn guard(&self) {
        assert_eq!(self.root.parent(), Some(Path::new("/tmp")));
        assert!(
            self.root
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("leelo-luks-test-")
        );
        assert_eq!(self.root.canonicalize().unwrap(), self.root);
        let metadata = fs::symlink_metadata(&self.image).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.len(), 64 * 1024 * 1024);
    }

    fn command(&self, args: &[&str]) -> Output {
        self.guard();
        let output = Command::new("cryptsetup").args(args).output().unwrap();
        assert!(
            output.status.success(),
            "cryptsetup failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn metadata(&self) -> Value {
        let output = self.command(&["luksDump", "--dump-json-metadata", self.image()]);
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn add_native_slot(&self) {
        let old = self.root.join("old.key");
        let new = self.root.join("new.key");
        self.command(&[
            "luksAddKey",
            "--batch-mode",
            "--pbkdf",
            "pbkdf2",
            "--pbkdf-force-iterations",
            "1000",
            "--key-slot",
            "1",
            "--key-file",
            old.to_str().unwrap(),
            self.image(),
            new.to_str().unwrap(),
        ]);
    }

    fn add_token(&self, id: u8) {
        self.add_token_json(id, br#"{"type":"fixture","keyslots":["0"]}"#);
    }

    fn add_token_json(&self, id: u8, json: &[u8]) {
        self.guard();
        let mut child = Command::new("cryptsetup")
            .args([
                "token",
                "import",
                "--token-id",
                &id.to_string(),
                "--json-file",
                "-",
                self.image(),
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(json).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "token fixture failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn check_old(&self) {
        let mut current = Luks2::open(&self.image, false).unwrap();
        assert_eq!(current.test_credential(Some(0), &OLD).unwrap(), 0);
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Only this constructor supplies the path. No user-selected path is deleted.
        if self.root.parent() == Some(Path::new("/tmp"))
            && self
                .root
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with("leelo-luks-test-"))
            && fs::symlink_metadata(&self.root).is_ok_and(|metadata| metadata.is_dir())
        {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

#[test]
#[ignore = "requires cryptsetup; creates only a disposable regular-file LUKS2 image"]
fn removed_cached_token_is_restored_and_resume_is_idempotent() {
    let fixture = Fixture::new();
    fixture.add_native_slot();
    let mut device = Luks2::open(&fixture.image, true).unwrap();
    let token = device
        .attach_enrollment(1, &NEW, b"signed-test-envelope")
        .unwrap();
    fixture.command(&[
        "token",
        "remove",
        "--token-id",
        &token.to_string(),
        fixture.image(),
    ]);
    assert!(fixture.metadata()["tokens"].as_object().unwrap().is_empty());
    let restored = device
        .attach_enrollment(1, &NEW, b"signed-test-envelope")
        .unwrap();
    assert_eq!(fixture.metadata()["tokens"].as_object().unwrap().len(), 1);
    assert_eq!(
        device
            .attach_enrollment(1, &NEW, b"signed-test-envelope")
            .unwrap(),
        restored
    );
    assert_eq!(fixture.metadata()["tokens"].as_object().unwrap().len(), 1);
    fixture.check_old();
}

#[test]
#[ignore = "requires cryptsetup; creates only a disposable regular-file LUKS2 image"]
fn full_token_table_is_rejected_before_slot_creation() {
    let fixture = Fixture::new();
    let mut device = Luks2::open(&fixture.image, true).unwrap();
    // Populate after open to test that preflight reads current metadata.
    for id in 0..32 {
        fixture.add_token(id);
    }
    assert!(matches!(
        device.add_enrollment(1, &OLD, &NEW, b"envelope"),
        Err(Error::NoTokenSpace)
    ));
    assert!(fixture.metadata()["keyslots"].get("1").is_none());
    fixture.check_old();
}

#[test]
#[ignore = "requires cryptsetup; creates only a disposable regular-file LUKS2 image"]
fn long_native_json_number_does_not_hide_used_metadata_space() {
    let fixture = Fixture::new();
    let number = format!("1.{}", "0".repeat(9500));
    let json = format!(r#"{{"type":"fixture","keyslots":["0"],"number":{number}}}"#);
    fixture.add_token_json(0, json.as_bytes());
    let before = fixture.command(&["luksDump", "--dump-json-metadata", fixture.image()]);
    assert!(
        before
            .stdout
            .windows(number.len())
            .any(|part| part == number.as_bytes())
    );
    let mut device = Luks2::open(&fixture.image, true).unwrap();
    assert!(matches!(
        device.add_enrollment(1, &OLD, &NEW, &vec![9; 2000]),
        Err(Error::MetadataSpace { .. })
    ));
    assert!(fixture.metadata()["keyslots"].get("1").is_none());
    let after = fixture.command(&["luksDump", "--dump-json-metadata", fixture.image()]);
    assert_eq!(before.stdout, after.stdout);
    fixture.check_old();
}

#[test]
#[ignore = "requires cryptsetup; creates only a disposable regular-file LUKS2 image"]
fn metadata_limit_is_checked_before_add_and_near_limit_succeeds() {
    let fixture = Fixture::new();
    let mut device = Luks2::open(&fixture.image, true).unwrap();
    let (mut low, mut high) = (1, 16 * 1024);
    while low + 1 < high {
        let middle = (low + high) / 2;
        if device.token_plan(1, &vec![9; middle], true).is_ok() {
            low = middle;
        } else {
            high = middle;
        }
    }
    assert!(matches!(
        device.add_enrollment(1, &OLD, &NEW, &vec![9; high]),
        Err(Error::MetadataSpace { .. })
    ));
    assert!(fixture.metadata()["keyslots"].get("1").is_none());
    let envelope = vec![9; low];
    let token = device.add_enrollment(1, &OLD, &NEW, &envelope).unwrap();
    let mut fresh = Luks2::open(&fixture.image, false).unwrap();
    assert_eq!(fresh.token(token as u8).unwrap().bytes, envelope);
    assert_eq!(fresh.test_credential(Some(1), &NEW).unwrap(), 1);
    fixture.check_old();
}

#[test]
#[ignore = "requires cryptsetup; creates only a disposable regular-file LUKS2 image"]
fn concurrent_leelo_writer_is_rejected_and_lock_releases() {
    let fixture = Fixture::new();
    let owner = Luks2::open(&fixture.image, true).unwrap();
    let lock = WriteLock::acquire(&owner.file).unwrap();
    let mut other = Luks2::open(&fixture.image, true).unwrap();
    assert!(matches!(
        other.add_enrollment(1, &OLD, &NEW, b"envelope"),
        Err(Error::WriterBusy)
    ));
    assert!(fixture.metadata()["keyslots"].get("1").is_none());
    drop(lock);
    let _new_lock = WriteLock::acquire(&other.file).unwrap();
    fixture.check_old();
}

#[test]
#[ignore = "requires cryptsetup; creates only a disposable regular-file LUKS2 image"]
fn occupied_slot_and_changed_uuid_are_rejected_after_open() {
    let fixture = Fixture::new();
    let mut device = Luks2::open(&fixture.image, true).unwrap();
    fixture.add_native_slot();
    assert!(matches!(
        device.add_enrollment(1, &OLD, &NEW, b"envelope"),
        Err(Error::OccupiedSlot)
    ));
    fixture.command(&[
        "luksUUID",
        "--uuid",
        "12345678-1234-4234-8234-123456789abc",
        fixture.image(),
    ]);
    assert!(matches!(
        device.add_enrollment(2, &OLD, &NEW, b"envelope"),
        Err(Error::WrongVolume)
    ));
    assert!(fixture.metadata()["keyslots"].get("2").is_none());
    fixture.check_old();
}
