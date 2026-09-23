use crate::{Result, create_private, sync_parent};
use leelo_crypto::SecretSigningKey;
use std::{fs::OpenOptions, io::Write, path::Path};

pub(super) fn create(private: &Path, public: &Path) -> Result<()> {
    let key = SecretSigningKey::generate()?;
    let mut secret = create_private(private)?;
    let mut write_private = || -> Result<()> {
        secret.write_all(key.export_seed().as_ref())?;
        secret.sync_all()?;
        sync_parent(private)
    };
    write_private().map_err(|error| format!(
        "private key file {} was created, but writing or syncing failed: {error}; no public key was created; inspect the private file before use",
        private.display()
    ))?;

    let mut public_file = OpenOptions::new().write(true).create_new(true).open(public)
        .map_err(|error| format!(
            "private key {} is durable; public key {} could not be created: {error}; retain the private key and do not assume an existing public file matches",
            private.display(), public.display()
        ))?;
    let mut write_public = || -> Result<()> {
        public_file.write_all(&key.public_key())?;
        public_file.sync_all()?;
        sync_parent(public)
    };
    write_public().map_err(|error| format!(
        "private key {} is durable; public key file {} was created, but writing or syncing failed: {error}; the key pair is not confirmed complete",
        private.display(), public.display()
    ))?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn existing_public_file_reports_and_preserves_partial_pair() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("leelo-keygen-{}-{nonce}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let private = root.join("admin.private");
        let public = root.join("admin.public");
        fs::write(&public, b"existing public file").unwrap();
        let error = create(&private, &public).unwrap_err().to_string();
        assert!(
            error.contains("private key")
                && error.contains("is durable")
                && error.contains("could not be created")
        );
        assert_eq!(fs::metadata(&private).unwrap().len(), 32);
        assert_eq!(
            fs::metadata(&private).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read(&public).unwrap(), b"existing public file");
        fs::remove_file(&private).unwrap();
        fs::remove_file(&public).unwrap();
        fs::remove_dir(&root).unwrap();
    }
}
