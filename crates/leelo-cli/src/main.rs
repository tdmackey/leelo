use clap::{Parser, Subcommand};
use std::{
    fs::{File, OpenOptions},
    io::Read,
    path::{Path, PathBuf},
};
#[cfg(target_os = "linux")]
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[cfg(target_os = "linux")]
mod enrollment;
mod keygen;
#[cfg(any(target_os = "linux", test))]
mod observation;
#[cfg(target_os = "linux")]
mod providers;

#[derive(Parser)]
#[command(
    name = "leelo",
    version,
    about = "TPM2 + network-bound LUKS2 enrollment (experimental)"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a local administrative signing key. This command does not contact a TPM or target disk.
    Keygen {
        #[arg(long)]
        private: PathBuf,
        #[arg(long)]
        public: PathBuf,
    },
    /// Authenticate an envelope with an externally trusted key. Then inspect the envelope.
    Inspect {
        #[arg(long)]
        envelope: PathBuf,
        #[arg(long)]
        trust_key: PathBuf,
    },
    /// Get a snapshot of the selected SHA256 PCR digest. This command requires Linux.
    PcrDigest {
        #[arg(long, default_value = "device:/dev/tpmrm0")]
        tcti: String,
        #[arg(long, default_value_t = 2176)]
        pcr_mask: u32,
    },
    /// Add a new network-bound slot. This command never deletes an existing slot.
    Enroll {
        #[arg(long)]
        device: PathBuf,
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        existing_key_file: PathBuf,
        #[arg(long)]
        signing_key: PathBuf,
        #[arg(long)]
        journal: PathBuf,
        #[arg(long, default_value = "device:/dev/tpmrm0")]
        tcti: String,
        #[arg(long, default_value_t = 2176)]
        pcr_mask: u32,
        #[arg(long, default_value_t = 1)]
        threshold: u8,
    },
    /// Verify that a staged enrollment unlocks its signed slot. Then attach the enrollment.
    ResumeEnrollment {
        #[arg(long)]
        device: PathBuf,
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        trust_key: PathBuf,
        #[arg(long)]
        pending_bundle: PathBuf,
        #[arg(long, default_value = "device:/dev/tpmrm0")]
        tcti: String,
    },
    /// Recover a token credential and test it or activate the named mapping.
    Unlock {
        #[arg(long)]
        device: PathBuf,
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        trust_key: PathBuf,
        #[arg(long)]
        token: u8,
        #[arg(long, default_value = "device:/dev/tpmrm0")]
        tcti: String,
        #[arg(
            long,
            conflicts_with = "check_only",
            required_unless_present = "check_only"
        )]
        mapping: Option<String>,
        #[arg(long)]
        check_only: bool,
    },
}

fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    File::open(path)?
        .take((max + 1) as u64)
        .read_to_end(&mut output)?;
    if output.len() > max {
        return Err("input exceeds permitted size".into());
    }
    Ok(output)
}
fn read_array<const N: usize>(path: &Path) -> Result<[u8; N]> {
    read_bounded(path, N)?
        .try_into()
        .map_err(|_| "key file has incorrect length".into())
}
fn sync_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn create_private(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err("private key creation requires Unix permission controls".into())
    }
    #[cfg(unix)]
    {
        Ok(options.open(path)?)
    }
}
#[cfg(target_os = "linux")]
fn read_secret(path: &Path, max: usize) -> Result<Zeroizing<Vec<u8>>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.mode() & 0o077 != 0 {
        return Err("secret file must be a regular file with mode 0600 or stricter".into());
    }
    let mut data = Zeroizing::new(Vec::new());
    file.take((max + 1) as u64).read_to_end(&mut data)?;
    if data.is_empty() || data.len() > max {
        return Err("secret file has invalid size".into());
    }
    Ok(data)
}

fn inspect(raw: &[u8], trust: &[u8; 32]) -> Result<()> {
    let env = leelo_envelope::authenticate(raw, trust)?;
    let d = &env.body().descriptor;
    println!(
        "{}",
        serde_json::json!({
            "authenticated":true,"binding_id":hex::encode(d.binding_id),
            "volume_uuid":uuid::Uuid::from_bytes(d.volume_uuid).to_string(),"slot":d.slot,
            "generation":d.generation,"mode":format!("{:?}",d.policy.mode()),
            "mandatory_tpm":true,"network_leaf_count":d.networks.len(),
            "pcr_mask":d.tpm_pcr_mask,"policy":format!("{:?}",d.policy.network())
        })
    );
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux;

fn run() -> Result<()> {
    match Args::parse().command {
        Command::Keygen { private, public } => {
            let result = keygen::create(&private, &public);
            let mut event = leelo_telemetry::Event::new(
                "client",
                "key_creation",
                "keygen",
                "key_file",
                if result.is_ok() { "success" } else { "failure" },
                if result.is_ok() {
                    "none"
                } else {
                    "key_creation_failed"
                },
            );
            event.storage_state = if result.is_ok() {
                "committed"
            } else {
                "unknown"
            };
            leelo_telemetry::Emitter::from_env().emit(event);
            result?;
            println!("created signing key and public trust key");
            Ok(())
        }
        Command::Inspect {
            envelope,
            trust_key,
        } => inspect(
            &read_bounded(&envelope, leelo_envelope::MAX_ENVELOPE)?,
            &read_array(&trust_key)?,
        ),
        command => {
            #[cfg(target_os = "linux")]
            {
                linux::run(command)
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = command;
                Err(
                    "TPM2/LUKS2 commands require Linux; proof/core tests also run on Windows"
                        .into(),
                )
            }
        }
    }
}
fn main() {
    if let Err(e) = run() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
