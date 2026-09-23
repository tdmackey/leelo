use clap::{Parser, Subcommand};
use leelo_crypto::SecretSigningKey;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
#[cfg(target_os = "linux")]
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

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
mod linux {
    use super::*;
    use leelo_envelope::{Descriptor, NetworkBinding};
    use leelo_policy::{Mode, NetworkNode, ProductionPolicy};
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Config {
        providers: Vec<ProviderConfig>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ProviderConfig {
        provider_id: String,
        key_id: String,
        public_key: String,
        url: String,
        ca_file: PathBuf,
    }
    fn unhex<const N: usize>(value: &str) -> Result<[u8; N]> {
        hex::decode(value)?
            .try_into()
            .map_err(|_| "wrong hex field length".into())
    }
    fn config(path: &Path) -> Result<(Vec<NetworkBinding>, leelo_net::HttpsNetworkProvider)> {
        let cfg: Config = serde_json::from_slice(&read_bounded(path, 32 * 1024)?)?;
        if cfg.providers.is_empty() || cfg.providers.len() > 27 {
            return Err("configure 1..27 independent network providers".into());
        }
        let mut bindings = Vec::new();
        let mut endpoints = Vec::new();
        for (i, p) in cfg.providers.into_iter().enumerate() {
            let provider_id = unhex(&p.provider_id)?;
            let public_key = unhex(&p.public_key)?;
            let key_id = unhex(&p.key_id)?;
            if leelo_net::key_id(&public_key) != key_id {
                return Err("provider key ID does not match public key".into());
            }
            let ca = if p.ca_file.is_absolute() {
                p.ca_file
            } else {
                path.parent().unwrap_or(Path::new(".")).join(p.ca_file)
            };
            endpoints.push(leelo_net::Endpoint {
                provider_id,
                url: p.url,
                ca_pem: read_bounded(&ca, 64 * 1024)?,
            });
            bindings.push(NetworkBinding {
                node_id: (i + 2) as u8,
                provider_id,
                key_id,
                public_key,
                input_seed: *leelo_crypto::random_bytes::<32>()?,
            });
        }
        Ok((bindings, leelo_net::HttpsNetworkProvider::new(endpoints)?))
    }
    fn journal(file: &mut File, phase: &str, descriptor: &Descriptor) -> Result<()> {
        writeln!(
            file,
            "{}",
            serde_json::json!({"phase":phase,"binding_id":hex::encode(descriptor.binding_id),"volume_uuid":uuid::Uuid::from_bytes(descriptor.volume_uuid).to_string(),"slot":descriptor.slot})
        )?;
        file.sync_all()?;
        Ok(())
    }
    fn sync_parent(path: &Path) -> Result<()> {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        File::open(parent)?.sync_all()?;
        Ok(())
    }
    pub fn run(command: Command) -> Result<()> {
        match command {
            Command::PcrDigest { tcti, pcr_mask } => {
                let mut tpm = leelo_tpm::Tpm2Provider::new(&tcti)?;
                println!("{}", hex::encode(tpm.pcr_digest(pcr_mask)?));
            }
            Command::Enroll {
                device,
                config: config_path,
                existing_key_file,
                signing_key,
                journal: journal_path,
                tcti,
                pcr_mask,
                threshold,
            } => {
                let (networks, mut net) = config(&config_path)?;
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
                    .map(|n| NetworkNode::Leaf {
                        id: n.node_id,
                        provider_id: n.provider_id,
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
                let mut log = create_private(&journal_path)?;
                journal(&mut log, "preflight", &descriptor)?;
                sync_parent(&journal_path)?;
                let prepared =
                    leelo_engine::prepare(descriptor.clone(), &signer, &mut net, &mut tpm)?;
                // Test recovery through the actual TPM and network before a slot change.
                let recovered = leelo_engine::unlock(
                    &prepared.envelope,
                    &signer.public_key(),
                    &descriptor.volume_uuid,
                    descriptor.slot,
                    &mut net,
                    &mut tpm,
                )?;
                if *recovered != *prepared.credential {
                    return Err("enrollment round-trip mismatch".into());
                }
                // Save the signed, encrypted recovery material before AddKey.
                // A crash can occur between the slot write and the token write.
                // To resume, authenticate this bundle and test its exact slot.
                let pending_path = journal_path.with_extension("pending.leelo");
                let mut pending = create_private(&pending_path)?;
                pending.write_all(&prepared.envelope)?;
                pending.sync_all()?;
                sync_parent(&pending_path)?;
                writeln!(
                    &mut log,
                    "{}",
                    serde_json::json!({
                        "phase":"pending-bundle-durable", "path":pending_path,
                        "sha384":hex::encode(leelo_crypto::hash_context(&prepared.envelope))
                    })
                )?;
                journal(&mut log, "prepared-and-recovery-tested", &descriptor)?;
                let token = luks.add_enrollment(
                    descriptor.slot,
                    &old,
                    &prepared.credential,
                    &prepared.envelope,
                )?;
                journal(&mut log, "token-written-and-slot-tested", &descriptor)
                    .map_err(|e| format!("enrollment committed to slot {} and token {token}, but journal update failed: {e}; retain {}", descriptor.slot, pending_path.display()))?;
                println!(
                    "{}",
                    serde_json::json!({"enrolled":true,"token":token,"slot":descriptor.slot,"pending_bundle":pending_path,"production_boot_test_required":true,"old_slots_preserved":true})
                );
            }
            Command::ResumeEnrollment {
                device,
                config: config_path,
                trust_key,
                pending_bundle,
                tcti,
            } => {
                let trusted = read_array(&trust_key)?;
                let raw = read_bounded(&pending_bundle, leelo_envelope::MAX_ENVELOPE)?;
                let envelope = leelo_envelope::authenticate(&raw, &trusted)?;
                let slot = envelope.body().descriptor.slot;
                let mut luks = leelo_luks::Luks2::open(&device, true)?;
                let (_, mut net) = config(&config_path)?;
                let mut tpm = leelo_tpm::Tpm2Provider::new(&tcti)?;
                let credential =
                    leelo_engine::unlock(&raw, &trusted, &luks.uuid(), slot, &mut net, &mut tpm)?;
                let token = luks.attach_enrollment(slot, &credential, &raw)?;
                println!(
                    "{}",
                    serde_json::json!({"enrolled":true,"resumed":true,"token":token,"slot":slot,"old_slots_preserved":true})
                );
            }
            Command::Unlock {
                device,
                config: config_path,
                trust_key,
                token,
                tcti,
                mapping,
                check_only: _,
            } => {
                let (_, mut net) = config(&config_path)?;
                let trusted = read_array(&trust_key)?;
                let mut luks = leelo_luks::Luks2::open(&device, false)?;
                let token = luks.token(token)?;
                let mut tpm = leelo_tpm::Tpm2Provider::new(&tcti)?;
                let key = leelo_engine::unlock(
                    &token.bytes,
                    &trusted,
                    &luks.uuid(),
                    token.slot,
                    &mut net,
                    &mut tpm,
                )?;
                if let Some(name) = mapping {
                    luks.activate(token.slot, key.as_ref(), &name)?;
                    println!("activated {name}");
                } else {
                    luks.test_credential(Some(token.slot), key.as_ref())?;
                    println!("unlock verified; no mapping created");
                }
            }
            _ => return Err("unexpected platform command".into()),
        }
        Ok(())
    }
}

fn run() -> Result<()> {
    match Args::parse().command {
        Command::Keygen { private, public } => {
            let key = SecretSigningKey::generate()?;
            let mut secret = create_private(&private)?;
            secret.write_all(key.export_seed().as_ref())?;
            secret.sync_all()?;
            let mut pubfile = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(public)?;
            pubfile.write_all(&key.public_key())?;
            pubfile.sync_all()?;
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
