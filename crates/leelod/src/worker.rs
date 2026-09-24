//! Only this server module can use the evaluation key.
//! This process uses a different OS account from the TLS frontend.
use crate::metrics::{Admission, Metrics, Outcome, Stage};
use leelo_crypto::SecretServer;
use leelo_protocol::{key_id, wire};
use std::fs::Permissions;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

const MAX_WORK: usize = 8;
const IPC_DEADLINE: Duration = Duration::from_secs(2);

pub fn keygen(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let secret = SecretServer::generate()?;
    let bytes = secret.export_secret_bytes();
    super::private_file::write_new(path, bytes.as_ref())?;
    let public = secret.public_key();
    println!(
        "{{\"key_id\":\"{}\",\"public_key\":\"{}\"}}",
        hex::encode(key_id(public.as_bytes())),
        hex::encode(public.as_bytes())
    );
    Ok(())
}

fn load(path: &Path) -> Result<SecretServer, Box<dyn std::error::Error>> {
    let bytes = super::private_file::read(path, 48)?;
    let mut scalar = Zeroizing::new([0; 48]);
    if bytes.len() != scalar.len() {
        return Err("evaluation key must contain exactly 48 bytes".into());
    }
    scalar.copy_from_slice(&bytes);
    Ok(SecretServer::from_secret_bytes(&scalar)?)
}

pub async fn run(
    key: &Path,
    socket: &Path,
    allowed_uid: u32,
    metrics: Arc<Metrics>,
    monitoring: &super::snapshot::Options,
) -> Result<(), Box<dyn std::error::Error>> {
    let secret = Arc::new(load(key).inspect_err(|_| {
        metrics.lifecycle("service_failed", "key_load", "failure", "invalid_key_file")
    })?);
    let parent = socket
        .parent()
        .ok_or("socket needs a parent directory")
        .inspect_err(|_| {
            metrics.lifecycle(
                "service_failed",
                "socket_directory",
                "failure",
                "invalid_directory",
            )
        })?;
    let metadata = std::fs::symlink_metadata(parent).inspect_err(|_| {
        metrics.lifecycle(
            "service_failed",
            "socket_directory",
            "failure",
            "invalid_directory",
        )
    })?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        metrics.lifecycle(
            "service_failed",
            "socket_directory",
            "failure",
            "invalid_directory",
        );
        return Err(
            "worker socket directory must be owned by worker UID and not writable by group/other"
                .into(),
        );
    }
    // The worker never removes an existing socket path automatically.
    let listener = UnixListener::bind(socket).inspect_err(|_| {
        metrics.lifecycle("service_failed", "listener", "failure", "bind_failed")
    })?;
    std::fs::set_permissions(socket, Permissions::from_mode(0o660)).inspect_err(|_| {
        metrics.lifecycle(
            "service_failed",
            "listener",
            "failure",
            "permissions_failed",
        )
    })?;
    let _exporter = super::snapshot::start_optional(monitoring, metrics.clone(), Some(allowed_uid));
    super::service::ready().inspect_err(|_| {
        metrics.lifecycle("service_failed", "readiness", "failure", "notify_failed")
    })?;
    metrics.lifecycle("service_ready", "startup", "success", "none");
    serve(listener, secret, allowed_uid, metrics).await
}

pub(crate) async fn serve(
    listener: UnixListener,
    secret: Arc<SecretServer>,
    allowed_uid: u32,
    metrics: Arc<Metrics>,
) -> Result<(), Box<dyn std::error::Error>> {
    let permits = Arc::new(Semaphore::new(MAX_WORK));
    let id = key_id(secret.public_key().as_bytes());
    loop {
        let (stream, _) =
            super::service::accept_observed(metrics.clone(), || listener.accept()).await?;
        match stream.peer_cred() {
            Ok(credentials) if credentials.uid() == allowed_uid => {}
            Ok(_) => {
                metrics.admission(Admission::Peer);
                metrics.event("worker_peer_denied", "admission", "failure", "peer_uid");
                continue;
            }
            Err(_) => {
                metrics.admission(Admission::PeerCheck);
                metrics.event(
                    "worker_peer_denied",
                    "admission",
                    "failure",
                    "peer_credentials",
                );
                continue;
            }
        }
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            metrics.admission(Admission::Capacity);
            metrics.event("capacity_rejected", "admission", "failure", "capacity");
            continue;
        };
        metrics.admission(Admission::Admitted);
        let inflight = metrics.enter();
        let metrics = metrics.clone();
        let secret = secret.clone();
        tokio::spawn(async move {
            // The permit also limits all pending reads and CPU evaluation jobs.
            let _permit = permit;
            let _inflight = inflight;
            let timer = metrics.stage(Stage::Worker);
            timer.finish(
                match tokio::time::timeout(
                    IPC_DEADLINE,
                    handle(stream, secret, id, metrics.clone()),
                )
                .await
                {
                    Ok(Ok(outcome) | Err(outcome)) => outcome,
                    Err(_) => Outcome::Timeout,
                },
            );
        });
    }
}

async fn handle(
    mut stream: UnixStream,
    secret: Arc<SecretServer>,
    id: [u8; 32],
    metrics: Arc<Metrics>,
) -> Result<Outcome, Outcome> {
    let validation = metrics.stage(Stage::Validation);
    let mut bytes = Vec::with_capacity(wire::REQUEST_BYTES + 1);
    (&mut stream)
        .take((wire::REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| Outcome::Read)?;
    let request = match wire::decode_request(&bytes) {
        Ok(request) if request.key_id == id => {
            validation.finish(Outcome::Success);
            request
        }
        other => {
            let outcome = if other.is_ok() {
                Outcome::WrongKey
            } else {
                Outcome::Frame
            };
            validation.finish(outcome);
            stream.write_all(&[1]).await.map_err(|_| Outcome::Write)?;
            return Ok(outcome);
        }
    };
    // A P-384 evaluation does not perform I/O. An attacker cannot change its work size.
    let timer = metrics.stage(Stage::Crypto);
    let evaluation = secret.evaluate(&request.point);
    let outcome = match &evaluation {
        Ok(_) => Outcome::Success,
        Err(leelo_crypto::Error::InvalidEncoding) => Outcome::InvalidPoint,
        Err(leelo_crypto::Error::Randomness) => Outcome::Randomness,
        Err(_) => Outcome::Crypto,
    };
    timer.finish(outcome);
    if matches!(outcome, Outcome::Randomness | Outcome::Crypto) {
        metrics.event(
            "evaluation_failed",
            "crypto",
            "failure",
            if outcome == Outcome::Randomness {
                "randomness"
            } else {
                "cryptographic_operation"
            },
        );
    }
    match evaluation {
        Ok(evaluation) => {
            stream.write_all(&[0]).await.map_err(|_| Outcome::Write)?;
            stream
                .write_all(&wire::encode_response(&evaluation))
                .await
                .map_err(|_| Outcome::Write)?;
        }
        Err(_) => stream.write_all(&[1]).await.map_err(|_| Outcome::Write)?,
    }
    stream.shutdown().await.map_err(|_| Outcome::Write)?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::os::unix::fs::symlink;

    #[test]
    fn key_file_rejects_permissions_symlinks_and_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        keygen(&path).unwrap();
        assert!(load(&path).is_ok());
        assert!(keygen(&path).is_err());
        std::fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();
        assert!(load(&path).is_err());
        std::fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(load(&link).is_err());
        OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(&[0])
            .unwrap();
        assert!(load(&path).is_err());
    }

    #[tokio::test]
    async fn socket_refuses_a_different_kernel_uid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("worker.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let secret = Arc::new(SecretServer::generate().unwrap());
        let forbidden_uid = rustix::process::geteuid().as_raw().wrapping_add(1);
        let task = tokio::spawn(async move {
            let _ = serve(
                listener,
                secret,
                forbidden_uid,
                Metrics::new(crate::metrics::Role::Worker, MAX_WORK),
            )
            .await;
        });
        let mut client = UnixStream::connect(path).await.unwrap();
        let mut response = [0; 1];
        let received = tokio::time::timeout(Duration::from_secs(1), client.read(&mut response))
            .await
            .unwrap();
        assert!(matches!(received, Ok(0) | Err(_)));
        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn worker_admission_is_bounded_and_counts_capacity_drops() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("worker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let secret = Arc::new(SecretServer::generate().unwrap());
        let metrics = Metrics::new(crate::metrics::Role::Worker, MAX_WORK);
        let observed = metrics.clone();
        let task = tokio::spawn(async move {
            serve(
                listener,
                secret,
                rustix::process::geteuid().as_raw(),
                observed,
            )
            .await
            .map_err(|_| ())
        });
        let mut pending = Vec::new();
        for _ in 0..MAX_WORK {
            pending.push(UnixStream::connect(&socket).await.unwrap());
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while !metrics
                .snapshot()
                .contains("leelo_inflight{role=\"worker\"} 8")
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let mut excess = UnixStream::connect(&socket).await.unwrap();
        let received = tokio::time::timeout(Duration::from_secs(1), excess.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, 0);
        assert!(
            metrics
                .snapshot()
                .contains("admission=\"capacity_rejected\"} 1")
        );
        drop(pending);
        task.abort();
    }

    #[tokio::test]
    async fn socket_rejects_wrong_mode_key_size_and_point() {
        let secret = Arc::new(SecretServer::generate().unwrap());
        let id = key_id(secret.public_key().as_bytes());
        let (_, point) = leelo_crypto::blind(b"socket regression").unwrap();
        let valid = wire::encode_request(&id, &point);
        let mut wrong_mode = valid.to_vec();
        wrong_mode[6] = 2;
        let mut wrong_key = valid.to_vec();
        wrong_key[8] ^= 1;
        let mut oversized = valid.to_vec();
        oversized.push(0);
        let bad_point = wire::encode_request(&id, &[0; 49]).to_vec();
        for (message, expected) in [
            (wrong_mode, Outcome::Frame),
            (wrong_key, Outcome::WrongKey),
            (oversized, Outcome::Frame),
            (valid[..88].to_vec(), Outcome::Frame),
            (bad_point, Outcome::InvalidPoint),
        ] {
            let (mut client, worker) = UnixStream::pair().unwrap();
            let task = tokio::spawn(handle(
                worker,
                secret.clone(),
                id,
                Metrics::new(crate::metrics::Role::Worker, MAX_WORK),
            ));
            client.write_all(&message).await.unwrap();
            client.shutdown().await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, [1]);
            assert_eq!(task.await.unwrap().unwrap(), expected);
        }
    }
}
