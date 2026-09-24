//! Read-only aggregate snapshots on a separate, protected Unix socket.
use crate::metrics::{Metrics, Outcome, SnapshotOutcome, Stage};
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;

const SCRAPERS: usize = 2;
const WRITE_DEADLINE: Duration = Duration::from_millis(100);

pub use crate::Monitoring as Options;

pub struct Exporter(tokio::task::JoinHandle<()>);
impl Drop for Exporter {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Observations cannot make an otherwise valid evaluator unavailable.
pub fn start_optional(
    options: &Options,
    metrics: Arc<Metrics>,
    evaluator_uid: Option<u32>,
) -> Option<Exporter> {
    start(options, metrics.clone(), evaluator_uid).unwrap_or_else(|_| {
        metrics.lifecycle("telemetry_failed", "snapshot", "failure", "setup_failed");
        None
    })
}

pub fn start(
    options: &Options,
    metrics: Arc<Metrics>,
    evaluator_uid: Option<u32>,
) -> io::Result<Option<Exporter>> {
    let Some(path) = &options.metrics_socket else {
        return Ok(None);
    };
    let uid = options
        .metrics_uid
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    validate_uid(uid, evaluator_uid)?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let parent_metadata = validate_directory(parent)?;
    let gid = options.metrics_gid.unwrap_or(parent_metadata.gid());
    if options.metrics_gid.is_some() {
        // systemd may restore RuntimeDirectory ownership before each command.
        // Assign only this validated metrics directory after service startup.
        std::os::unix::fs::chown(parent, None, Some(gid))?;
    }
    // Never unlink or follow an existing socket path. Service management owns cleanup.
    let listener = UnixListener::bind(path)?;
    // The service is a member of the observation group. Assign it explicitly:
    // setgid directories are incompatible with RestrictSUIDSGID=yes.
    std::os::unix::fs::chown(path, None, Some(gid))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(Some(Exporter(tokio::spawn(serve(listener, uid, metrics)))))
}

fn validate_uid(uid: u32, evaluator_uid: Option<u32>) -> io::Result<()> {
    if uid == rustix::process::geteuid().as_raw() || Some(uid) == evaluator_uid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "collector must use a separate UID",
        ));
    }
    Ok(())
}

fn validate_directory(path: &Path) -> io::Result<std::fs::Metadata> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "metrics directory must be service-owned and not group/other writable",
        ));
    }
    Ok(metadata)
}

async fn serve(listener: UnixListener, uid: u32, metrics: Arc<Metrics>) {
    let permits = Arc::new(Semaphore::new(SCRAPERS));
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(_) => {
                metrics.snapshot_outcome(SnapshotOutcome::Listener);
                metrics.event(
                    "snapshot_listener_failed",
                    "snapshot",
                    "failure",
                    "listener_error",
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        match stream.peer_cred() {
            Ok(peer) if peer.uid() == uid => {}
            Ok(_) => {
                metrics.snapshot_outcome(SnapshotOutcome::Peer);
                continue;
            }
            Err(_) => {
                metrics.snapshot_outcome(SnapshotOutcome::PeerCheck);
                continue;
            }
        }
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            metrics.snapshot_outcome(SnapshotOutcome::Capacity);
            continue;
        };
        let metrics = metrics.clone();
        tokio::spawn(async move {
            let _permit = permit;
            send(stream, metrics).await;
        });
    }
}

async fn send(mut stream: UnixStream, metrics: Arc<Metrics>) {
    let timer = metrics.stage(Stage::Snapshot);
    let snapshot = metrics.snapshot();
    let result = bounded_write(&mut stream, snapshot.as_bytes()).await;
    let (counter, outcome) = match result {
        Ok(()) => (SnapshotOutcome::Served, Outcome::Success),
        Err(Outcome::Timeout) => (SnapshotOutcome::Timeout, Outcome::Timeout),
        Err(_) => (SnapshotOutcome::Write, Outcome::Write),
    };
    metrics.snapshot_outcome(counter);
    timer.finish(outcome);
}

async fn bounded_write<W: AsyncWrite + Unpin>(writer: &mut W, bytes: &[u8]) -> Result<(), Outcome> {
    match tokio::time::timeout(WRITE_DEADLINE, async {
        writer.write_all(bytes).await?;
        writer.shutdown().await
    })
    .await
    {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(Outcome::Write),
        Err(_) => Err(Outcome::Timeout),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::Role;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn unauthorized_peer_receives_no_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metrics.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let metrics = Metrics::new(Role::Worker, 8);
        let task = tokio::spawn(serve(
            listener,
            rustix::process::geteuid().as_raw().wrapping_add(1),
            metrics.clone(),
        ));
        let mut client = UnixStream::connect(path).await.unwrap();
        let mut bytes = Vec::new();
        client.read_to_end(&mut bytes).await.unwrap();
        assert!(bytes.is_empty());
        assert!(metrics.snapshot().contains("outcome=\"peer_rejected\"} 1"));
        task.abort();
    }
    #[tokio::test]
    async fn authorized_peer_gets_only_fixed_aggregate_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metrics.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let task = tokio::spawn(serve(
            listener,
            rustix::process::geteuid().as_raw(),
            Metrics::new(Role::Worker, 8),
        ));
        let mut client = UnixStream::connect(path).await.unwrap();
        let mut text = String::new();
        client.read_to_string(&mut text).await.unwrap();
        assert!(text.contains("leelo_concurrency_limit{role=\"worker\"} 8"));
        assert!(text.len() < 64 * 1024);
        assert!(!text.contains("key_id"));
        task.abort();
    }
    #[tokio::test(start_paused = true)]
    async fn slow_reader_has_a_fixed_deadline() {
        let (mut writer, _reader) = tokio::io::duplex(1);
        let start = tokio::time::Instant::now();
        assert_eq!(
            bounded_write(&mut writer, &[0; 1024]).await,
            Err(Outcome::Timeout)
        );
        assert_eq!(start.elapsed(), WRITE_DEADLINE);
    }
    #[test]
    fn collector_is_separate_and_directory_is_protected() {
        let current = rustix::process::geteuid().as_raw();
        assert!(validate_uid(current, None).is_err());
        assert!(validate_uid(current.wrapping_add(1), Some(current.wrapping_add(1))).is_err());
        let dir = tempfile::tempdir().unwrap();
        assert!(validate_directory(dir.path()).is_ok());
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(validate_directory(dir.path()).is_err());
    }

    #[tokio::test]
    async fn unset_group_retains_the_validated_directory_group() {
        let dir = tempfile::tempdir().unwrap();
        let before = std::fs::metadata(dir.path()).unwrap();
        let path = dir.path().join("metrics.sock");
        let options = Options {
            metrics_socket: Some(path.clone()),
            metrics_uid: Some(rustix::process::geteuid().as_raw().wrapping_add(1)),
            metrics_gid: None,
        };
        let _exporter = start(&options, Metrics::new(Role::Frontend, 64), None)
            .unwrap()
            .unwrap();
        let after = std::fs::metadata(dir.path()).unwrap();
        assert_eq!(after.gid(), before.gid());
        assert_eq!(after.mode(), before.mode());
        assert_eq!(std::fs::metadata(path).unwrap().gid(), before.gid());
    }

    #[tokio::test]
    async fn configured_group_applies_to_metrics_directory_and_socket_without_setgid() {
        let current_uid = rustix::process::geteuid().as_raw();
        let primary_gid = rustix::process::getegid().as_raw();
        // Prefer a distinct group when the test account can assign one. The
        // deployed service test separately exercises SupplementaryGroups.
        let observation_gid = rustix::process::getgroups()
            .unwrap()
            .into_iter()
            .map(|group| group.as_raw())
            .find(|group| *group != primary_gid)
            .unwrap_or_else(|| {
                if current_uid == 0 {
                    primary_gid.wrapping_add(1)
                } else {
                    primary_gid
                }
            });
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
        let path = dir.path().join("metrics.sock");
        let options = Options {
            metrics_socket: Some(path.clone()),
            metrics_uid: Some(current_uid.wrapping_add(1)),
            metrics_gid: Some(observation_gid),
        };
        let exporter = start(&options, Metrics::new(Role::Worker, 8), None)
            .unwrap()
            .unwrap();
        let socket = std::fs::symlink_metadata(&path).unwrap();
        assert_eq!(socket.uid(), current_uid);
        assert_eq!(socket.gid(), observation_gid);
        assert_eq!(socket.mode() & 0o7777, 0o660);
        assert_eq!(
            std::fs::symlink_metadata(dir.path()).unwrap().gid(),
            observation_gid
        );
        assert_eq!(
            std::fs::symlink_metadata(dir.path()).unwrap().mode() & 0o7777,
            0o750
        );
        // Startup must not unlink or replace a socket already present.
        assert!(start(&options, Metrics::new(Role::Worker, 8), None).is_err());
        assert_eq!(std::fs::symlink_metadata(path).unwrap().ino(), socket.ino());
        drop(exporter);
    }
}
