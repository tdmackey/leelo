use crate::metrics::{Metrics, Received};
use crate::{Result, SnapshotRole};
use leelo_telemetry::{MAX_EVENT_BYTES, Record, unix_time_ms};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, recvmsg};
use std::fs::{File, OpenOptions};
use std::io::{self, IoSliceMut, Read, Write};
use std::mem::MaybeUninit;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::path::Path;
use std::time::{Duration, Instant};

const LOG_LIMIT: u64 = 16 * 1024 * 1024;
const SNAPSHOT_LIMIT: usize = 64 * 1024;
const SNAPSHOT_DEADLINE: Duration = Duration::from_millis(250);

fn private_directory(path: &Path) -> Result<()> {
    let info = std::fs::symlink_metadata(path)?;
    if !info.is_dir()
        || info.uid() != rustix::process::geteuid().as_raw()
        || info.mode() & 0o022 != 0
    {
        return Err(
            "directory must be owned by collector and not writable by group or other".into(),
        );
    }
    Ok(())
}

fn open_log(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .mode(0o600)
        .custom_flags((rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC).bits() as i32)
        .open(path)?;
    let info = file.metadata()?;
    if !info.is_file()
        || info.uid() != rustix::process::geteuid().as_raw()
        || info.mode() & 0o077 != 0
        || info.len() > LOG_LIMIT + 8192
    {
        return Err("invalid local event log".into());
    }
    Ok(file)
}

fn replay(path: &Path, metrics: &mut Metrics) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let mut file = open_log(path)?;
    let mut bytes = Vec::new();
    (&mut file).take(LOG_LIMIT + 8193).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LOG_LIMIT + 8192 {
        return Err("event log exceeds bound".into());
    }
    // A newline commits one local record. Never concatenate the next append with
    // a crash/short-write tail, even when that tail happens to be valid JSON.
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        let complete = bytes
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map_or(0, |n| n + 1);
        file.set_len(complete as u64)?;
        file.sync_data()?;
        bytes.truncate(complete);
        metrics.rejected = metrics.rejected.saturating_add(1);
    }
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        if line.len() > MAX_EVENT_BYTES + 1024 {
            metrics.rejected = metrics.rejected.saturating_add(1);
            continue;
        }
        if let Ok(record) = serde_json::from_slice::<Received>(line) {
            metrics.accept(&record);
        } else {
            metrics.rejected = metrics.rejected.saturating_add(1);
        }
    }
    Ok(())
}

fn read_event(socket: &UnixDatagram, sources: &[(String, u32)]) -> io::Result<Option<Received>> {
    let mut bytes = [0; MAX_EVENT_BYTES + 1];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmCredentials(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let message = recvmsg(
        socket,
        &mut [IoSliceMut::new(&mut bytes)],
        &mut ancillary,
        RecvFlags::CMSG_CLOEXEC,
    )?;
    if message
        .flags
        .intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC)
        || message.bytes > MAX_EVENT_BYTES
    {
        return Ok(None);
    }
    let mut credentials = None;
    for item in ancillary.drain() {
        if let RecvAncillaryMessage::ScmCredentials(value) = item {
            credentials = Some(value);
        }
    }
    let Some(credentials) = credentials else {
        return Ok(None);
    };
    if !sources
        .iter()
        .any(|(_, uid)| *uid == credentials.uid.as_raw())
    {
        return Ok(None);
    }
    let Some(record) = Record::decode(&bytes[..message.bytes]) else {
        return Ok(None);
    };
    if !sources
        .iter()
        .any(|(component, uid)| component == &record.component && *uid == credentials.uid.as_raw())
    {
        return Ok(None);
    }
    Ok(Some(Received {
        source_uid: credentials.uid.as_raw(),
        source_pid: credentials.pid.as_raw_nonzero().get() as u32,
        received_at_ms: unix_time_ms().unwrap_or(0),
        record,
    }))
}

pub fn events(socket: &Path, state_dir: &Path, source: &[String]) -> Result<()> {
    if source.is_empty() || source.len() > 32 {
        return Err("invalid source list".into());
    }
    let mut sources = Vec::new();
    for value in source {
        let (component, uid) = value.split_once(':').ok_or("source needs component:uid")?;
        let uid: u32 = uid.parse()?;
        if !["client", "frontend", "worker", "leelod"].contains(&component)
            || sources.iter().any(|(previous_component, previous_uid)| {
                previous_component == component && *previous_uid == uid
            })
        {
            return Err("invalid or duplicate component and source UID".into());
        }
        sources.push((component.to_owned(), uid));
    }
    private_directory(socket.parent().ok_or("socket needs a parent")?)?;
    private_directory(state_dir)?;
    let socket = UnixDatagram::bind(socket)?;
    // Pass credentials before senders can write. The private directory controls access.
    rustix::net::sockopt::set_socket_passcred(&socket, true)?;
    std::fs::set_permissions(
        socket
            .local_addr()?
            .as_pathname()
            .ok_or("pathname socket required")?,
        std::fs::Permissions::from_mode(0o660),
    )?;
    socket.set_read_timeout(Some(Duration::from_millis(200)))?;
    let path = state_dir.join("events.jsonl");
    let previous = state_dir.join("events.previous.jsonl");
    let mut metrics = Metrics::default();
    replay(&previous, &mut metrics)?;
    replay(&path, &mut metrics)?;
    let mut log = open_log(&path)?;
    let mut log_size = log.metadata()?.len();
    let mut last_export = Instant::now() - Duration::from_secs(1);
    loop {
        match read_event(&socket, &sources) {
            Ok(Some(received)) => {
                if metrics.accept(&received) {
                    let mut bytes = serde_json::to_vec(&received)?;
                    bytes.push(b'\n');
                    if log_size + bytes.len() as u64 > LOG_LIMIT {
                        drop(log);
                        std::fs::rename(&path, &previous)?;
                        log = open_log(&path)?;
                        log_size = 0;
                    }
                    if log.write_all(&bytes).is_err() {
                        metrics.write_failures = metrics.write_failures.saturating_add(1);
                        // write_all can write a prefix before failing. If rollback
                        // fails, stop instead of appending onto damaged state.
                        log.set_len(log_size)?;
                    } else {
                        log_size += bytes.len() as u64;
                    }
                }
            }
            Ok(None) => metrics.rejected = metrics.rejected.saturating_add(1),
            Err(error)
                if [
                    io::ErrorKind::WouldBlock,
                    io::ErrorKind::TimedOut,
                    io::ErrorKind::Interrupted,
                ]
                .contains(&error.kind()) => {}
            Err(_) => return Err("event receive failed".into()),
        }
        if last_export.elapsed() >= Duration::from_secs(1) {
            let text = metrics.render(unix_time_ms().unwrap_or(0));
            if crate::reconcile::atomic_write(&state_dir.join("events.prom"), text.as_bytes())
                .is_err()
            {
                metrics.write_failures = metrics.write_failures.saturating_add(1);
            }
            last_export = Instant::now();
        }
    }
}

pub fn snapshot(
    socket: &Path,
    server_uid: u32,
    expected_role: SnapshotRole,
    output: &Path,
) -> Result<()> {
    let mut bytes = read_snapshot(socket, server_uid, Instant::now() + SNAPSHOT_DEADLINE)?;
    let text = std::str::from_utf8(&bytes)?;
    let mut series = std::collections::BTreeSet::new();
    let role = expected_role.as_str();
    if text.is_empty() || !text.ends_with('\n') {
        return Err("invalid metrics snapshot".into());
    }
    for line in text.lines() {
        if sample_role(line) != Some(role)
            || !series.insert(line.rsplit_once(' ').map(|(key, _)| key))
        {
            return Err("invalid metrics snapshot".into());
        }
    }
    let suffix = format!(
        "leelo_daemon_snapshot_timestamp_seconds{{role=\"{role}\"}} {}\n",
        unix_time_ms().unwrap_or(0) as f64 / 1000.0
    );
    bytes.extend_from_slice(suffix.as_bytes());
    crate::reconcile::atomic_write(output, &bytes)
}

fn wait_ready(stream: &UnixStream, flags: PollFlags, deadline: Instant) -> io::Result<()> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or(io::ErrorKind::TimedOut)?;
        let timeout = Timespec::try_from(remaining).map_err(|_| io::ErrorKind::InvalidInput)?;
        let mut fds = [PollFd::new(stream, flags)];
        match poll(&mut fds, Some(&timeout)) {
            Ok(0) => return Err(io::ErrorKind::TimedOut.into()),
            Ok(_) => return Ok(()),
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

fn read_snapshot(socket: &Path, server_uid: u32, deadline: Instant) -> Result<Vec<u8>> {
    use rustix::net::{
        AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect, socket_with,
    };
    let address = SocketAddrUnix::new(socket)?;
    let fd = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )?;
    let mut stream = UnixStream::from(fd);
    match connect(&stream, &address) {
        Ok(()) => {}
        Err(rustix::io::Errno::INPROGRESS) => {
            wait_ready(&stream, PollFlags::OUT, deadline)?;
            rustix::net::sockopt::socket_error(&stream)??;
        }
        // Linux AF_UNIX reports EAGAIN for a full backlog. Fail promptly: the
        // collector must never block behind an unresponsive snapshot listener.
        Err(error) => return Err(error.into()),
    }
    if rustix::net::sockopt::socket_peercred(&stream)?.uid.as_raw() != server_uid {
        return Err("unexpected metrics owner".into());
    }
    let mut bytes = Vec::with_capacity(8192);
    loop {
        if Instant::now() >= deadline {
            return Err("snapshot deadline".into());
        }
        let mut chunk = [0; 4096];
        let len = match stream.read(&mut chunk) {
            Ok(len) => len,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait_ready(&stream, PollFlags::IN, deadline)?;
                continue;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        if len == 0 {
            break;
        }
        if bytes.len() + len > SNAPSHOT_LIMIT {
            return Err("snapshot exceeds bound".into());
        }
        bytes.extend_from_slice(&chunk[..len]);
    }
    Ok(bytes)
}

fn sample_role(line: &str) -> Option<&'static str> {
    const STAGES: &[&str] = &[
        "connection",
        "tls",
        "http",
        "validation",
        "ipc",
        "worker",
        "crypto",
        "listener_retry",
        "snapshot",
    ];
    const OUTCOMES: &[&str] = &[
        "success",
        "cancelled",
        "timeout",
        "protocol_error",
        "invalid_headers",
        "invalid_body",
        "invalid_frame",
        "wrong_key",
        "invalid_point",
        "randomness_failure",
        "crypto_failure",
        "connect_error",
        "write_error",
        "read_error",
        "refused",
        "unexpected_eof",
        "io_error",
        "not_found",
        "method_not_allowed",
        "unavailable",
        "other_error",
    ];
    let (key, value) = line.rsplit_once(' ')?;
    if key.len() > 512
        || !value
            .parse::<f64>()
            .is_ok_and(|value| value.is_finite() && value >= 0.0)
    {
        return None;
    }
    let (name, labels) = key.split_once('{')?;
    let labels: Vec<_> = labels
        .strip_suffix('}')?
        .split(',')
        .map(|field| {
            let (name, value) = field.split_once('=')?;
            Some((name, value.strip_prefix('"')?.strip_suffix('"')?))
        })
        .collect::<Option<_>>()?;
    let role = match labels.first()? {
        ("role", "frontend") => "frontend",
        ("role", "worker") => "worker",
        _ => return None,
    };
    // Fixed names, label keys, order and values match the daemon schema. This
    // also makes duplicate-series detection independent of label permutations.
    let valid = match (name, &labels[1..]) {
        (
            "leelo_telemetry_dropped_total" | "leelo_telemetry_suppressed_total",
            [("signal", "events")],
        ) => true,
        ("leelo_connections_total", [("admission", value)]) => [
            "admitted",
            "capacity_rejected",
            "peer_rejected",
            "peer_check_error",
        ]
        .contains(value),
        ("leelo_inflight" | "leelo_concurrency_limit" | "leelo_listener_retrying", []) => true,
        ("leelo_server_stage_completions_total", [("stage", stage), ("outcome", outcome)]) => {
            STAGES.contains(stage) && OUTCOMES.contains(outcome)
        }
        ("leelo_server_stage_duration_seconds_bucket", [("stage", stage), ("le", bound)]) => {
            STAGES.contains(stage)
                && [
                    "0.001", "0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1", "2", "5",
                    "10", "+Inf",
                ]
                .contains(bound)
        }
        (
            "leelo_server_stage_duration_seconds_count" | "leelo_server_stage_duration_seconds_sum",
            [("stage", stage)],
        ) => STAGES.contains(stage),
        ("leelo_http_responses_total", [("status", status)]) => {
            ["200", "400", "404", "405", "503", "0"].contains(status)
        }
        ("leelo_accept_errors_total", [("class", class)]) => {
            ["interrupted", "resource", "network", "other"].contains(class)
        }
        ("leelo_snapshot_connections_total", [("outcome", outcome)]) => [
            "served",
            "peer_rejected",
            "peer_check_error",
            "capacity_rejected",
            "write_error",
            "timeout",
            "listener_error",
        ]
        .contains(outcome),
        _ => false,
    };
    valid.then_some(role)
}

#[cfg(test)]
mod tests {
    use super::*;
    use leelo_telemetry::{Emitter, Event};

    #[test]
    fn kernel_uid_controls_event_admission() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.sock");
        let socket = UnixDatagram::bind(&path).unwrap();
        rustix::net::sockopt::set_socket_passcred(&socket, true).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let emit = Emitter::new(Some(&path));
        let uid = rustix::process::geteuid().as_raw();
        emit.emit(Event::new(
            "client",
            "operation_completed",
            "activate",
            "activate",
            "success",
            "none",
        ));
        assert!(
            read_event(&socket, &[("client".into(), uid.wrapping_add(1))])
                .unwrap()
                .is_none()
        );
        emit.emit(Event::new(
            "client",
            "operation_completed",
            "activate",
            "activate",
            "success",
            "none",
        ));
        assert_eq!(
            read_event(&socket, &[("client".into(), uid)])
                .unwrap()
                .unwrap()
                .source_uid,
            uid
        );
        emit.emit(Event::new(
            "client",
            "operation_completed",
            "activate",
            "activate",
            "success",
            "none",
        ));
        assert!(
            read_event(&socket, &[("worker".into(), uid)])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn snapshot_rejects_payload_and_nonfinite_values() {
        assert_eq!(
            sample_role("leelo_inflight{role=\"worker\"} 2"),
            Some("worker")
        );
        assert_eq!(sample_role("private_key secret"), None);
        assert_eq!(sample_role("leelo_inflight{role=\"worker\"} NaN"), None);
        assert_eq!(sample_role("leelo_test{value=\"arbitrary text\"} 1"), None);
        assert_eq!(sample_role("leelo_test{secret=\"deadbeef\"} 1"), None);
        assert_eq!(
            sample_role("leelo_inflight{role=\"worker\",role=\"frontend\"} 1"),
            None
        );
    }

    fn sample(sequence: u64) -> Received {
        serde_json::from_value(serde_json::json!({
            "source_uid": 42, "source_pid": 10, "received_at_ms": 1000,
            "record": {
                "schema_version":1,"component":"client","event":"phase_completed","operation":"activate",
                "stage":"recover","outcome":"success","reason":"none","duration_seconds":0.1,
                "mode":"network_bound","provider_index":null,"storage_state":"not_applicable",
                "awaiting_boot_test":false,"degraded":false,"native_code":null,"software_version":"0.1.0",
                "attempt_id":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"boot_id":null,
                "sequence":sequence,"unix_time_ms":1000,"dropped_before":0
            }
        })).unwrap()
    }

    #[test]
    fn restart_repairs_partial_tail_before_next_append() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let mut file = open_log(&path).unwrap();
        let first = serde_json::to_vec(&sample(0)).unwrap();
        file.write_all(&first).unwrap();
        file.write_all(b"\n{\"record\":").unwrap();
        drop(file);
        let mut metrics = Metrics::default();
        replay(&path, &mut metrics).unwrap();
        assert_eq!(metrics.accepted, 1);
        assert_eq!(metrics.rejected, 1);
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            first.len() as u64 + 1
        );
        let mut file = open_log(&path).unwrap();
        file.write_all(&serde_json::to_vec(&sample(1)).unwrap())
            .unwrap();
        file.write_all(b"\n").unwrap();
        drop(file);
        let mut restarted = Metrics::default();
        replay(&path, &mut restarted).unwrap();
        assert_eq!(restarted.accepted, 2);
        assert_eq!(restarted.rejected, 0);
        // Complete JSON without its commit newline is also an incomplete tail.
        std::fs::write(&path, first).unwrap();
        replay(&path, &mut restarted).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        assert_eq!(restarted.rejected, 1);
    }

    #[test]
    fn snapshot_connect_never_blocks_behind_a_full_backlog() {
        use rustix::net::{
            AddressFamily, SocketAddrUnix, SocketFlags, SocketType, bind, connect, listen,
            socket_with,
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metrics.sock");
        let address = SocketAddrUnix::new(&path).unwrap();
        let socket = || {
            socket_with(
                AddressFamily::UNIX,
                SocketType::STREAM,
                SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
                None,
            )
            .unwrap()
        };
        let listener = socket();
        bind(&listener, &address).unwrap();
        listen(&listener, 1).unwrap();
        let mut pending = Vec::new();
        let mut full = false;
        for _ in 0..8 {
            let stream = socket();
            match connect(&stream, &address) {
                Ok(()) => pending.push(stream),
                Err(rustix::io::Errno::AGAIN) => {
                    full = true;
                    break;
                }
                Err(error) => panic!("unexpected local connect failure: {error}"),
            }
        }
        assert!(full, "test must fill the unaccepted connection backlog");
        let start = Instant::now();
        assert!(
            read_snapshot(
                &path,
                rustix::process::geteuid().as_raw(),
                start + SNAPSHOT_DEADLINE
            )
            .is_err()
        );
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn snapshot_read_deadline_is_total_and_invalid_data_preserves_old_output() {
        use std::os::unix::net::UnixListener;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metrics.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            for byte in b"leelo_inflight{role=\"worker\"} 1\n" {
                if stream.write_all(&[*byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(40));
            }
        });
        let output = dir.path().join("metrics.prom");
        std::fs::write(&output, b"previous complete observation\n").unwrap();
        let start = Instant::now();
        assert!(
            snapshot(
                &path,
                rustix::process::geteuid().as_raw(),
                SnapshotRole::Worker,
                &output
            )
            .is_err()
        );
        assert!(start.elapsed() < Duration::from_secs(1));
        thread.join().unwrap();
        assert_eq!(
            std::fs::read(&output).unwrap(),
            b"previous complete observation\n"
        );
    }

    #[test]
    fn duplicate_snapshot_series_are_rejected() {
        use std::os::unix::net::UnixListener;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("metrics.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let thread = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .write_all(
                    b"leelo_inflight{role=\"worker\"} 1\nleelo_inflight{role=\"worker\"} 2\n",
                )
                .unwrap();
        });
        let output = dir.path().join("metrics.prom");
        assert!(
            snapshot(
                &path,
                rustix::process::geteuid().as_raw(),
                SnapshotRole::Worker,
                &output
            )
            .is_err()
        );
        assert!(!output.exists());
        thread.join().unwrap();
    }

    #[test]
    fn authenticated_snapshot_peer_cannot_claim_another_role() {
        use std::os::unix::net::UnixListener;
        for expected in [SnapshotRole::Worker, SnapshotRole::Frontend] {
            for reported in ["worker", "frontend"] {
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("metrics.sock");
                let listener = UnixListener::bind(&path).unwrap();
                let thread = std::thread::spawn(move || {
                    let (mut stream, _) = listener.accept().unwrap();
                    writeln!(stream, "leelo_inflight{{role=\"{reported}\"}} 1").unwrap();
                });
                let output = dir.path().join("metrics.prom");
                let previous = b"previous complete observation\n";
                std::fs::write(&output, previous).unwrap();
                let result = snapshot(
                    &path,
                    rustix::process::geteuid().as_raw(),
                    expected,
                    &output,
                );
                thread.join().unwrap();
                if expected.as_str() == reported {
                    result.unwrap();
                    let text = std::fs::read_to_string(&output).unwrap();
                    assert!(text.contains(&format!(
                        "leelo_daemon_snapshot_timestamp_seconds{{role=\"{reported}\"}}"
                    )));
                } else {
                    assert!(result.is_err());
                    assert_eq!(std::fs::read(&output).unwrap(), previous);
                }
            }
        }
    }
}
