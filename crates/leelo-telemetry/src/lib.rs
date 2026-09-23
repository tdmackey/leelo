//! Emit bounded public observations. Delivery must not control credential release.
#![forbid(unsafe_code)]

#[cfg(not(target_os = "linux"))]
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const MAX_EVENT_BYTES: usize = 4096;
pub const SCHEMA_VERSION: u8 = 1;

/// Label values must be static program text. This type has no free-text field.
pub struct Event {
    pub component: &'static str,
    pub event: &'static str,
    pub operation: &'static str,
    pub stage: &'static str,
    pub outcome: &'static str,
    pub reason: &'static str,
    pub duration: Duration,
    pub mode: &'static str,
    pub provider_index: Option<u8>,
    pub storage_state: &'static str,
    pub awaiting_boot_test: bool,
    pub degraded: bool,
    pub native_code: Option<i64>,
}

impl Event {
    pub fn new(
        component: &'static str,
        event: &'static str,
        operation: &'static str,
        stage: &'static str,
        outcome: &'static str,
        reason: &'static str,
    ) -> Self {
        Self {
            component,
            event,
            operation,
            stage,
            outcome,
            reason,
            duration: Duration::ZERO,
            mode: "none",
            provider_index: None,
            storage_state: "not_applicable",
            awaiting_boot_test: false,
            degraded: false,
            native_code: None,
        }
    }
}

/// This owned representation is for collectors. Validate it before use.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub schema_version: u8,
    pub component: String,
    pub event: String,
    pub operation: String,
    pub stage: String,
    pub outcome: String,
    pub reason: String,
    pub duration_seconds: f64,
    pub mode: String,
    pub provider_index: Option<u8>,
    pub storage_state: String,
    pub awaiting_boot_test: bool,
    pub degraded: bool,
    pub native_code: Option<i64>,
    pub software_version: String,
    pub attempt_id: Option<[u8; 16]>,
    pub boot_id: Option<[u8; 16]>,
    pub sequence: u64,
    pub unix_time_ms: Option<u64>,
    pub dropped_before: u64,
}

impl Record {
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > MAX_EVENT_BYTES {
            return None;
        }
        let value: Self = serde_json::from_slice(bytes).ok()?;
        value.valid().then_some(value)
    }

    pub fn valid(&self) -> bool {
        self.schema_version == SCHEMA_VERSION
            && self.software_version.len() <= 48
            && self
                .software_version
                .bytes()
                .all(|v| v.is_ascii_alphanumeric() || b".-_".contains(&v))
            && [
                self.component.as_str(),
                &self.event,
                &self.operation,
                &self.stage,
                &self.outcome,
                &self.reason,
                &self.mode,
                &self.storage_state,
            ]
            .into_iter()
            .all(valid_label)
            && self.duration_seconds.is_finite()
            && (0.0..=604_800.0).contains(&self.duration_seconds)
            && self
                .provider_index
                .is_none_or(|index| (1..=31).contains(&index))
            && vocabulary(self)
    }
}

fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 48
        && value
            .bytes()
            .all(|v| v.is_ascii_lowercase() || v.is_ascii_digit() || v == b'_')
}

fn vocabulary(record: &Record) -> bool {
    ["client", "frontend", "worker", "leelod"].contains(&record.component.as_str())
        && [
            "operation_started",
            "operation_completed",
            "provider_completed",
            "phase_started",
            "phase_completed",
            "enrollment_state",
            "key_creation",
            "service_start",
            "service_ready",
            "service_stop",
            "service_failed",
            "telemetry_failed",
            "worker_peer_denied",
            "capacity_rejected",
            "evaluation_failed",
            "listener_recovered",
            "listener_impaired",
            "listener_failed",
            "snapshot_listener_failed",
            "worker_reply_invalid",
        ]
        .contains(&record.event.as_str())
        && [
            "enroll",
            "resume",
            "check",
            "activate",
            "keygen",
            "inspect",
            "pcr_digest",
            "serve",
        ]
        .contains(&record.operation.as_str())
        && ["none", "unknown", "network_bound", "attested"].contains(&record.mode.as_str())
        && [
            "not_applicable",
            "not_mutated",
            "pending_reconciliation",
            "committed",
            "unknown",
        ]
        .contains(&record.storage_state.as_str())
        && [
            "preflight",
            "preflight_durable",
            "prepare",
            "recover",
            "recovery_test",
            "activate",
            "check",
            "validate",
            "tpm_seal",
            "network",
            "tpm_unseal",
            "authenticate_payload",
            "prepare_payload",
            "share_generation",
            "pending_bundle",
            "pending_bundle_durable",
            "prepared_and_recovery_tested",
            "storage_commit",
            "storage_committed",
            "storage_attach",
            "final_journal",
            "final_journal_durable",
            "key_file",
            "key_load",
            "startup",
            "service",
            "socket_directory",
            "listener",
            "snapshot",
            "readiness",
            "admission",
            "crypto",
            "connection",
            "ipc",
            "tls_config",
        ]
        .contains(&record.stage.as_str())
        && [
            "started",
            "success",
            "failure",
            "observed",
            "not_started",
            "authenticated",
            "failed",
            "canceled_quorum",
            "canceled_deadline",
            "canceled_operation",
        ]
        .contains(&record.outcome.as_str())
        && [
            "none",
            "envelope",
            "cryptography",
            "sharing",
            "policy",
            "tpm",
            "insufficient_factors",
            "deadline",
            "inconsistent_shares",
            "target_mismatch",
            "unsupported_mode",
            "runtime",
            "configuration",
            "unavailable",
            "timeout",
            "remote_rejected",
            "invalid_response",
            "invalid_proof",
            "authentication",
            "io",
            "cryptsetup",
            "partial_enrollment",
            "writer_busy",
            "metadata_changed",
            "occupied_slot",
            "metadata_capacity",
            "invalid_token",
            "wrong_volume",
            "storage",
            "configuration_or_operation",
            "peer_uid",
            "peer_credentials",
            "capacity",
            "randomness",
            "cryptographic_operation",
            "temporary_accept",
            "fatal_accept",
            "invalid_reply",
            "invalid_key_file",
            "invalid_directory",
            "bind_failed",
            "permissions_failed",
            "setup_failed",
            "notify_failed",
            "invalid_configuration",
            "key_creation_failed",
            "service_failed",
            "accept_error",
            "listener_error",
        ]
        .contains(&record.reason.as_str())
}

fn attempt_id() -> Option<[u8; 16]> {
    let mut bytes = [0; 16];
    #[cfg(target_os = "linux")]
    {
        let length =
            rustix::rand::getrandom(&mut bytes, rustix::rand::GetRandomFlags::NONBLOCK).ok()?;
        (length == bytes.len()).then_some(bytes)
    }
    #[cfg(not(target_os = "linux"))]
    {
        OsRng.try_fill_bytes(&mut bytes).ok().map(|()| bytes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmitStatus {
    Sent,
    Disabled,
    Dropped,
}

/// One emitter owns one operation or daemon lifetime. It does not flush on drop.
pub struct Emitter {
    path: Option<PathBuf>,
    #[cfg(unix)]
    socket: Option<std::os::unix::net::UnixDatagram>,
    attempt_id: Option<[u8; 16]>,
    boot_id: Option<[u8; 16]>,
    sequence: AtomicU64,
    dropped: AtomicU64,
}

impl Emitter {
    pub fn from_env() -> Self {
        let path = std::env::var_os("LEELO_EVENTS_SOCKET").map(PathBuf::from);
        Self::new(path.as_deref())
    }

    pub fn new(path: Option<&Path>) -> Self {
        let attempt_id = if path.is_some() { attempt_id() } else { None };
        #[cfg(unix)]
        let socket = path.and_then(|_| {
            let socket = std::os::unix::net::UnixDatagram::unbound().ok()?;
            socket.set_nonblocking(true).ok()?;
            Some(socket)
        });
        Self {
            path: path.map(Path::to_path_buf),
            #[cfg(unix)]
            socket,
            attempt_id,
            boot_id: path.and_then(|_| boot_id()),
            sequence: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        }
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn emit(&self, event: Event) -> EmitStatus {
        let Some(path) = &self.path else {
            return EmitStatus::Disabled;
        };
        // A collector cannot deduplicate an event without an attempt ID.
        // Count the loss locally; do not claim delivery or wait for entropy.
        if self.attempt_id.is_none() {
            return self.drop_event();
        }
        if ![
            event.component,
            event.event,
            event.operation,
            event.stage,
            event.outcome,
            event.reason,
            event.mode,
            event.storage_state,
        ]
        .into_iter()
        .all(valid_label)
        {
            return self.drop_event();
        }
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        let record = self.record(event, sequence);
        let mut buffer = FixedBuffer {
            bytes: [0; MAX_EVENT_BYTES],
            len: 0,
        };
        if !record.valid() || serde_json::to_writer(&mut buffer, &record).is_err() {
            return self.drop_event();
        }
        #[cfg(unix)]
        if self.socket.as_ref().is_some_and(|socket| {
            socket
                .send_to(&buffer.bytes[..buffer.len], path)
                .is_ok_and(|n| n == buffer.len)
        }) {
            return EmitStatus::Sent;
        }
        #[cfg(not(unix))]
        let _ = path;
        self.drop_event()
    }

    fn drop_event(&self) -> EmitStatus {
        let _ = self
            .dropped
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                Some(count.saturating_add(1))
            });
        EmitStatus::Dropped
    }

    fn record(&self, event: Event, sequence: u64) -> Record {
        Record {
            schema_version: SCHEMA_VERSION,
            component: event.component.into(),
            event: event.event.into(),
            operation: event.operation.into(),
            stage: event.stage.into(),
            outcome: event.outcome.into(),
            reason: event.reason.into(),
            duration_seconds: event.duration.as_secs_f64(),
            mode: event.mode.into(),
            provider_index: event.provider_index,
            storage_state: event.storage_state.into(),
            awaiting_boot_test: event.awaiting_boot_test,
            degraded: event.degraded,
            native_code: event.native_code,
            software_version: env!("CARGO_PKG_VERSION").into(),
            attempt_id: self.attempt_id,
            boot_id: self.boot_id,
            sequence,
            unix_time_ms: unix_time_ms(),
            dropped_before: self.dropped(),
        }
    }
}

pub fn unix_time_ms() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|value| value.as_millis().try_into().ok())
}

fn boot_id() -> Option<[u8; 16]> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let mut bytes = Vec::with_capacity(37);
    std::fs::File::open("/proc/sys/kernel/random/boot_id")
        .ok()?
        .take(38)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() != 37 || bytes[36] != b'\n' {
        return None;
    }
    let mut output = [0; 16];
    let mut digits = bytes[..36].iter().copied().filter(|v| *v != b'-');
    for item in &mut output {
        *item = (digits.next()? as char).to_digit(16)? as u8 * 16
            + (digits.next()? as char).to_digit(16)? as u8;
    }
    if digits.next().is_some() {
        return None;
    }
    Some(output)
}

struct FixedBuffer {
    bytes: [u8; MAX_EVENT_BYTES],
    len: usize,
}
impl Write for FixedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.bytes.len() - self.len {
            return Err(io::ErrorKind::WriteZero.into());
        }
        self.bytes[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn event() -> Event {
        Event::new(
            "client",
            "operation_completed",
            "activate",
            "activate",
            "success",
            "none",
        )
    }

    #[test]
    fn schema_rejects_arbitrary_text_and_unknown_fields() {
        let emitter = Emitter::new(None);
        let record = emitter.record(event(), 0);
        let mut json = serde_json::to_value(&record).unwrap();
        json["secret"] = "never accepted".into();
        assert!(Record::decode(&serde_json::to_vec(&json).unwrap()).is_none());
        let mut record = record;
        record.reason = "request body: secret".into();
        assert!(!record.valid());
        record.reason = "deadbeefcafebabe".into();
        assert!(!record.valid());
        record.reason = "none".into();
        record.provider_index = Some(255);
        assert!(!record.valid());
    }

    #[test]
    fn disabled_delivery_does_not_count_as_loss() {
        let emitter = Emitter::new(None);
        assert_eq!(emitter.emit(event()), EmitStatus::Disabled);
        assert_eq!(emitter.dropped(), 0);
    }

    #[test]
    fn unavailable_attempt_identity_counts_as_loss_without_waiting() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.sock");
        #[cfg(unix)]
        let receiver = std::os::unix::net::UnixDatagram::bind(&path).unwrap();
        let mut emitter = Emitter::new(Some(&path));
        emitter.attempt_id = None;
        let start = std::time::Instant::now();
        assert_eq!(emitter.emit(event()), EmitStatus::Dropped);
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(emitter.dropped(), 1);
        #[cfg(unix)]
        {
            receiver.set_nonblocking(true).unwrap();
            let mut bytes = [0; MAX_EVENT_BYTES];
            assert_eq!(
                receiver.recv(&mut bytes).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        }
        emitter.dropped.store(u64::MAX, Ordering::Relaxed);
        assert_eq!(emitter.emit(event()), EmitStatus::Dropped);
        assert_eq!(emitter.dropped(), u64::MAX);
    }

    #[cfg(unix)]
    #[test]
    fn absent_and_full_collectors_never_wait() {
        use std::os::unix::net::UnixDatagram;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.sock");
        let emitter = Emitter::new(Some(&path));
        assert_eq!(emitter.emit(event()), EmitStatus::Dropped);
        let receiver = UnixDatagram::bind(&path).unwrap();
        receiver.set_nonblocking(true).unwrap();
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            emitter.emit(event());
        }
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(emitter.dropped() > 1);
        let mut bytes = [0; MAX_EVENT_BYTES + 1];
        let len = receiver.recv(&mut bytes).unwrap();
        let record = Record::decode(&bytes[..len]).unwrap();
        assert_eq!(record.dropped_before, 1);
        assert_eq!(record.sequence, 1);
        assert!(record.attempt_id.is_some());
        let json = serde_json::to_string(&record).unwrap();
        assert!(!json.contains("volume_uuid"));
        assert!(!json.contains("binding_id"));
    }
}
