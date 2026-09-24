//! Fixed-cardinality, in-memory observations. No request-derived values enter labels.
use std::fmt::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Instant;

#[derive(Clone, Copy)]
pub enum Role {
    Frontend,
    Worker,
}
impl Role {
    fn name(self) -> &'static str {
        match self {
            Self::Frontend => "frontend",
            Self::Worker => "worker",
        }
    }
}

macro_rules! labels {
    ($name:ident { $($variant:ident => $label:literal),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(usize)]
        pub enum $name { $($variant),+ }
        impl $name {
            const ALL: &'static [Self] = &[$(Self::$variant),+];
            fn name(self) -> &'static str { match self { $(Self::$variant => $label),+ } }
        }
    };
}
labels!(Admission { Admitted => "admitted", Capacity => "capacity_rejected", Peer => "peer_rejected", PeerCheck => "peer_check_error" });
labels!(Stage { Connection => "connection", Tls => "tls", Http => "http", Validation => "validation", Ipc => "ipc", Worker => "worker", Crypto => "crypto", ListenerRetry => "listener_retry", Snapshot => "snapshot" });
labels!(Outcome {
    Success => "success", Cancelled => "cancelled", Timeout => "timeout", Protocol => "protocol_error",
    Headers => "invalid_headers", Body => "invalid_body", Frame => "invalid_frame", WrongKey => "wrong_key",
    InvalidPoint => "invalid_point", Randomness => "randomness_failure", Crypto => "crypto_failure",
    Connect => "connect_error", Write => "write_error", Read => "read_error", Refused => "refused",
    Eof => "unexpected_eof", Io => "io_error", NotFound => "not_found", Method => "method_not_allowed",
    Unavailable => "unavailable", Other => "other_error"
});
labels!(AcceptClass { Interrupted => "interrupted", Resource => "resource", Network => "network", Other => "other" });
labels!(SnapshotOutcome { Served => "served", Peer => "peer_rejected", PeerCheck => "peer_check_error", Capacity => "capacity_rejected", Write => "write_error", Timeout => "timeout", Listener => "listener_error" });

const BUCKETS_NS: [u64; 12] = [
    1_000_000,
    5_000_000,
    10_000_000,
    25_000_000,
    50_000_000,
    100_000_000,
    250_000_000,
    500_000_000,
    1_000_000_000,
    2_000_000_000,
    5_000_000_000,
    10_000_000_000,
];
const BUCKET_LABELS: [&str; 12] = [
    "0.001", "0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1", "2", "5", "10",
];
const STATUSES: [u16; 6] = [200, 400, 404, 405, 503, 0];

fn add(counter: &AtomicU64, amount: u64) {
    // Saturating counters remain monotonic even on long-lived services.
    let _ = counter.fetch_update(Relaxed, Relaxed, |value| Some(value.saturating_add(amount)));
}

pub struct Metrics {
    events: leelo_telemetry::Emitter,
    start: Instant,
    event_window: AtomicU64,
    suppressed_events: AtomicU64,
    role: Role,
    limit: u64,
    admissions: [AtomicU64; Admission::ALL.len()],
    inflight: AtomicU64,
    completions: [[AtomicU64; Outcome::ALL.len()]; Stage::ALL.len()],
    durations: [[AtomicU64; BUCKETS_NS.len() + 1]; Stage::ALL.len()],
    duration_sum: [AtomicU64; Stage::ALL.len()],
    statuses: [AtomicU64; STATUSES.len()],
    accept_errors: [AtomicU64; AcceptClass::ALL.len()],
    retrying: AtomicU64,
    snapshots: [AtomicU64; SnapshotOutcome::ALL.len()],
}

impl Metrics {
    pub fn new(role: Role, limit: usize) -> Arc<Self> {
        Arc::new(Self {
            events: leelo_telemetry::Emitter::from_env(),
            start: Instant::now(),
            event_window: AtomicU64::new(0),
            suppressed_events: AtomicU64::new(0),
            role,
            limit: limit as u64,
            admissions: std::array::from_fn(|_| AtomicU64::new(0)),
            inflight: AtomicU64::new(0),
            completions: std::array::from_fn(|_| std::array::from_fn(|_| AtomicU64::new(0))),
            durations: std::array::from_fn(|_| std::array::from_fn(|_| AtomicU64::new(0))),
            duration_sum: std::array::from_fn(|_| AtomicU64::new(0)),
            statuses: std::array::from_fn(|_| AtomicU64::new(0)),
            accept_errors: std::array::from_fn(|_| AtomicU64::new(0)),
            retrying: AtomicU64::new(0),
            snapshots: std::array::from_fn(|_| AtomicU64::new(0)),
        })
    }
    pub fn admission(&self, result: Admission) {
        add(&self.admissions[result as usize], 1);
    }
    pub fn enter(self: &Arc<Self>) -> Inflight {
        add(&self.inflight, 1);
        Inflight(self.clone())
    }
    pub fn stage(self: &Arc<Self>, stage: Stage) -> Timer {
        Timer {
            metrics: self.clone(),
            stage,
            start: Instant::now(),
            finished: false,
        }
    }
    pub fn http_status(&self, status: u16) {
        let index = STATUSES
            .iter()
            .position(|candidate| *candidate == status)
            .unwrap_or(STATUSES.len() - 1);
        add(&self.statuses[index], 1);
    }
    pub fn accept_error(&self, error: &std::io::Error) {
        use rustix::io::Errno;
        let class = if error.kind() == std::io::ErrorKind::Interrupted {
            AcceptClass::Interrupted
        } else if matches!(
            error.raw_os_error().map(Errno::from_raw_os_error),
            Some(Errno::MFILE | Errno::NFILE | Errno::NOBUFS | Errno::NOMEM)
        ) {
            AcceptClass::Resource
        } else if matches!(
            error.kind(),
            std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::WouldBlock
        ) || matches!(
            error.raw_os_error().map(Errno::from_raw_os_error),
            Some(
                Errno::NETDOWN
                    | Errno::NETUNREACH
                    | Errno::HOSTUNREACH
                    | Errno::HOSTDOWN
                    | Errno::PROTO
                    | Errno::NOPROTOOPT
                    | Errno::OPNOTSUPP
            )
        ) {
            AcceptClass::Network
        } else {
            AcceptClass::Other
        };
        add(&self.accept_errors[class as usize], 1);
    }
    pub fn retry(self: &Arc<Self>) -> Retry {
        self.retrying.store(1, Relaxed);
        Retry {
            metrics: self.clone(),
            timer: Some(self.stage(Stage::ListenerRetry)),
        }
    }
    pub fn snapshot_outcome(&self, outcome: SnapshotOutcome) {
        add(&self.snapshots[outcome as usize], 1);
    }
    /// Flood-sensitive diagnostics share one event per five-second window; counters retain volume.
    pub fn event(
        &self,
        name: &'static str,
        stage: &'static str,
        outcome: &'static str,
        reason: &'static str,
    ) {
        let window = self.start.elapsed().as_secs() / 5 + 1;
        let previous = self.event_window.load(Relaxed);
        if previous == window
            || self
                .event_window
                .compare_exchange(previous, window, Relaxed, Relaxed)
                .is_err()
        {
            add(&self.suppressed_events, 1);
            return;
        }
        self.lifecycle(name, stage, outcome, reason);
    }
    pub fn lifecycle(
        &self,
        name: &'static str,
        stage: &'static str,
        outcome: &'static str,
        reason: &'static str,
    ) {
        self.events.emit(leelo_telemetry::Event::new(
            self.role.name(),
            name,
            "serve",
            stage,
            outcome,
            reason,
        ));
    }
    fn observe(&self, stage: Stage, outcome: Outcome, nanoseconds: u64) {
        add(&self.completions[stage as usize][outcome as usize], 1);
        let bucket = BUCKETS_NS
            .iter()
            .position(|bound| nanoseconds <= *bound)
            .unwrap_or(BUCKETS_NS.len());
        add(&self.durations[stage as usize][bucket], 1);
        add(&self.duration_sum[stage as usize], nanoseconds);
    }
    /// Prometheus text with a schema-fixed upper bound. Snapshots are approximate under concurrency.
    pub fn snapshot(&self) -> String {
        let mut output = String::with_capacity(48 * 1024);
        let role = self.role.name();
        writeln!(
            output,
            "leelo_telemetry_dropped_total{{role=\"{role}\",signal=\"events\"}} {}",
            self.events.dropped()
        )
        .unwrap();
        writeln!(
            output,
            "leelo_telemetry_suppressed_total{{role=\"{role}\",signal=\"events\"}} {}",
            self.suppressed_events.load(Relaxed)
        )
        .unwrap();
        for admission in Admission::ALL {
            writeln!(
                output,
                "leelo_connections_total{{role=\"{role}\",admission=\"{}\"}} {}",
                admission.name(),
                self.admissions[*admission as usize].load(Relaxed)
            )
            .unwrap();
        }
        writeln!(
            output,
            "leelo_inflight{{role=\"{role}\"}} {}\nleelo_concurrency_limit{{role=\"{role}\"}} {}",
            self.inflight.load(Relaxed),
            self.limit
        )
        .unwrap();
        for stage in Stage::ALL {
            for outcome in Outcome::ALL {
                writeln!(output, "leelo_server_stage_completions_total{{role=\"{role}\",stage=\"{}\",outcome=\"{}\"}} {}", stage.name(), outcome.name(), self.completions[*stage as usize][*outcome as usize].load(Relaxed)).unwrap();
            }
            let mut count = 0u64;
            for (index, bound) in BUCKET_LABELS
                .iter()
                .chain(std::iter::once(&"+Inf"))
                .enumerate()
            {
                count = count.saturating_add(self.durations[*stage as usize][index].load(Relaxed));
                writeln!(output, "leelo_server_stage_duration_seconds_bucket{{role=\"{role}\",stage=\"{}\",le=\"{bound}\"}} {count}", stage.name()).unwrap();
            }
            writeln!(output, "leelo_server_stage_duration_seconds_count{{role=\"{role}\",stage=\"{}\"}} {count}\nleelo_server_stage_duration_seconds_sum{{role=\"{role}\",stage=\"{}\"}} {:.9}", stage.name(), stage.name(), self.duration_sum[*stage as usize].load(Relaxed) as f64 / 1e9).unwrap();
        }
        for (index, status) in STATUSES.iter().enumerate() {
            writeln!(
                output,
                "leelo_http_responses_total{{role=\"{role}\",status=\"{status}\"}} {}",
                self.statuses[index].load(Relaxed)
            )
            .unwrap();
        }
        for class in AcceptClass::ALL {
            writeln!(
                output,
                "leelo_accept_errors_total{{role=\"{role}\",class=\"{}\"}} {}",
                class.name(),
                self.accept_errors[*class as usize].load(Relaxed)
            )
            .unwrap();
        }
        writeln!(
            output,
            "leelo_listener_retrying{{role=\"{role}\"}} {}",
            self.retrying.load(Relaxed)
        )
        .unwrap();
        for result in SnapshotOutcome::ALL {
            writeln!(
                output,
                "leelo_snapshot_connections_total{{role=\"{role}\",outcome=\"{}\"}} {}",
                result.name(),
                self.snapshots[*result as usize].load(Relaxed)
            )
            .unwrap();
        }
        output
    }
}

pub struct Inflight(Arc<Metrics>);
impl Drop for Inflight {
    fn drop(&mut self) {
        self.0.inflight.fetch_sub(1, Relaxed);
    }
}
pub struct Timer {
    metrics: Arc<Metrics>,
    stage: Stage,
    start: Instant,
    finished: bool,
}
impl Timer {
    pub fn finish(mut self, outcome: Outcome) {
        self.record(outcome);
        self.finished = true;
    }
    fn record(&self, outcome: Outcome) {
        self.metrics.observe(
            self.stage,
            outcome,
            self.start.elapsed().as_nanos().min(u64::MAX as u128) as u64,
        );
    }
}
impl Drop for Timer {
    fn drop(&mut self) {
        if !self.finished {
            self.record(Outcome::Cancelled);
        }
    }
}
pub struct Retry {
    metrics: Arc<Metrics>,
    timer: Option<Timer>,
}
impl Retry {
    pub fn finish(mut self, outcome: Outcome) {
        self.timer.take().unwrap().finish(outcome);
    }
}
impl Drop for Retry {
    fn drop(&mut self) {
        self.metrics.retrying.store(0, Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_accounting_and_cardinality_are_bounded() {
        let metrics = Metrics::new(Role::Worker, 8);
        let before = metrics.snapshot();
        let guard = metrics.enter();
        assert_eq!(metrics.inflight.load(Relaxed), 1);
        drop(guard);
        metrics.stage(Stage::Worker).finish(Outcome::Success);
        drop(metrics.stage(Stage::Worker));
        for status in 0..=u16::MAX {
            metrics.http_status(status);
        }
        for outcome in Outcome::ALL {
            metrics.stage(Stage::Crypto).finish(*outcome);
        }
        let after = metrics.snapshot();
        assert_eq!(before.lines().count(), after.lines().count());
        assert!(after.len() < 64 * 1024);
        assert_eq!(
            metrics.completions[Stage::Worker as usize][Outcome::Success as usize].load(Relaxed),
            1
        );
        assert_eq!(
            metrics.completions[Stage::Worker as usize][Outcome::Cancelled as usize].load(Relaxed),
            1
        );
        assert_eq!(metrics.inflight.load(Relaxed), 0);
    }
    #[test]
    fn retry_cancellation_clears_current_state() {
        let metrics = Metrics::new(Role::Frontend, 64);
        let retry = metrics.retry();
        assert_eq!(metrics.retrying.load(Relaxed), 1);
        drop(retry);
        assert_eq!(metrics.retrying.load(Relaxed), 0);
        assert_eq!(
            metrics.completions[Stage::ListenerRetry as usize][Outcome::Cancelled as usize]
                .load(Relaxed),
            1
        );
    }

    #[test]
    fn even_saturated_counters_fit_the_snapshot_wire_bound() {
        let metrics = Metrics::new(Role::Frontend, 64);
        for row in &metrics.completions {
            for counter in row {
                counter.store(u64::MAX, Relaxed);
            }
        }
        for row in &metrics.durations {
            for counter in row {
                counter.store(u64::MAX, Relaxed);
            }
        }
        for counter in &metrics.duration_sum {
            counter.store(u64::MAX, Relaxed);
        }
        assert!(metrics.snapshot().len() < 64 * 1024);
    }
}
