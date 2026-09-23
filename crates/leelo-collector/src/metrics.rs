use leelo_telemetry::Record;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt::Write;

const MAX_SERIES: usize = 512;
const MAX_REPLAY: usize = 65_536;
const BUCKETS: [f64; 9] = [0.005, 0.025, 0.1, 0.5, 1.0, 2.0, 5.0, 15.0, 30.0];
type EventId = (u32, [u8; 16], u64);
type AttemptId = (u32, [u8; 16]);

#[derive(Default)]
struct Attempt {
    reported_drops: u64,
    terminal: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Received {
    pub source_uid: u32,
    pub source_pid: u32,
    pub received_at_ms: u64,
    pub record: Record,
}

#[derive(Default)]
struct Histogram {
    buckets: [u64; 9],
    count: u64,
    sum: f64,
}

#[derive(Default)]
pub struct Metrics {
    seen: BTreeSet<EventId>,
    order: VecDeque<EventId>,
    counters: BTreeMap<String, u64>,
    histograms: BTreeMap<String, Histogram>,
    attempts: BTreeMap<AttemptId, Attempt>,
    attempt_order: VecDeque<AttemptId>,
    reported_drops: u64,
    replay_evictions: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub duplicates: u64,
    pub overflow: u64,
    pub write_failures: u64,
    pub last_received_ms: u64,
}

impl Metrics {
    /// Deduplicate within the bounded local replay window. No identifier is a metric label.
    pub fn accept(&mut self, received: &Received) -> bool {
        let record = &received.record;
        if !record.valid() {
            self.rejected = self.rejected.saturating_add(1);
            return false;
        }
        if let Some(id) = record.attempt_id {
            let key = (received.source_uid, id, record.sequence);
            if self.seen.contains(&key) {
                self.duplicates = self.duplicates.saturating_add(1);
                return false;
            }
            let attempt_id = (received.source_uid, id);
            let terminal = record.component == "client" && record.event == "operation_completed";
            if terminal
                && self
                    .attempts
                    .get(&attempt_id)
                    .is_some_and(|attempt| attempt.terminal)
            {
                // A new sequence must not turn a second or contradictory terminal
                // observation into another completed operation.
                self.rejected = self.rejected.saturating_add(1);
                return false;
            }
            self.seen.insert(key);
            self.order.push_back(key);
            if self.order.len() > MAX_REPLAY
                && let Some(old) = self.order.pop_front()
            {
                self.seen.remove(&old);
                self.replay_evictions = self.replay_evictions.saturating_add(1);
            }
            if !self.attempts.contains_key(&attempt_id) {
                if self.attempt_order.len() == MAX_REPLAY
                    && let Some(old) = self.attempt_order.pop_front()
                {
                    self.attempts.remove(&old);
                    self.replay_evictions = self.replay_evictions.saturating_add(1);
                }
                self.attempt_order.push_back(attempt_id);
            }
            let attempt = self.attempts.entry(attempt_id).or_default();
            self.reported_drops = self
                .reported_drops
                .saturating_add(record.dropped_before.saturating_sub(attempt.reported_drops));
            attempt.reported_drops = attempt.reported_drops.max(record.dropped_before);
            attempt.terminal |= terminal;
        } else {
            self.rejected = self.rejected.saturating_add(1);
            return false;
        }
        self.accepted = self.accepted.saturating_add(1);
        self.last_received_ms = self.last_received_ms.max(received.received_at_ms);
        if record.component != "client" {
            return true;
        }
        let operation = record.operation.as_str();
        if ![
            "enroll",
            "resume",
            "resume_enrollment",
            "check",
            "activate",
            "keygen",
            "inspect",
            "pcr_digest",
        ]
        .contains(&operation)
        {
            return true;
        }
        match record.event.as_str() {
            "operation_completed" => {
                self.increment(format!("leelo_client_operations_total{{operation=\"{operation}\",mode=\"{}\",outcome=\"{}\"}}", record.mode, record.outcome));
                self.observe(
                    format!("leelo_client_operation_duration_seconds{{operation=\"{operation}\""),
                    record.duration_seconds,
                );
                if record.outcome == "failure" {
                    self.increment(format!("leelo_client_failures_total{{operation=\"{operation}\",stage=\"{}\",reason=\"{}\"}}", record.stage, record.reason));
                }
                if record.degraded
                    && record.outcome == "success"
                    && ["check", "activate"].contains(&operation)
                {
                    self.increment("leelo_unlock_degraded_total".into());
                }
            }
            "phase_completed" => self.observe(
                format!(
                    "leelo_client_phase_duration_seconds{{operation=\"{operation}\",stage=\"{}\"",
                    record.stage
                ),
                record.duration_seconds,
            ),
            "provider_completed" if record.outcome != "not_started" => {
                if let Some(index) = record.provider_index {
                    self.increment(format!("leelo_provider_attempts_total{{provider=\"{index}\",phase=\"{}\",outcome=\"{}\"}}", record.stage, record.outcome));
                    if record.outcome == "failed" {
                        self.increment(format!("leelo_provider_failures_total{{provider=\"{index}\",phase=\"{}\",reason=\"{}\"}}", record.stage, record.reason));
                    }
                    self.observe(
                        format!(
                            "leelo_provider_duration_seconds{{provider=\"{index}\",phase=\"{}\"",
                            record.stage
                        ),
                        record.duration_seconds,
                    );
                }
            }
            _ => {}
        }
        true
    }

    fn increment(&mut self, key: String) {
        if self.counters.len() + self.histograms.len() >= MAX_SERIES
            && !self.counters.contains_key(&key)
        {
            self.overflow = self.overflow.saturating_add(1);
            return;
        }
        let counter = self.counters.entry(key).or_default();
        *counter = counter.saturating_add(1);
    }

    fn observe(&mut self, key: String, duration: f64) {
        if self.counters.len() + self.histograms.len() >= MAX_SERIES
            && !self.histograms.contains_key(&key)
        {
            self.overflow = self.overflow.saturating_add(1);
            return;
        }
        let histogram = self.histograms.entry(key).or_default();
        histogram.count = histogram.count.saturating_add(1);
        histogram.sum = (histogram.sum + duration).min(f64::MAX);
        for (index, limit) in BUCKETS.iter().enumerate() {
            if duration <= *limit {
                histogram.buckets[index] = histogram.buckets[index].saturating_add(1);
            }
        }
    }

    pub fn render(&self, now_ms: u64) -> String {
        let mut out = format!(
            "leelo_collector_events_total{{outcome=\"accepted\"}} {}\nleelo_collector_events_total{{outcome=\"rejected\"}} {}\nleelo_collector_events_total{{outcome=\"duplicate\"}} {}\nleelo_collector_series_rejected_total {}\nleelo_collector_write_failures_total {}\nleelo_collector_last_event_timestamp_seconds {}\nleelo_collector_snapshot_timestamp_seconds {}\n",
            self.accepted,
            self.rejected,
            self.duplicates,
            self.overflow,
            self.write_failures,
            self.last_received_ms as f64 / 1000.0,
            now_ms as f64 / 1000.0
        );
        for (key, value) in &self.counters {
            let _ = writeln!(out, "{key} {value}");
        }
        let _ = writeln!(
            out,
            "leelo_telemetry_reported_drops_total {}",
            self.reported_drops
        );
        let _ = writeln!(
            out,
            "leelo_collector_replay_state_evictions_total {}",
            self.replay_evictions
        );
        for (key, histogram) in &self.histograms {
            let (name, labels) = key.split_once('{').expect("internal histogram key");
            for (limit, count) in BUCKETS.iter().zip(histogram.buckets) {
                let _ = writeln!(out, "{name}_bucket{{{labels},le=\"{limit}\"}} {count}");
            }
            let _ = writeln!(
                out,
                "{name}_bucket{{{labels},le=\"+Inf\"}} {}\n{name}_count{{{labels}}} {}\n{name}_sum{{{labels}}} {}",
                histogram.count, histogram.count, histogram.sum
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn received(sequence: u64, event: &str, outcome: &str) -> Received {
        let record = serde_json::from_value(serde_json::json!({
            "schema_version":1,"component":"client","event":event,"operation":"activate",
            "stage":"recover","outcome":outcome,"reason":"none","duration_seconds":0.1,
            "mode":"network_bound","provider_index":1,"storage_state":"not_applicable",
            "awaiting_boot_test":false,"degraded":false,"native_code":null,"software_version":"0.1.0",
            "attempt_id":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"boot_id":null,
            "sequence":sequence,"unix_time_ms":1000,"dropped_before":0
        })).unwrap();
        Received {
            source_uid: 42,
            source_pid: 10,
            received_at_ms: 1000,
            record,
        }
    }

    #[test]
    fn canceled_and_unstarted_work_do_not_become_provider_failures() {
        let mut metrics = Metrics::default();
        assert!(metrics.accept(&received(0, "provider_completed", "canceled_quorum")));
        assert!(metrics.accept(&received(1, "provider_completed", "not_started")));
        assert!(!metrics.accept(&received(0, "provider_completed", "canceled_quorum")));
        let output = metrics.render(1000);
        assert!(output.contains("outcome=\"canceled_quorum\"} 1"));
        assert!(!output.contains("not_started"));
        assert!(!output.contains("outcome=\"failed\""));
        assert!(!output.contains("attempt_id"));
    }

    #[test]
    fn labels_cannot_grow_the_registry_without_bound() {
        let mut metrics = Metrics::default();
        for sequence in 0..2000 {
            // The decoder's finite vocabulary is a separate boundary. Exercise
            // the registry bound directly, including future schema extensions.
            metrics.increment(format!("counter_{sequence}"));
        }
        assert!(metrics.counters.len() + metrics.histograms.len() <= MAX_SERIES);
        assert!(metrics.overflow > 0);
    }

    #[test]
    fn one_attempt_cannot_report_multiple_or_contradictory_terminal_outcomes() {
        let mut metrics = Metrics::default();
        assert!(metrics.accept(&received(0, "operation_completed", "success")));
        assert!(!metrics.accept(&received(0, "operation_completed", "success")));
        assert!(!metrics.accept(&received(1, "operation_completed", "success")));
        assert!(!metrics.accept(&received(2, "operation_completed", "failure")));
        assert_eq!(metrics.accepted, 1);
        assert_eq!(metrics.duplicates, 1);
        assert_eq!(metrics.rejected, 2);
        let output = metrics.render(1000);
        assert!(output.contains("outcome=\"success\"} 1"));
        assert!(!output.contains("leelo_client_operations_total{operation=\"activate\",mode=\"network_bound\",outcome=\"failure\"}"));
        // Same random identifier from a different authenticated source is distinct.
        let mut other = received(0, "operation_completed", "success");
        other.source_uid = 43;
        assert!(metrics.accept(&other));
    }

    #[test]
    fn replay_and_loss_tracking_remain_bounded_and_keep_accepting_new_attempts() {
        let mut metrics = Metrics::default();
        for index in 0..MAX_REPLAY + 2 {
            let mut event = received(0, "phase_completed", "success");
            let mut id = [0; 16];
            id[..8].copy_from_slice(&(index as u64).to_be_bytes());
            event.record.attempt_id = Some(id);
            event.record.dropped_before = 1;
            assert!(metrics.accept(&event));
        }
        assert_eq!(metrics.seen.len(), MAX_REPLAY);
        assert_eq!(metrics.order.len(), MAX_REPLAY);
        assert_eq!(metrics.attempts.len(), MAX_REPLAY);
        assert_eq!(metrics.attempt_order.len(), MAX_REPLAY);
        assert_eq!(metrics.reported_drops, MAX_REPLAY as u64 + 2);
        assert!(metrics.replay_evictions > 0);
    }

    #[test]
    fn counters_saturate_and_reported_loss_counts_only_new_information() {
        let mut metrics = Metrics::default();
        let mut event = received(0, "phase_completed", "success");
        event.record.dropped_before = 5;
        assert!(metrics.accept(&event));
        event.record.sequence = 1;
        event.record.dropped_before = 3;
        assert!(metrics.accept(&event));
        assert_eq!(metrics.reported_drops, 5);
        event.record.sequence = 2;
        event.record.dropped_before = 7;
        assert!(metrics.accept(&event));
        assert_eq!(metrics.reported_drops, 7);
        metrics.accepted = u64::MAX;
        event.record.sequence = 3;
        assert!(metrics.accept(&event));
        assert_eq!(metrics.accepted, u64::MAX);
        metrics.counters.insert("test".into(), u64::MAX);
        metrics.increment("test".into());
        assert_eq!(metrics.counters["test"], u64::MAX);
    }
}
