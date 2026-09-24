# Operational observations

Leelo provides optional local events, aggregate metrics, a valid-evaluation probe, and a reconciliation command.
These functions cover the current network-bound implementation.
They do not provide attestation, a fleet inventory service, or a durable central audit service.

## Outcomes

An evaluator response, a recovered credential, a tested credential, and an activated mapping are separate outcomes.
The client emits its terminal success only after the requested credential test or mapping activation succeeds.
Filesystem mounting and application readiness remain separate service checks.

Provider success means that both the VOPRF proof and the wrapped share passed authentication.
`canceled_quorum` means that sufficient factors succeeded before that request completed.
It is not a provider failure.
`not_started` is not an attempt.
`canceled_deadline` and actual provider timeouts are separate observations.
A successful command can include an observed provider failure; it is then a degraded success.
An unattempted provider has unknown health.

The engine report uses fixed arrays and contains no credentials or shares.
Existing engine APIs remain available.
The observed API variants take a caller-owned `OperationReport` that survives failure.
They invoke no logging callback and perform no telemetry I/O.
The verified policy, SSS, and primitive crypto crates have no telemetry dependency.

The 30-second engine budget is not a whole-command deadline.
Enrollment runs separate preparation and recovery operations before storage work.
Synchronous TPM calls cannot be interrupted by that budget.
Measure complete commands and use external service supervision for hangs.

## Local events

Set `LEELO_EVENTS_SOCKET=/run/leelo-observe/events.sock` on the CLI or daemon to enable events.
Unset it to disable delivery.
The emitter sends one bounded nonblocking Unix datagram per event.
It does not retry, flush, or wait for a collector.
Linux attempt-ID generation uses nonblocking kernel entropy.
If entropy is unavailable when the emitter starts, it counts later events as local loss and sends no events for that emitter lifetime.
Daemon snapshots can report this count; a short-lived client can lose all remote observations.
Unlock does not wait for entropy for telemetry.

Schema version 1 contains fixed-vocabulary component, event, operation, stage, outcome, reason, mode, and storage state.
It also contains elapsed duration, software version, provider position, an optional native numeric code, and public state flags.
The emitter adds a random attempt ID, local boot ID when available, sequence number, wall-clock timestamp, and prior delivery-loss count.
Wall-clock timestamps do not establish clock synchronization.
The collector adds receive time and kernel-authenticated sender PID/UID.

No volume UUID, binding ID, device path, URL, submitted key ID, credential, share, seed, private key, envelope, TPM blob, point, proof, or raw error string is exported.
The existing private enrollment journal retains its required local identity fields.
The collector does not copy these fields into metrics.
Attempt and boot IDs are restricted log fields; they are not metric labels.

The daemon records startup, readiness, stop, startup failure, listener transitions, boundary rejection, overload, and internal evaluation failures.
Flood-sensitive diagnostics share a five-second rate limit.
Counters retain the aggregate volume.
SIGKILL, crashes, or power loss can prevent a final event.

The client records operation and phase transitions, provider outcomes, and enrollment milestones.
Command outcome and storage state are separate.
For example, final-journal failure after successful storage commit reports command failure with `storage_state=committed` and `awaiting_boot_test=true`.
Optional event delivery does not change mandatory journal or pending-bundle synchronization.

## Collector deployment

Use separate `leelo-key`, `leelo-http`, and `leelo-collector` accounts.
The collector needs a separate `leelo-observe` group.
Do not add it to `leelo-ipc`, grant it key access, or grant it TPM or disk access.
Give event senders access to the observation socket group.
Explicit UID-to-component pairs control which records the collector accepts:

```sh
leelo-collector events --socket /run/leelo-observe/events.sock \
  --state-dir /var/lib/leelo-observe \
  --source worker:992 --source frontend:991 --source leelod:992
```

The numbers are examples. Use actual local UIDs.
On a client host, use its actual CLI UID, for example `--source client:0`.
The collector requires kernel credentials and the configured component/UID pair.
A permitted frontend cannot report a client result unless the operator explicitly assigns both roles to that UID.
Do not share production identities to make collection work.

Both directories must belong to the collector and must not be writable by group or other users.
Use mode 0750 with the observation group.
The socket has mode 0660.
Event logs have mode 0600; metrics textfiles have mode 0640.
Give the external textfile reader only the permissions needed to read the aggregate files.
Protect the monitoring network and log store separately.

The [collector unit](../crates/leelo-collector/systemd/leelo-events.service) manages the socket directory lifetime.
Provision `/etc/leelo-observe/sources.env`, owned by root, with the configured source arguments:

```text
LEELO_EVENT_SOURCES="--source worker:992 --source frontend:991 --source leelod:992"
```

The collector refuses an existing socket pathname.
Systemd removes its runtime directory when the unit stops.
For a manual run, remove a stale socket only after its owning process has stopped.
Do not make unlock depend on collector startup or successful remote export.

The collector retains two local event logs of at most 16 MiB each, plus one bounded record during rotation.
It repairs a partial final record before appending after restart.
Replay restores only retained history.
Event and attempt deduplication each retain at most 65,536 entries.
An older replay outside these windows can be counted again.
An eviction counter reports this loss of replay coverage.
These logs are best-effort operational records, not permanent audit storage or unlimited exactly-once delivery.
Counters can decrease after restart when older rotated history is no longer available.

Run a separate log agent for central retention, access control, delivery, and inventory integration.
Do not assume that a missing success event proves failure or that an absent failure event proves success.
Keep the enrollment recovery journal as the storage-correctness record.

## Daemon snapshots

Enable the daemon's `--metrics-socket` and `--metrics-uid` pair.
When systemd manages the directory group, also set the trusted numeric `--metrics-gid` to the observation group.
The daemon assigns that group after service-manager directory setup.
The socket uses a separate service-owned directory and observation group.
The collector UID must differ from the worker and its authorized evaluator UID.
The [daemon instructions](../crates/leelod/README.md#local-observations) specify directory and systemd setup.
The worker remains AF_UNIX-only with IP access denied.
No public HTTP metrics or health route is added.
Failure to start the optional snapshot exporter emits `telemetry_failed` and leaves evaluation service available.
There is no fallback to a public or unauthorized metrics socket.

```sh
leelo-collector snapshot --socket /run/leelo-key-metrics/metrics.sock \
  --server-uid 992 --role worker --output /var/lib/leelo-observe/worker.prom
```

The reader checks the server UID, a 64 KiB size bound, a 250 ms total socket deadline, fixed metric fields, and that every sample matches the configured `--role worker|frontend`. The expected role comes from trusted configuration, so an authenticated frontend cannot submit worker metrics.
It replaces the textfile atomically and adds a role-specific snapshot timestamp.
A failed read leaves the prior complete file; alert on its age.
The [snapshot service](../crates/leelo-collector/systemd/leelo-snapshot@.service) also limits whole-process runtime.
For each instance, configure `LEELO_SNAPSHOT_SOCKET`, `LEELO_SERVER_UID`, and `LEELO_SNAPSHOT_ROLE` (`worker` or `frontend`) in root-controlled `/etc/leelo-observe/INSTANCE.env`.
Enable its matching timer.

| Metric family | Meaning |
|---|---|
| `leelo_connections_total` | Admission outcome by daemon role. Includes drops before TLS. |
| `leelo_inflight`, `leelo_concurrency_limit` | Admitted work and configured concurrency limit. |
| `leelo_server_stage_completions_total` | Stage outcome, including TLS, IPC, worker, crypto, and cancellation. |
| `leelo_server_stage_duration_seconds` | Stage duration histogram. |
| `leelo_http_responses_total` | Responses produced; not proof of receipt or unlock. |
| `leelo_accept_errors_total`, `leelo_listener_retrying` | Listener failures and current impairment. |
| `leelo_client_operations_total`, `leelo_client_failures_total` | Observed command outcomes and safe failure categories. |
| `leelo_client_operation_duration_seconds`, `leelo_client_phase_duration_seconds` | Command and phase duration histograms derived from received events. |
| `leelo_provider_attempts_total`, `leelo_provider_duration_seconds` | Attempt outcomes and duration by configured provider position and phase. |
| `leelo_provider_failures_total` | Fixed failure reason by configured provider position and phase. |
| `leelo_unlock_degraded_total` | Successful checks or activations with an observed provider failure. |
| `leelo_telemetry_dropped_total`, `leelo_telemetry_reported_drops_total` | Daemon loss and sender-reported loss. Complete delivery failure can remain unreported. |
| `leelo_collector_*` | Admission, duplicates, replay eviction, registry limits, write failures, and freshness. |

Client provider positions are one-based positions in the trusted local providers configuration.
They are not global provider identities.
Aggregate them only within a stable policy cohort supplied by deployment configuration.
The probe uses the same one-based convention in its configured providers file.
Join these indexes only when both processes use the same stable configuration order.
The collector caps the combined counter/histogram registry at 512 label sets; each histogram expands to a fixed number of samples.
Changing policy/configuration mappings requires corresponding dashboard context.
Outer command phases and inner engine phases overlap. Do not sum them as separate wall-clock intervals.

## Functional probes and fleet reconciliation

Run [leelo-probe](../crates/leelo-probe/README.md) from each required client network.
It performs a real TLS evaluation with a fresh blind and verifies the proof under the configured public pin.
It reports the expiry of the certificate actually observed on that validated connection.
The result includes failure and freshness; a failed run replaces the last-run file.
Schedule probes with a timer, not inside a metrics scrape.
The duration is a last-run gauge, not a cumulative histogram.
Use a dedicated TPM/LUKS canary for storage and TPM coverage.

The Linux reconciliation command accepts two bounded, operator-controlled JSON files.
It exports aggregate counts only:

```sh
leelo-collector reconcile --inventory /etc/leelo-observe/inventory.json \
  --observations /var/lib/management/boot-observations.json \
  --output /var/lib/leelo-observe/fleet.prom
```

Example inventory:

```json
{
  "schema_version": 1,
  "updated_at_ms": 1800000000000,
  "valid_for_seconds": 300,
  "boots": [{
    "target": "critical_service",
    "boot_id": "expected_boot_reference",
    "requested_at_ms": 1800000000000,
    "deadline_ms": 1800000060000
  }],
  "enrollments": [{
    "journal": "/var/lib/leelo/enrollment.jsonl",
    "created_at_ms": 1799990000000,
    "production_boot_test_passed": false
  }]
}
```

Example external observations:

```json
{
  "schema_version": 1,
  "updated_at_ms": 1800000050000,
  "boots": [{
    "target": "critical_service",
    "boot_id": "expected_boot_reference",
    "observed_at_ms": 1800000040000,
    "outcome": "success"
  }]
}
```

Use actual timestamps and externally established boot references.
The deployment's management plane must define what completed activation of all required volumes means and authenticate that observation.
Leelo does not discover this inventory, fetch BMC data, or infer per-volume completion from anonymous evaluator requests.
A copied or delayed success from another boot cannot satisfy the expected boot reference.
Missing, failed, pending, late-success, and stale/unknown states remain distinct.
Conflicting reports with the same observation time produce unknown state.
A successful boot after its deadline remains a deadline miss.
Stale inventory does not remove machines from the denominator.

Journal reconciliation reads only local regular files, not disk metadata or keys.
Inputs must pass the held-file type, ownership, permission, size, local-filesystem, and no-symlink checks.
Use service supervision to bound whole-process runtime; filesystem and kernel scheduling can still stall.
An incomplete journal requires inspection even if a command may have committed before its final write failed.
A complete journal records prior storage verification, not present disk state.
Resume can complete a slot while an earlier journal remains incomplete; resolve that discrepancy through an explicit local inspection and inventory update.
An operator supplies production boot-test status from independent evidence.
This command never mutates a journal, slot, or recovery route.

`leelo_oldest_enrollment_requiring_reconciliation_timestamp_seconds` tracks only incomplete journals.
Separate oldest timestamps track enrollment awaiting a production boot test and unknown enrollment state.
`leelo_oldest_unresolved_enrollment_timestamp_seconds` spans all three categories; use the matching category timestamp and nonzero count for age alerts.

## Alerts and diagnosis

[monitoring/alerts.yml](../monitoring/alerts.yml) contains starter rules.
The thresholds are deployment defaults to tune after load and failure tests.
Configure the external `leelo_expected_probe` inventory with the same `instance,target` labels as probe metrics.
Keep this inventory available independently of the host that runs the probe.
Use normal node/systemd monitoring for missing hosts, service failures, restart loops, OOM, CPU, memory, tasks, and file descriptors.

Dashboards should show these views:

1. Fresh valid-probe results, observed certificate expiry, and network/provider redundancy by site and policy cohort.
2. Confirmed boot success/failure, pending, missing, and unknown counts from the full expected inventory.
3. Command and phase latency, provider outcomes, cancellation, and degraded success.
4. Committed and incomplete enrollment states, unresolved age, and pending boot qualification.
5. Event loss, replay coverage, collector freshness, and inventory freshness.

For a failed boot, first confirm the machine attempted the expected boot.
Check independent management-plane evidence if the client cannot report.
Then inspect the last known stage: network, TPM, credential check, or activation.
For a failed probe, inspect its fixed outcome category, local service metrics, TLS configuration, and recent changes.
For invalid proofs or authentication failures, check public pins and configuration changes before assigning a cause.
For saturation, check request rates and stage durations before changing limits.
For an incomplete enrollment, retain the recovery credential and pending bundle and use the supported local recovery workflow.
Never weaken TPM policy, change a trusted pin automatically, or delete a slot to clear an alert.

A successful evaluation does not prove a usable TPM or a healthy complete threshold policy.
Nested policies require their actual tree and fresh leaf observations; a global healthy-server count is insufficient.
Automated policy-tree health aggregation, central immutable audit retention, authenticated remote fleet reporting, and future attested-mode observations remain deployment or future implementation work.

## Validation and assurance

The [validation report](observability-test-report.md) records local checks and Fedora deployment results.

Run these checks:

```sh
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
bash scripts/test-observability.sh
promtool check rules monitoring/alerts.yml
promtool test rules monitoring/alerts.test.yml
```

The integration script uses disposable software-TPM and regular-file LUKS fixtures.
It runs credential operations with healthy, absent, and full collectors.
It does not activate a real mapping or test encrypted-root initramfs boot.
Daemon tests cover admission, error categories, bounded authorized snapshots, slow readers, and cancellation.
Probe tests use actual TLS connections and validate wrong pins, proofs, trust roots, hostnames, malformed responses, deadlines, and stale-file replacement.
Collector tests cover kernel UID roles, fixed vocabularies, log repair, terminal deduplication, bounded state, and stale/missing inventory.

The existing policy and field-arithmetic proof suites remain separate checks.
They do not prove event delivery, telemetry timing, collector durability, or complete information-flow security.
