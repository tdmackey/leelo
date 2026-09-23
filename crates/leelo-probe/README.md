# Independent evaluator probe

`leelo-probe` makes one ordinary HTTPS evaluation, validates the returned VOPRF
proof against a trusted public pin, discards the output, and exits. It uses the
same trusted providers JSON as `leelo`: `provider_id`, `key_id`, `public_key`,
HTTPS origin `url`, and `ca_file`. Relative CA paths resolve beside that JSON.
Select one provider by its **one-based index**. Keep this mapping stable and use
a dedicated file for each target. Deployment/location labels belong to the
collector configuration; identities, URLs and paths are never metric labels.

```sh
leelo-probe --config /etc/leelo/providers.json --target 1 \
  --textfile /var/lib/leelo-probe/target-1.prom
```

Run from each required client network. The fixed, public nonproduction input is
domain-separated from envelope inputs and every run samples a new blind. There
is no LUKS, TPM, credential, private evaluation key, or envelope argument. This
probe checks evaluator availability, not unlock or activation availability.

DNS, hostname and CA validation remain enabled. TLS 1.3, no proxies or redirects,
exact protocol framing, bounded configuration/CA reads and the five-second
complete-response deadline come from the ordinary network adapter. Configuration
is at most 32 KiB, contains at most 27 providers, and CA files are at most 64 KiB.
Only operator-controlled regular files should be configured. The systemd unit
adds a whole-process timeout, including local filesystem operations.

The expiry metric is parsed from the **peer leaf certificate observed on that
validated TLS exchange**, not the configured trust bundle. No certificate or
protocol bytes are exported. A failed handshake has no observed expiry. Once a
TLS response arrives, expiry can still be reported if HTTP, framing or proof
verification subsequently fails. `certificate_observed=0` means unknown, not a
long-lived certificate. A successful evaluation without a parseable observed
certificate marks collection incomplete.

The `.prom` file is written to a unique temporary file in the same directory and
atomically replaced, including for handled probe failures. Configure the Node
Exporter textfile collector to read that directory. One writer owns each file.
All metrics are **last-run gauges**, including duration; do not use `rate()` on
them or infer a cumulative request count or latency histogram. Outcome labels
are a closed enum and target is an index from 1 through 27. Exported fields are:

* `leelo_probe_success`: full evaluation/proof verification result.
* `leelo_probe_last_attempt_timestamp_seconds`: latest completed attempt, even
  on failure; alert on age and missing series separately from success.
* `leelo_probe_started_timestamp_seconds`, `leelo_probe_duration_seconds`:
  wall-clock start and monotonic elapsed time.
* `leelo_probe_collection_success`, `leelo_probe_clock_valid`: completeness and
  local clock checks, not evidence of NTP synchronization.
* `leelo_probe_outcome{outcome=...}`: one-hot fixed failure category.
* `leelo_probe_certificate_observed` and, when known,
  `leelo_tls_certificate_not_after_timestamp_seconds`.

There is deliberately no persisted last-success value: old content and previous
target configurations are never trusted. Abrupt termination may leave the prior
complete file, so freshness alerts are mandatory. A textfile-write failure exits
2 and reports `collection_success=false` in the bounded JSON stdout report and
a fixed stderr message; it cannot update an inaccessible metrics destination.
Exit 0 means successful evaluation and complete collection, 1 means a recorded
failed evaluation, and 2 means invalid invocation or incomplete collection.
Configuration/transport messages never include unrestricted error text. Network
transport includes DNS/TCP/TLS failures; it does not claim to distinguish them.

Use the accompanying service/timer templates to schedule and stagger runs. Do
not execute a probe in a scrape handler. Review the interval against the
evaluator query budget. Provision the unprivileged `leelo-probe` account,
read-only provider/CA files, and output directory without granting key-worker,
TPM, or disk access. Enable normal Node Exporter/systemd monitoring as well.

Tests use temporary OpenSSL certificates and real loopback TLS. Run:

```sh
cargo test -p leelo-probe --locked
```
