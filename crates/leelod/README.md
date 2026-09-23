# Leelo evaluator

This executable implements only network-bound mode. It is a prototype and has not had an audit. It does not verify attestation. The executable has three commands:

```text
leelod keygen --key /var/lib/leelo-key/evaluation.key
leelod worker --key /var/lib/leelo-key/evaluation.key --socket /run/leelo-key/evaluator.sock --allow-uid 991
leelod serve --listen 0.0.0.0:8443 --cert /etc/leelo-http/server.crt --tls-key /etc/leelo-http/server.key --worker-socket /run/leelo-key/evaluator.sock
```

The numeric UID above is an example. Replace it with the actual UID of the frontend account. Key generation prints only public JSON fields, `key_id` and `public_key`, as hexadecimal strings. The evaluation key contains exactly 48 secret bytes. The key ID contains the first 32 bytes of SHA-384 over its 49-byte compressed public key. Copy public key material through the trusted enrollment configuration. A remotely discovered advertisement cannot replace a trusted pin.

Run `keygen` as the worker account. The command creates the key exclusively with mode 0600. It never overwrites an existing file. It synchronizes the file and its parent directory before it prints public metadata. Creation and synchronization use the same opened parent directory. Investigate a failed or partial creation before you try another path. The worker rejects a key file with any of these properties:

- A symlink in the final path component.
- A file type other than a regular file.
- An owner different from the worker account.
- Permissions for the group or other users.
- A length other than 48 bytes.

The operator must control parent directories and configured paths. TLS private keys have the same ownership and permission requirements, with a maximum size of 64 KiB. The TLS key must belong to the frontend account.

## Process separation

Create separate `leelo-key` and `leelo-http` OS accounts. Create a shared `leelo-ipc` group. Give only `leelo-key` read access to the evaluation key directory and file. The TLS certificate and key belong to `leelo-http`. Create the socket directory with owner `leelo-key:leelo-ipc` and mode 0750. The worker creates its socket with mode 0660. The kernel supplies the UID of the connecting process. The worker checks that UID against `--allow-uid`. Group membership alone does not permit evaluation access. The group and other users must not have write access to socket directories.

The worker rejects existing socket paths. Use the service manager to manage the lifetime of the private runtime directory. Remove stale sockets only after the worker stops.

The worker reports `READY=1` to `NOTIFY_SOCKET` after key validation, socket creation, and socket permission setup. The frontend reports readiness after TLS configuration and listener setup. Both attempt any configured metrics socket setup before readiness; an optional snapshot setup failure disables that exporter and emits a fixed `telemetry_failed` event while evaluation service continues. Critical key, TLS, listener, permission, and readiness-notification failures still stop startup. Both example units use `Type=notify`. The frontend starts after the worker reports readiness. Standalone processes do not need a notification socket. Startup readiness is not proof of continuing evaluator availability or functioning telemetry.

The same executable supplies both commands. Run the commands as separate processes under separate UIDs. One shared UID does not isolate the evaluation key. That UID can reopen its files and might inspect other processes. The frontend module does not load an evaluation key. It sends only a key ID and a blinded point to the configured socket. A compromised frontend can still request online evaluations while the worker is available. Process separation does not prevent denial of service or a privileged host compromise.

The example units in `systemd/` are templates. They are not installed. Prepare accounts, directories, files, the actual frontend UID, and firewall rules before you install the units. Adjust paths and resource budgets for the target distribution. Do not give the worker network access. Disable core dumps in the deployment configuration. Keep secrets out of swap. Use an external network policy to restrict client access to this network-bound evaluator.

## Protocol and limits

The frontend accepts only `POST /v1/evaluate` with content type `application/vnd.leelo.network-bound-v1`. HTTP/1.1 uses TLS 1.3. The client verifies the certificate and hostname. The protocol has no TLS 0-RTT, HTTP keep-alive, compressed bodies, alternative modes, or version negotiation. The frontend rejects an attested request. It never interprets that request as network-bound.

The binary header is `4c 45 45 4c 01 01 01 00`. Its fields are magic, version 1, suite 1, network-bound mode 1, and reserved zero. A request contains exactly 89 bytes: the header, a 32-byte key ID, and a 49-byte point. A successful response contains exactly 153 bytes: the header, a 49-byte point, and a 96-byte DLEQ proof.

The worker accepts exactly this request over Unix IPC, followed by a write-half-close. A successful IPC response contains byte zero, followed by the network response. A refusal contains byte one. Neither interface serializes secret key objects. The client uses `leelo-engine` to verify the proof against its enrollment pin before it derives a wrapping key.

The frontend permits 64 simultaneous connections, including incomplete TLS handshakes. The handshake and header deadline is two seconds. The total connection deadline is five seconds. The frontend permits at most 16 HTTP headers, an 8 KiB HTTP parser buffer, and an 89-byte body.

The worker permits eight simultaneous connections and uses a two-second IPC deadline. All curve operations have a fixed size. Timeout cancellation does not interrupt a synchronous curve operation. Fixed operation sizes and concurrency limits restrict that work. The frontend and worker refuse excess work. They do not keep unlimited queues. These resource limits do not provide a cumulative cryptographic-query budget or a rate limit for each client.

Temporary accept errors do not stop a listener. The listener delays retries from 50 milliseconds to a maximum of one second. Local counters record every retry, current impairment, and its duration. Rate-limited events report listener transitions. Diagnostics contain no request data. Unrecoverable listener errors stop the service.

A change to an evaluation key invalidates old bindings. This prototype holds one evaluation key per worker and has no rotation registry. Keep old workers available at separately configured endpoints while you explicitly reenroll dependent volumes. TLS certificate renewal does not change the evaluation key.

## Local observations

Each process keeps fixed arrays of saturating atomic counters and duration buckets. Updating an observation performs no I/O and allocates no request-dependent storage. Stage guards record one terminal observation, including cancellation when a surrounding deadline drops a future. These observations cannot authorize or change an evaluation. Counters reset on process restart and snapshots are approximate under concurrent updates.

Enable an aggregate snapshot using both `--metrics-socket /run/leelo-key-metrics/metrics.sock` and `--metrics-uid COLLECTOR_UID` (use a separate directory for the frontend). The collector UID must differ from the service UID and, on the worker, from the authorized frontend UID. The parent directory must already be owned by the service UID and must not be writable by its group or others. Use an independent `leelo-observe` group for telemetry and a dedicated service-owned mode-0750 directory. Set `--metrics-gid OBSERVE_GID` to assign that numeric group to the validated metrics directory and socket during daemon startup, after systemd prepares runtime directories. Without this optional flag, the socket uses the directory's existing group. The daemon sets the socket to mode 0660. The service must have the observation group in `SupplementaryGroups`; the kernel enforces the group assignment, no setgid directory is needed, and `RestrictSUIDSGID=yes` remains enabled. Do not reuse the evaluator socket or key directory for metrics, add the collector to `leelo-ipc`, or grant it key-file access.

The optional `systemd/leelo-key-observability.conf` and `systemd/leelo-http-observability.conf` templates configure these directories under service-manager lifetime control. They are not installed automatically. Provision the `leelo-observe` group, a separate collector account, and a root-controlled `/etc/leelo-observe/collector.env` containing numeric `LEELO_COLLECTOR_UID` and `LEELO_COLLECTOR_GID` (the latter is the `leelo-observe` GID). Make the collector a member of `leelo-observe` only. The templates add the service accounts to that observation group without changing the evaluator socket group, evaluation UID authorization, private key permissions, or the worker's AF_UNIX-only/no-IP sandbox. Match `ExecStart` paths and flags to the deployment. The collector must separately create its protected datagram socket if event collection is enabled. Snapshot setup errors leave the exporter disabled with no permissive fallback; use snapshot freshness and the fixed failure event to detect this independently of service readiness.

A collector connects to the metrics socket, sends nothing, and reads a Prometheus text snapshot through EOF. Kernel peer credentials must match the configured UID before serialization. The format contains only fixed names/labels and numeric samples; even saturated counters fit within 64 KiB. There are at most two concurrent snapshot writers, each with a 100 ms write deadline. Metrics requests do not evaluate a point or read a key. Existing socket paths are never removed automatically; systemd removes the dedicated runtime directory on stop. Exported families are:

| Family | Meaning and bounded labels |
|---|---|
| `leelo_connections_total` | One OS-accepted connection outcome by `role`, `admission` (admitted, capacity rejected, peer rejected, peer-check error). |
| `leelo_inflight`, `leelo_concurrency_limit` | Current admitted evaluation work and its configured limit by `role`; frontend limit 64, worker limit 8. |
| `leelo_server_stage_completions_total` | Terminal local outcome by `role`, `stage`, `outcome`; connection, TLS, HTTP, validation, IPC, worker, crypto, listener retry, snapshot. |
| `leelo_server_stage_duration_seconds` | Fixed duration histogram by `role`, `stage`; buckets resolve 1 ms through 10 s, including the 2 s and 5 s deadlines. |
| `leelo_http_responses_total` | Produced responses by `role`, `status`: 200, 400, 404, 405, 503, or 0 for other status codes. This does not prove client receipt. |
| `leelo_accept_errors_total`, `leelo_listener_retrying` | Listener errors by fixed `class` and current impairment by `role`. |
| `leelo_snapshot_connections_total` | Snapshot served, peer/credential rejection, capacity rejection, write failure, timeout, or listener failure by `role`, `outcome`. |
| `leelo_telemetry_dropped_total`, `leelo_telemetry_suppressed_total` | Best-effort event delivery losses and deliberate diagnostic rate limiting by `role`, `signal`. |

Outcome categories distinguish framing, wrong key, invalid point, entropy/crypto failure, IPC connect/read/write/refusal/empty/invalid reply, timeout, and cancellation. Worker refusal remains generic across the process boundary. The frontend cannot infer its cause. Public HTTP behavior remains unchanged, including generic 400/503 and pre-TLS admission drops. A synchronous curve evaluation cannot be preempted by a Tokio timeout; its runtime is measured separately.

Set `LEELO_EVENTS_SOCKET` to a protected local Unix datagram collector socket to emit allowlisted structured events through `leelo-telemetry`. No remote export or retry is performed by the daemon. Service lifecycle events are unsampled; flood-sensitive diagnostics share a maximum of one event per five-second window, with aggregate counters retaining volume. A full/missing sink drops the event and increments a loss counter. Normal SIGTERM/SIGINT records a stop event without flushing or waiting for collection; crashes and SIGKILL can lose final observations. Use service-manager state and collector freshness as independent evidence.

No submitted key IDs, IPs, URLs, paths, request bodies, points, proofs, or secret objects enter metrics or events. Network-bound requests contain no authenticated device or volume identity. A successful server response is not an unlock record. Use a separately configured valid-evaluation probe with the trusted public pin for continuing functionality, and actual client activation evidence for unlocks. No public health or metrics route is added.

## Tests

Run `cargo test -p leelod -p leelo-net -p leelo-protocol` on Linux. Tests cover key-file permissions, symlinks, lengths, malformed IPC, and exact message framing. They also test actual child-process HTTPS-to-worker evaluation with proof verification.

The TLS test uses the `openssl` executable to create temporary certificates. The test runs services only on loopback. It removes temporary files and child processes. It checks wrong certificate trust, a wrong hostname, TLS 1.2, unsupported modes, and oversized bodies. All test processes use the same UID. These tests do not establish deployment isolation between OS users.

Tests also check worker readiness, private file creation, transient accept retries, capped retry delays, and retry cancellation. A real TLS server sends a slow response to check the complete-response deadline. The shared `leelo-protocol` crate tests exact message lengths and required header fields.
