# Observability validation

Date: 2026-09-23.

The observability changes passed Windows and Linux tests and the disposable Fedora deployment checks.
This report covers the current network-bound implementation.
The [operating instructions](observability.md) describe setup, metric meanings, and limits.

## Local checks

| Check | Result |
|---|---|
| Windows workspace tests | Passed, including compile-fail documentation tests. Linux-only tests are excluded on Windows. |
| Ubuntu 24.04 workspace tests | Passed, including compile-fail documentation tests. Fixture-only TPM and LUKS tests remain explicitly separate. |
| Windows and Linux strict workspace Clippy | Passed. The final collector and telemetry changes also passed scoped checks. |
| Workspace formatting and diff whitespace | Passed. |
| Collector tests after the final review | All 22 Linux tests and 11 portable Windows tests passed. |
| Telemetry tests after the final review | All four Linux tests and three portable Windows tests passed. |
| Prometheus rule validation | All 16 rules and all behavior tests passed. |
| Verus policy and arithmetic suites | 11 policy obligations and 11 arithmetic obligations verified, with zero errors. |

The test run used the locked dependencies.
The existing dependency versions were retained when the new observation tools were added.

The [disposable integration script](../scripts/test-observability.sh) passed with each of these collector conditions:

1. A functioning local collector.
2. An absent collector and socket.
3. A bound collector socket with a full receive queue and no reader.

Each condition ran actual software-TPM and regular-file LUKS enrollment, pending-bundle resume, credential checks, and the expected network failure.
The functioning collector recorded the expected six command outcomes.
It retained the distinction between storage commit and pending production boot qualification.
The test checked authenticated provider outcomes, configuration position 1, preparation and recovery stages, and the exact event field allowlist.
It found no rejected records in the normal sequence.
This fixture does not activate a device-mapper mapping or boot an encrypted root.

## Fedora deployment

The existing Fedora 44 evaluator and client VMs used kernel `6.19.10-300.fc44.x86_64`.
SELinux remained Enforcing.
The test retained the evaluation key, TPM state, enrolled slot, recovery material, and encrypted filesystem.

The first complete Fedora observation run passed 63 tests:

| Target | Passed |
|---|---:|
| CLI | 6 |
| Collector | 20 |
| Probe | 7 |
| Telemetry | 3 |
| Daemon | 23 unit tests and 4 TLS/worker integration tests |

The live deployment checks established these results:

- Worker and frontend readiness events reached a collector with a separate UID.
- The collector read both metrics sockets. It could not read the evaluation key or connect to the evaluator socket.
- A different UID in the observation group could not read a metrics snapshot.
- The worker retained AF_UNIX-only access, IP denial, seccomp filtering, and its resource limits.
- An unprivileged probe completed HTTPS evaluation and proof verification. Its reported expiry matched the leaf certificate from an independent validated TLS connection.
- The existing TPM/LUKS credential passed a check and actual mapping activation. The filesystem marker matched after a read-only mount. The mapping was then closed.
- Client events distinguished credential checking from activation. Provider position was 1. No sender loss or new schema rejection occurred during the normal sequence.
- The credential check still passed with the collector stopped. Before and after LUKS metadata hashes matched.

The deployment test found and resolved a directory-group problem.
The service sandbox correctly prohibited setting the setgid bit.
Systemd also reset a runtime directory's group between pre-start and start commands.
The daemon now assigns the configured observation GID to its validated metrics directory and socket during startup.
The separate collector UID check and the existing service sandbox remain in place.

The reusable [Fedora fixture](../scripts/fedora/guest-observability.sh) checks the existing enrollment without formatting, enrolling, changing slots, extending PCRs, or rotating keys.
Bounded local evidence is retained under `.tools/observability-test/`.
The evidence contains selected events, aggregate snapshots, probe results, service properties, and metadata digests.
It does not contain private keys or full LUKS metadata.

The final Fedora follow-up passed all 22 collector tests and four telemetry tests.
These 26 tests repeat affected parts of the earlier run; they are not 26 additional unique tests.
Correct UID and role pairs read both snapshots.
Both wrong-role cases were rejected, and the prior output files remained byte-for-byte unchanged.
The collector still could not read the key or use the evaluator socket.
The worker sandbox and rejection of an unauthorized snapshot UID also passed again.
Only the collector executable was replaced in this follow-up. The deployed daemon executable was unchanged.
The client and storage configuration were unchanged, and the follow-up ran no storage check or activation command.

The client guest's existing automatic data-unlock unit failed while the evaluator was intentionally unavailable during the follow-up build.
This run does not claim a successful automatic boot unlock.
The earlier explicit credential check and mapping activation results remain separate evidence.
Both guests and both software TPM services are now stopped. Their disks and TPM state remain available for later tests.

## Final review checks

The final review added explicit tests for these cases:

- A snapshot with a valid sender UID but the wrong configured role is rejected before output replacement.
- An emitter without a random attempt ID counts local loss and sends no undeduplicable event. It does not wait for entropy.
- Conflicting boot reports at the same time produce unknown state. A late successful activation remains a deadline miss.
- Incomplete, unknown, and unqualified enrollments have separate age metrics. An old qualification cannot age a new incomplete journal.
- Journal reconciliation rejects symlinks, non-regular files, unsafe ownership or writers, excessive size, aliases, malformed records, changed identities, and invalid phase order.
- Cancellation after quorum and work that never started do not become provider failures.
- A successful proof alone is not an authenticated-share success. A recovered credential alone is not a completed activation.
- Optional metrics setup failure preserves service readiness and valid evaluation. It emits a fixed failure event and does not open a permissive fallback socket.

## Assurance limits

The policy and arithmetic proof sources have these SHA-256 values:

| Source | SHA-256 |
|---|---|
| `crates/leelo-policy/src/verified.rs` | `7b5ace310c54092ad36e1e12fd3233172fa8d6575b3448e0ed42cc2fe820737d` |
| `crates/leelo-sss/src/gf256.rs` | `ce4856935f1dab8f548e10e334c51b4fbc62178f9032c0e9ab446d9d9bfbff28` |

These existing proofs cover their specified policy and arithmetic contracts.
They do not prove the full program, event delivery, process isolation, timing, or absence of information leaks.
The verified crates have no telemetry dependency.

The new events use finite fields and bounded local delivery.
Tests check their field restrictions and failure behavior.
These checks are not a formal noninterference proof or a complete side-channel review.

The events are best-effort records. A crash can lose them, and local retention and deduplication have fixed limits.
Fleet reconciliation requires trusted external inventory and authenticated boot evidence.
This work does not add a central inventory service, permanent audit store, attestation service, or encrypted-root boot qualification.
