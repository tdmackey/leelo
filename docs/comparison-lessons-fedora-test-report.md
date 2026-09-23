# Comparison lessons: Fedora validation

Date: 2026-09-23. This report covers the current comparison-lessons changes on the preserved disposable Fedora evaluator and client. It does not repeat the earlier reboot qualification or claim a new encrypted-root boot test.

The native Fedora workspace build, tests, strict Clippy, formal verification, existing-volume activation, and DNS timeout fixture all passed. The run reused the evaluation key, TPM state, enrollment, LUKS slot, and filesystem. It did not format a volume, enroll a credential, change a slot or key, or extend a PCR.

## Environment and source

Both guests ran Fedora Linux 44 Cloud Edition, kernel `6.19.10-300.fc44.x86_64`, with SELinux Enforcing. Native builds used Rust and Cargo 1.95.0. Other recorded versions were cryptsetup 2.8.8, swtpm 0.10.2, tpm2-tools 5.7, and OpenSSL 3.5.8.

The existing pinned verifier was Verus `0.2026.06.28.1847ab3`, Linux x86-64 release, using Rust 1.96.0. No verifier download was needed.

The staged `Cargo.lock` SHA-256 was `62b0585b2a11f93750531219ef6a66ac000cbbff06f3a07634e597e557502af7`. A 98-entry source manifest covers the root Cargo files and toolchain pin, plus non-Markdown files in `crates/`, `verification/`, and `test-vectors/`. The guest manifest matched the workspace manifest byte for byte. Its SHA-256 was `7408e0d757eb145cdaf17f7d7524140ba45370611ad37583c0fa23dbed2b9ae6`. Documentation was excluded because it was being updated during validation. Installed binary hashes are retained with the version evidence.

## Native checks

| Check | Result |
|---|---|
| `cargo build --workspace --locked` | Passed |
| `scripts/check.sh` | Formatting, all workspace tests, and all-targets Clippy with `-D warnings` passed |
| Workspace tests | 131 unit/integration tests and 4 documentation tests passed; zero failed |
| Explicitly ignored tests | 2 CLI persistence, 6 LUKS, and 1 TPM fixture tests; these were not counted as passes |
| Composed protocol fixture | All 3 tests passed within the workspace total |
| `scripts/verify.sh` | Policy: 28 verified; arithmetic: 38 verified; release: 8 verified; zero errors |

The first test attempt found that the staging helper omitted the new `test-vectors/` directory. That attempt stopped at compilation. The fixture was staged, the helper was corrected, and the complete check then passed. The initial diagnostic is retained separately. The isolated fuzz workspace and the ignored persistence fixtures were validated in other lanes; they were not executed in this Fedora run.

## Live deployment

The [existing-volume observation fixture](../scripts/fedora/guest-observability.sh) passed against the newly built binaries:

- The separate collector UID read authorized worker and frontend snapshots. Both wrong-role requests were rejected without replacing the existing output. A different UID in the observation group received no snapshot.
- The collector could not read the evaluation key or connect to the evaluator socket. The worker retained `RestrictAddressFamilies=AF_UNIX`, IP denial, seccomp filtering, `NoNewPrivileges`, and its resource limits. Both daemon readiness events reached the collector.
- The unprivileged probe completed HTTPS evaluation and VOPRF proof verification. Its certificate expiry exactly matched the leaf certificate from an independent validated TLS connection.
- The existing TPM/LUKS credential passed check-only and actual device-mapper activation. A read-only mount yielded the expected filesystem marker, and the mapping was then closed.
- The new client events distinguished checking from activation, used trusted provider position 1, and reported no sender loss. The collector's schema-rejection count did not increase during that sequence.
- Check-only still succeeded with the collector stopped. Before and after LUKS metadata digests matched. No device-mapper block mapping remained before shutdown.

The [DNS timeout fixture](../scripts/fedora/guest-dns-timeout.sh) discarded six DNS queries in a private mount namespace. Despite a resolver configuration specifying a 30-second timeout and five attempts, the complete CLI process exited with `Timeout` after **3.061 seconds**, exit code 1, without forced termination. It emitted no stdout and did not expose the test hostname. The guest resolver and LUKS metadata remained unchanged.

## Evidence and shutdown

New evidence is retained locally under `.tools/comparison-lessons-test/`; earlier `.tools/observability-test/` evidence was preserved. Separate guest result directories and private mount namespaces also preserved the earlier guest results. The new capture contains bounded events, metrics, probe and command results, service properties, metadata digests, version and binary hashes, source manifests, and test logs. It does not export private keys or full LUKS metadata.

Key files are `fedora-workspace-checks.log`, `fedora-verification.log`, `fedora-evaluator-verify.log`, `fedora-client-validation.log`, `fedora-dns-timeout.log`, `fedora-versions-and-binaries.txt`, `fedora-source-manifest.sha256`, and the `client/`, `evaluator/`, and `dns/` evidence directories.

Both guests shut down cleanly. The evaluator and client QEMU units and both swtpm units were confirmed `inactive`/`dead`; the transient units had been collected. `fedora-shutdown.log` and `fedora-stopped-state.txt` record this state. Guest disks and private TPM state remain preserved for future testing.
