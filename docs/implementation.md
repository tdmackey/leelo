# Implementation and assurance status

Leelo is an executable prototype of the **network-bound** profile. The implementation does not complete the full design.

A verified policy decision cannot validate missing attestation evidence. It also cannot guarantee the correctness of a TPM, library, or kernel.

## Implemented functions

* Rust policy validation requires a local TPM branch and a network threshold subtree. Validation rejects duplicate node IDs, duplicate provider identities, malformed thresholds, and oversized policies.
* Normal Cargo builds use the executable policy functions that contain Verus annotations. The pinned proof runner uses the same functions. Refer to `verification/README.md` for theorem boundaries and tool assumptions.
* Shamir shares contain 32 bytes over GF(256). Coordinates are distinct and nonzero. Coefficients are independent. Share ownership includes zeroization. Arithmetic proofs and exhaustive tests establish separate claims.
* The cryptographic profile uses RFC 9497 P-384 VOPRF, HKDF-SHA384, ChaCha20-Poly1305, and strict Ed25519 verification. The implementation provides fixed wrapper interfaces and published primitive test vectors.
* Signatures authenticate deterministic-CBOR envelopes. Trusted signing keys are external. Token metadata cannot select a credential file, command, or arbitrary URL. Authentication covers node, provider, and key identities, and the LUKS slot association.
* The TPM2-TSS network-bound adapter requires explicit SHA256 PCR equality and restricts use to Unseal. The adapter pins parent and child Names. It uses policy-only objects and salted encrypted sessions. It cleans up the resources that it owns.
* The direct libcryptsetup adapter adds LUKS2 slots, tests credentials, stores tokens, and activates mappings. The adapter does not run shell commands for cryptography or manipulate raw headers.
* The TLS evaluator and client use a separately invoked private-key worker. Secret protection and frontend separation require separate OS identities and private filesystem permissions. The service documentation specifies these requirements.

## Missing functions and assurance gaps

EK certificate and fleet inventory onboarding are not implemented. Quote and event-log appraisal are not implemented. Production live `PolicySigned` authorization and per-binding attested evaluator authorization are not implemented.

The production TPM adapter explicitly rejects `Attested`. Test doubles exercise the policy gate. They do not provide attestation assurance.

Signed PCR update policies and TPM NV rollback control are not implemented. Fleet-wide key lifecycle and revocation are not implemented. Initramfs packaging and a LUKS token shared-library plugin are not implemented.

Enrollment is not an atomic transaction across multiple commands. The transaction manager has no proof of power-loss safety.

Before slot creation, the CLI uses fsync on a signed encrypted pending bundle and its parent directory. `resume-enrollment` authenticates that bundle and recovers the credential. It tests the exact signed slot before token attachment.

The resume operation cannot recreate a slot if the interruption occurred before slot creation. The tool reports failures after slot addition explicitly. It never deletes a recovery slot to compensate for a failure.

Hardware and firmware platforms are not qualified. A power-loss storage test campaign has not been completed. Software-TPM, regular-file LUKS2, and disposable VM data-volume tests provide narrower evidence.

There is no computational proof of the VOPRF/SSS/AEAD composition. There is no probabilistic Shamir secrecy proof linked to executable code. Policy compiler refinement is incomplete. Machine code has no constant-time proof.

The cryptographic backend has no independent audit. The documented assurance limitations of the P-384 candidate remain a release blocker.

## Enrollment and PCR requirements

The prototype CLI uses an explicitly supplied local administrative signing key. It does not implement the remote attested intake service in the target design.

`enroll` records the current digest of the selected PCRs. An update that changes these measurements requires manual recovery and re-enrollment until signed PCR updates are implemented.

PCR11 can differ between enrollment in the running OS and unlock in the initramfs. The default PCR7+11 mask is not a validated boot-phase measurement contract. Do not silently approve new PCR values during boot.

## Boundary contracts

The policy core receives authenticated observations from trusted adapters. The proof establishes the release predicate for those observations. It does not establish that a caller supplied a true observation.

`leelo-engine` checks signatures and AEAD authentication before it supplies these observations. Adversarial tests cover adapter calls and their sequence. Full verification of those operations is incomplete.

Only the named CLI `unlock` operation activates an actual mapping. The `--check-only` option tests the recovered credential without activation. No command prints recovered credentials.

Human recovery routes remain separate OR paths through LUKS. Enrollment preserves these routes.

The design document specifies the intended architecture. This document records implementation scope. A discrepancy is an implementation gap. It does not weaken the target security requirements.

## Completed validation

On 2026-09-22, workspace tests passed on native Windows and Ubuntu 24.04 under WSL2. Strict Clippy and formatting checks also passed.

Dedicated Linux tests used real TPM2-TSS operations with a disposable swtpm. The tests also used actual TLS frontend and worker processes.

The [end-to-end report](e2e-test-report.md) records enrollment, credential recovery, pending-bundle repair, idempotency, and network failure tests. These tests used a temporary LUKS2 image. The initial run did not activate a mapping or reboot.

The subsequent [Fedora 44 two-VM run](fedora-vm-test-report.md) passed those checks and both proof suites natively in Fedora. The run used a dedicated virtual block device. It tested actual device-mapper activation, ext4 persistence, and automatic data-volume unlock after reboot.

Network outage, incorrect trust, signed-token mutation, and changed PCR11 caused automatic unlock to fail. These failures preserved the recovery credential and LUKS metadata.

Evaluator UID separation and key-file and IPC access checks passed with SELinux enforcing. The guest PCR11 was zero during ordinary boot. The evaluator used the `unconfined_service_t` domain.

These results do not establish a UKI measurement policy or custom SELinux confinement. No test used a physical TPM or physical disk. Initramfs encrypted-root boot has not been tested.

The [proof results](../verification/README.md) record 10 policy and 11 arithmetic obligations verified with zero errors. Historical source hashes identify the production files used for those runs. They identify the tested revision before later documentation and source-comment edits.

Adversarial engine tests cover envelope-byte mutation before provider I/O, threshold outages, invalid payload authentication, and missing live authorization. They also cover unsupported-mode rejection before provider I/O.

These results are not an independent audit or a whole-system proof.

The repository provides a GitHub Actions workflow to repeat these checks. The workflow has not run on a hosted runner in this session.
