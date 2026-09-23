# Architecture review fixes

These changes address the architecture review of commit `590fed8`.
The implementation still supports the network-bound profile.
Production attested authorization remains disabled.

## Recovery and policy

`ProductionPolicy` owns one private compiled plan.
Leaf order, child relationships, share coordinates, and threshold decisions use this plan.
The envelope validator uses the policy's leaf order and checks the derived evaluator key ID.

Enrollment checks the complete generated share set and each network wrapper before signing.
Unlock stops after a sufficient set of authenticated leaves arrives.
Recovery checks all collected shares, including surplus shares in nested branches.
It does not fetch extra leaves solely to check consistency.

The engine permits at most four concurrent network evaluations.
It owns the evaluation futures and cancels pending work after quorum or failure.
The HTTPS adapter applies one deadline across DNS, connection, headers, and the complete response.
Slow body delivery cannot restart that deadline.
The client uses asynchronous DNS. Runtime shutdown cancels its DNS driver tasks.
It does not wait for a blocking system DNS lookup.
Local resolver configuration and hosts-file reads remain synchronous.

Each provider has a five-second response budget.
Enrollment and unlock each have a 30-second operation budget.
The engine checks the budget before releasing a credential.
TPM operations remain synchronous. The engine cannot interrupt a blocked TPM driver call.

Provider failures retain safe categories and public identities.
Successful recovery can report a degraded quorum.
TPM failures retain their operation name and native error information.
Diagnostics do not contain credentials, secret buffers, or response bodies.

## Enrollment and storage

A private CLI module owns enrollment, durable records, and resume.
Endpoint resolution does not create unused enrollment seeds during unlock.
The LUKS adapter owns metadata refresh, capacity checks, and stored-state verification.
It reloads the pinned target and checks its UUID before relevant operations.
Cached token state cannot establish successful attachment.

Preflight checks available token IDs and metadata capacity before adding a slot.
The capacity estimate remains conservative; refer to the [storage contract](../crates/leelo-luks/README.md).
Leelo coordinates its writers through Linux open-file-description locks.
Native cryptsetup writers require separate administrative coordination.
The multi-write enrollment sequence is not globally atomic.

Errors after a slot write identify partial enrollment and preserve the cause.
The pending bundle and original recovery credential remain the recovery route.
No failure path removes a recovery slot or overwrites an unrelated token.

Both administrative and evaluator key creation synchronize file data and parent directories.
Administrative key creation reports a partial private/public pair explicitly.

## Evaluator service

The shared `leelo-protocol` crate owns evaluator messages and public key identity.
The daemon's normal dependencies no longer include the client recovery stack.
The frontend and private key worker remain separate processes with separate OS identities.

The worker sends its readiness notification after key validation and socket setup.
The systemd unit waits for that notification before dependent service startup.
Temporary listener errors use bounded retry delays and safe local diagnostics.

## Verification

The policy proof adds a contract that preserves gate contents during a copy.
The current suites verify 11 policy obligations and 11 finite-field obligations.
The [proof record](../verification/review-fixes.json) identifies the source hashes.
Compiler equivalence, complete Shamir correctness, and end-to-end protocol composition remain unproved.

Focused tests cover quorum cancellation, concurrency limits, complete-response deadlines,
safe failure diagnostics, stale token removal, token capacity, metadata capacity,
writer exclusion, readiness notification, and temporary listener failures.
The storage regression tests operate on disposable regular-file images.
The TPM tests use an explicitly supplied software TPM.

On 2026-09-23, Windows workspace tests passed with 44 tests and four documentation tests.
Formatting and strict Clippy checks passed.
The six explicit LUKS regression tests and real software-TPM tests also passed on Linux.
The existing TLS, TPM, LUKS enrollment, repair, and recovery integration tests passed against these changes.
The [Fedora review-fix run](fedora-review-fixes-test-report.md) also passed on a dedicated virtual block device.
It checked writer exclusion, a second enrollment, preservation of existing slots and tokens,
idempotent resume, actual mapping, and filesystem contents.
Reboot unlock, worker readiness, process isolation, DNS timeout, outage, tamper, and PCR rejection checks passed.
The DNS test measured complete process exit at 3.05 seconds while its server discarded replies.
Refer to the [implementation ledger](implementation.md) and the VM report for platform results and test limits.
No power-loss campaign or physical-TPM qualification is claimed.
