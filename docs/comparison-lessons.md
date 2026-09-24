# Changes from the VOPRF and OPAQUE reviews

Leelo keeps its fixed RFC 9497 P-384 profile. These changes apply engineering
lessons from the reviewed implementations. They do not add OPAQUE or replace the
Leelo protocol.

## One operation owns recovery

The engine now delegates recovery to a private consuming `UnlockOperation`.
It owns the authenticated envelope, absolute deadline, policy session, and release
gate. Private evidence values hold authenticated network and TPM shares and the
final payload. Their secret fields use zeroizing ownership. The values have no
public constructor, `Clone`, `Debug`, or serializer.

The existing public unlock operation remains simple. It returns a credential only
after all authentication, target, policy, and deadline checks succeed. The final
gate checks the full 48-byte descriptor context, transition order, required
live-authorization flag, and release at most once. This context is not a fresh
attempt identifier. The private evidence constructors and consuming operation
prevent callers from transferring evidence between attempts.

This change does not implement the attested profile. A future attested operation
must also own its TPM session, challenge, blind requests, verified grant, and
deadline. The production adapter continues to reject that mode.

## Proofs extend into production data flow

The policy constructor executes a verified source-to-plan certificate checker.
For every response assignment, an accepted plan has the same decision as the
source tree. The checker also validates leaf IDs, provider order, thresholds,
child order, edges, and complete plan consumption. A compiler defect that changes
these properties causes policy admission to fail.

The arithmetic suite now proves nonzero field inversion, production polynomial
evaluation and interpolation kernels, and recovery for every secret and slope
in the mandatory 2-of-2 root. The engine suite proves context-bound release order.

The current verifier reports **28 policy, 38 sharing-arithmetic, and 8 release
obligations, with zero errors**. All use the production source and
`--no-cheating`. Read the [exact contracts and trust boundary](../verification/README.md).
The [source record](../verification/assurance-upgrades.json) contains hashes.

General t-of-n reconstruction, Shamir secrecy, cryptographic composition, trusted
adapter observations, monotonic-clock behavior, and the complete Rust orchestration
remain outside these proofs. The compiler traversal remains ordinary Rust; the
verified admission check establishes its accepted result's decision semantics.

## Complete fixtures and generated malformed inputs

The [frozen protocol vector](../test-vectors/README.md) records the descriptor,
signed envelope, context and leaf hashes, VOPRF request and response, derived
keys, encrypted shares, final credential, and LUKS token. Tests compare all frozen
values, recover through the production engine with fresh blinds, and reject
re-signed context, provider, TPM object, and payload mutations.

`scripts/check-protocol-vector.py` independently checks composition with Python
and OpenSSL-backed cryptography. It supplies a separate CBOR codec, polynomial
arithmetic, and framing calculation. It checks signatures, HKDF outputs, and AEAD
payloads. It takes the VOPRF output as an explicit input; it is not a second VOPRF
implementation. The TPM blob is a synthetic fixture. All fixture secrets are public.

The isolated [fuzz workspace](../fuzz/README.md) has five targets: envelopes,
evaluator wire frames, cryptographic encodings, LUKS token codecs, and bounded
policy construction. Envelope fuzzing also signs arbitrary bodies with a fixed
test key so malformed input reaches the authenticated parser. No production
authentication bypass is added. The same harness functions run as deterministic
seed, truncation, mutation, boundary, and generated-input regressions.

The fuzz workflow runs short coverage-guided AddressSanitizer campaigns and keeps
failure artifacts. These runs check that the harness works. They do not establish
comprehensive parser coverage or the absence of bugs.

## Failures beneath the public API

Each VOPRF blind or proof operation first obtains a fresh 256-bit seed through the
fallible OS entropy API. A private ChaCha20 stream then supplies the upstream
infallible RNG interface. The seed and stream state zeroize on drop. Tests force
entropy failure in both operations and require an error without an output.
The adapter exposes no public seed injection, fallback source, or shared stream.
The finite stream cannot wrap. Exhaustion of the upstream infallible interface
is an invariant failure; normal operations consume only a small part of the stream.

A private enrollment journal owns the persistence sequence. Its test-only I/O
adapter injects partial writes, create failures, file-sync failures, and
directory-sync failures against real temporary files. The storage callback cannot
run until the pending bundle and prepared record are durable. Post-commit journal
failure preserves the committed state and pending bundle.

`bash scripts/test-enrollment-persistence.sh` includes explicit tests with
disposable regular-file LUKS2 images. They reopen the target, recover the retained
signed bundle, repeat token attachment, and test the old recovery credential.
The script does not accept a host disk path. These tests establish error handling;
they do not prove filesystem or hardware behavior during a power loss.

Existing engine and TPM tests continue to check unavailable factors, deadlines,
cancellation, and authorization failure. The patched asynchronous DNS adapter also
has a regression that observes a real query, cancels it, and checks that retries stop.

## Dependency assurance is routine

The [dependency workflow](../.github/workflows/dependencies.yml) checks locked
graphs on changes and weekly against the current RustSec database. It also checks
sources, licenses, version requirements, and forbidden VOPRF features. Exceptions
must be specific and reviewed. See the [dependency policy](dependency-policy.md).

The first scan found advisories in the old Hickory dependency and an unmaintained
PEM parser. The transport now uses patched Hickory through reqwest's custom
resolver interface. PEM parsing uses the maintained rustls API. No advisory
exception was added. Duplicate incompatible crate generations remain visible
warnings, as documented in the policy.

## Validation

Native Windows workspace tests (86 tests and four documentation tests), strict
Clippy, and formatting passed. The pinned verifier passed all 74 obligations.
The frozen protocol tests and the independent Python composition check passed.

On Ubuntu 24.04 under WSL, all five persistence tests passed. They cover 20
pre-commit I/O failures, four failures of the final journal after a real LUKS2
commit, unchanged LUKS metadata when the prepared-record sync fails, exclusive
file preservation, and successful ordering. The tests use a synthetic TPM adapter
and real envelope authentication, VOPRF, filesystem I/O, and libcryptsetup.
Strict CLI Clippy also passed on Linux.

The [fuzz smoke record](../fuzz/smoke-result.json) reports 2,000 inputs for each
of five targets under AddressSanitizer, with no crashes. Deterministic fuzz
regressions and strict Clippy passed on Windows and Linux. These short runs are
harness checks, not a completed security fuzzing campaign.

The locked production and enabled fuzz dependency graphs passed cargo-deny
advisory, source, license, and feature checks. No advisory was suppressed.
Documented duplicate-generation warnings remain visible.

The [Fedora validation](comparison-lessons-fedora-test-report.md) passed 131
workspace tests and four documentation tests, formatting, strict Clippy, and
all 74 verifier obligations. Live checks passed for TPM/LUKS credential recovery,
mapping activation, filesystem content, evaluator isolation, collector outage,
and bounded DNS failure. The run preserved existing keys, slots, tokens, PCR
state, and LUKS metadata.

The hosted GitHub Actions workflows have not run in this session. No independent
cryptographic audit, hardware qualification, or full attested protocol proof is
claimed.
