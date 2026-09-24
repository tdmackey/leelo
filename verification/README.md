# Production proofs

The verifier checks the same executable source that Cargo builds. The current
suite checks **28 policy, 38 sharing-arithmetic, and 8 release obligations**, with
zero errors. These 74 obligations are not 74 independent security theorems.
The [current record](assurance-upgrades.json) identifies the checked source hashes.

## Run the verifier

Install Rust 1.96.0 through rustup. The scripts do not change the global default.

| Platform | All proofs | Policy proofs only |
|---|---|---|
| Windows | `pwsh -File scripts/verify.ps1` | `pwsh -File scripts/verify-policy.ps1` |
| Linux | `bash scripts/verify.sh` | `bash scripts/verify-policy.sh` |

For the first run, add `-InstallVerus` on Windows or `--install-verus` on Linux.
The scripts download the specified official archive into `.tools` and check
its pinned SHA-256 before extraction. [toolchain.json](toolchain.json) records
the versions, checksums, and download source.

The scripts use Verus `--no-cheating`. They scan the local proof source for
annotations that bypass verification. No local `assume`, `admit`, `external_body`,
or external specification is permitted. Cargo uses the pinned `vstd` macros to
remove proof and specification code from normal builds.

## Policy decisions and compilation

[policy.rs](policy.rs) includes the actual production files
`crates/leelo-policy/src/verified.rs` and `verified_compile.rs`.

| Production contract | Guarantee |
|---|---|
| Gate and network evaluation | Evaluation agrees with the recursive postorder specification. Invalid thresholds and dangling edges fail. Loops terminate and index operations meet their bounds. |
| Response recording | Only a valid, previously false response position can change to true. Duplicate or invalid responses cause no change. |
| Policy release | The required observations must be present. Attested mode also requires live authorization. A state permits at most one release. |
| Gate copy | Copying preserves the complete gate contents. |
| Source-to-plan certificate | Every accepted plan has the same threshold result as the source tree for every response assignment. It preserves leaf IDs, provider order, thresholds, child order, and edges, and consumes the complete plan. |

`ProductionPolicy::new` validates and compiles a tree, then executes the verified
certificate checker before it returns a policy. A compiler mismatch fails
admission. The compiler traversal is ordinary Rust. Its semantic fidelity is
checked at runtime instead of being a trusted assumption. The checker does not
prove compiler completeness or the validator's unique-ID and size checks.

Sharing, recovery, and decisions use the same private plan. The certificate
proves threshold decision semantics. It does not prove the recursive sharing and
recovery adapters. The source type's derived traits are outside verification.

Tests cover invalid policies, corrupted certificates, 256 generated trees, all
leaf subsets of those trees, leaf order, duplicate responses, surplus shares,
and the mandatory TPM factor. Tests supplement the proof; they do not extend it.

## Field arithmetic and interpolation

[sss.rs](sss.rs) includes the actual `crates/leelo-sss/src/gf256.rs` and
`interpolation.rs` used by splitting and reconstruction.

The multiplication proof establishes agreement with carryless polynomial
multiplication modulo `x^8+x^4+x^3+x+1` (`0x11b`). It also proves agreement between
compact reduction and polynomial long division for every 16-bit input.
The inverse contract proves `mul(a, inverse_nonzero(a)) == 1` for every nonzero
byte. The source uses fixed masked multiplication rounds and a fixed exponent chain.

The interpolation contracts relate production Horner evaluation, Lagrange
weights, and weighted byte sums to their mathematical specifications. A separate
theorem proves recovery for every secret and slope in the mandatory 2-of-2 root
at coordinates 1 and 2.

There is **no general t-of-n reconstruction theorem or probabilistic secrecy
proof**. Public validation, random coefficient generation, 32-byte assembly,
surplus-share checks, and the recursive network sharing adapter remain ordinary
Rust. Tests compare all byte products and nonzero inverses, and compare generated
sharing cases with a separate polynomial long-division oracle.

## Context and release order

[release.rs](release.rs) includes the actual private engine gate in
`crates/leelo-engine/src/release.rs`.

The gate requires the complete 48-byte descriptor context at each transition.
It accepts network, TPM, and payload evidence in that order. The TPM transition
requires the live-authorization flag in attested mode. Release requires a true
deadline observation and can occur only once. Rejected transitions preserve state.

A private consuming `UnlockOperation` owns the authenticated envelope, deadline,
policy session, and release gate. Private evidence values own zeroizing secrets.
The operation creates each value after the corresponding authentication step.
They have no public constructor, `Clone`, `Debug`, or serializer. The descriptor
context is not a per-attempt nonce. Isolation between attempts comes from this
private ownership and the consuming operation, not from context uniqueness.

The proof checks context equality and state transitions. It does **not** prove
that an AEAD tag, VOPRF proof, TPM response, or clock observation is valid. The
private Rust orchestration supplies those facts and remains subject to integration
tests and review. A false caller-supplied observation is outside the theorem.
The production TPM adapter still rejects the unimplemented attested profile.

## Trust boundary

The Rust compiler, Verus translation, SMT solver, and pinned library contracts
remain trusted. No proof establishes cryptographic composition, whole-system
confidentiality, TPM or FFI correctness, secret erasure, or machine-code timing.
Source code without secret-dependent branches does not establish constant-time
machine code. Tests with a software TPM do not qualify hardware or firmware.

When a proof changes, update this description and run the complete verifier.
Do not accept omitted functions, timeouts, or unknown results as a successful
proof. Keep the verifier pointed at the production source.

## Historical results

Earlier records retain their original hashes and scope:

* The [initial Fedora run](../docs/fedora-vm-test-report.md) checked 10 policy and
  11 arithmetic obligations.
* The [documentation recheck](documentation-recheck.json) checked the same counts
  after comment and documentation edits.
* The [architecture-fix record](review-fixes.json) checked 11 policy and
  11 arithmetic obligations after the gate-copy contract was added.

Those records describe earlier source versions. They are not the current proof scope.
