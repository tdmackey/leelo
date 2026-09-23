# Policy and arithmetic proofs

## Run the verifier

Install Rust 1.96.0 through rustup before you run the proof scripts.
The scripts do not change the global default toolchain.

To check the policy contracts, use the command for your platform:

| Platform | Command |
|---|---|
| Windows | `pwsh -File scripts/verify-policy.ps1` |
| Linux | `bash scripts/verify-policy.sh` |

To check both the policy contracts and finite-field arithmetic, use one of these commands:

| Platform | Command |
|---|---|
| Windows | `pwsh -File scripts/verify.ps1` |
| Linux | `bash scripts/verify.sh` |

For the first run, add `-InstallVerus` on Windows or `--install-verus` on Linux.
This option downloads the specified official archive into `.tools`.
The script checks the specified SHA-256 checksum before it extracts the archive.
`toolchain.json` records the versions, checksums, and official download source.

The scripts use Verus `--no-cheating` mode.
They also check the local source for annotations that bypass the proof.

## Production policy source

`policy.rs` includes **the actual executable file** `crates/leelo-policy/src/verified.rs`.
Cargo compiles the same file with the specified `vstd` macros.
These macros remove proof and specification code from normal Rust builds.
The proof build does not use a copy or a replacement implementation.
The source has no local `assume`, `admit`, `external_body`, or external specification.

The first native Windows run reported **10 verified, 0 errors**.
The run used Verus `0.2026.06.28.1847ab3`, Rust `1.96.0-x86_64-pc-windows-msvc`, and the supplied Z3 solver.
The proof covers these contracts:

| Production function | Verified contract |
|---|---|
| `evaluate_gate` | The result agrees with the specified threshold and leaf rules. The function rejects zero thresholds, oversized thresholds, and dangling edges. The loop terminates. Arithmetic operations and index operations meet their safety requirements. |
| `evaluate_network` | The result equals the final value of the recursive postorder specification. This contract includes rejection of an empty program. |
| `record_response` | The function accepts an observation only if its index is in range and its previous value is false. It changes only that value to true. A duplicate or invalid index causes no change to the response vector. |
| `can_release` | The result is true if and only if all required observations are present and no release occurred. Required observations are envelope, TPM, network, and root authentication. Attested mode also requires the live-authorization observation. |
| `try_release` | The function permits release if and only if the release predicate was true. It changes only the released flag. The same state cannot permit a second release. |

The verifier count includes specification and termination obligations.
The count does not identify ten independent security theorems for the full design.
The proof does not establish security for the complete program.

The [Fedora 44 VM run](../docs/fedora-vm-test-report.md) also ran both proof scripts on native Linux.
That run used the specified Verus release and Rust 1.96.0.
It reported **10 policy and 11 arithmetic obligations verified, zero errors**.
The report records the production source hashes for that run.
It separates the VM integration results from the proof claims.

The [documentation recheck](documentation-recheck.json) records the proof run after the Simplified Technical English rewrite.
Both proof suites passed again with 10 policy and 11 arithmetic obligations, and zero errors.
The record contains the new source hashes.
Earlier result files and the Fedora report retain the hashes from their original runs.

## Proof limits and assumptions

* `ProductionPolicy::new`, nested input validation, and the policy compiler have ordinary Rust tests. They do not have a compiler-equivalence proof. The compiler converts a public tree to a postorder program. The runtime cannot encode an alternative to the mandatory TPM root. No mechanized theorem currently proves this API property.
* The verified evaluator counts child positions. The public validator and compiler establish unique node identities, provider identities, and compiled edges. Tests check these properties. The proof does not silently assume these conditions in a separate model.
* `PolicySession` supplies booleans only after its caller reports authenticated observations. The proof does not authenticate signatures, AEAD tags, TPM messages, device identity, or network providers. It does not establish freshness. An incorrect or dishonest caller can report false observations. Production adapters remain part of the trusted integration boundary.
* The policy core owns no key material. It returns a release decision, not plaintext. These policy contracts do not cover secret sharing, cryptographic confidentiality, constant-time execution, or key erasure. A separate proof covers multiplication, as specified below.
* The Rust compiler, Verus translation, SMT solver, and specified Verus library and specifications remain trusted. The prohibition on local proof bypasses does not remove trust in standard-library contracts.
* A public policy can have a maximum of 31 nodes. This count includes the implicit root and mandatory TPM node. Maximum depth is 4, including the implicit root. The network subtree starts at depth 2. Enforce parser and allocation limits before you construct a recursive tree from attacker-controlled input.
* Model replay, late provider responses, deadlines, cancellation, and cryptographic binding in the integration. The proof covers duplicate accounting and the final release gate. A boolean alone cannot establish freshness.

## Regression tests

`cargo test -p leelo-policy` checks these properties and failure conditions:

* Node collisions and provider collisions.
* Invalid thresholds, size limits, and depth limits.
* The mandatory TPM factor, even when two network factors succeed.
* Duplicate retries and attested authorization.
* Root authentication and release at most once.

The tests compare all subsets of a nested policy with a separate recursive reference evaluator.
These tests give evidence for the compiler, which has no equivalence proof.
They do not replace that proof.

When you change a proof, update this description of its limits.
Keep the reference to the same production source file.
Run the complete verifier before you claim that the contracts remain proved.
Do not accept omitted functions, timeouts, or unknown results as a successful proof.

## Production GF(256) multiplication

`gf256.rs` includes the actual `crates/leelo-sss/src/gf256.rs` that sharing and interpolation use.
The native Windows run reported **11 verified, 0 errors** with the specified toolchain and `--no-cheating`.
The production multiplier uses eight fixed masked rounds.
The code explicitly expands these rounds to keep the refinement proof small.

The mathematical specification constructs the 16-bit carryless product of two bytes.
It then reduces the product modulo `x^8+x^4+x^3+x+1` (`0x11b`).
A separate proof compares compact polynomial-basis reduction with eight steps of polynomial long division.
The two results agree for every 16-bit input.
The production `mul` postcondition proves agreement with the specification for every pair of bytes.
The proof also checks the `xtime` and masked-term helper contracts.

These proofs relate the actual source to its specification.
They do not prove a replacement reference implementation.
The proof does **not** establish the full Shamir interpolation or secrecy theorem.
The source safety check includes `inverse_nonzero`.
However, the function has no formal postcondition that proves a multiplicative inverse for each nonzero input.
Runtime tests check that property for all 255 nonzero bytes.
A separate multiplication test compares all 65,536 byte pairs with an independent long-division implementation.

The multiplier has no source branches or table indexes that depend on secret values.
The proof establishes functional behavior and safety.
It does not establish machine-code timing, microarchitectural behavior, zeroization, or cryptographic noninterference.
