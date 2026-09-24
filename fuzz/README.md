# Parser and policy fuzzing

This isolated Cargo workspace calls production APIs. It does not open disks,
contact providers, use a TPM, or create production keys. Fixed signing and server
keys are public test fixtures. Its separate `Cargo.lock` records fuzz dependencies;
it does not add libFuzzer to the application workspace.
`scripts/check-dependencies.py` checks both the production graph and this
workspace with all features enabled. The shared policy has no advisory
exceptions; its version-specific `libfuzzer-sys 0.4.13` license allowance is for
the crate's declared NCSA component.

| Target | Checked property |
|---|---|
| `envelope` | Outer CBOR frames and separately re-signed arbitrary bodies cannot crash the parser. Every accepted frame re-encodes identically and retains its context hash. The test signer gets malformed/deep input through the authentication gate without adding a production bypass. |
| `wire` | Every accepted request/response has the unique exact encoding. |
| `crypto_encodings` | Production scalar/public-point wrappers and the pinned upstream point/proof decoders cannot panic. Accepted values at Leelo's fixed lengths re-encode identically. The upstream decoders can accept trailing bytes; Leelo's fixed arrays and wire lengths reject those before use. |
| `luks_token` | Accepted JSON/base64 preserves one bounded envelope and a canonical slot through re-encoding. This invokes the codec only. |
| `policy` | Bounded generated trees exercise malformed thresholds, identities, providers, size and depth. Accepted policies agree with an independent recursive evaluator across generated response sets, including reversed order. Unknown and duplicate observations are rejected. |

Run the deterministic regression harness on the normal Rust toolchain:

```sh
cargo test --manifest-path fuzz/Cargo.toml --locked
```

It runs the same target functions on checked-in seed families, truncations, byte
mutations, parser-limit boundaries, and deterministic generated inputs. This is
regression evidence, not a coverage-guided fuzz-duration claim.

On Linux install `clang` and `libcryptsetup-dev`, then install the pinned runner
and toolchain:

```sh
rustup toolchain install nightly-2026-09-22 --profile minimal
cargo install cargo-fuzz --version 0.13.2 --locked
bash scripts/test-fuzz.sh
```

The script uses AddressSanitizer and coverage-guided libFuzzer through cargo-fuzz.
It fetches the locked graph first, builds offline, and rejects lockfile changes.
Each target runs for at most 10 seconds or 2,000 inputs after startup, whichever
finishes first. Set `LEELO_FUZZ_SECONDS` and `LEELO_FUZZ_RUNS` to positive integers
for longer campaigns. Build time is separate. Expanded corpora stay under
`.tools/fuzz-corpus`; crash reproducers stay under `fuzz/artifacts`. CI uploads
reproducers on failure. These short runs establish harness execution, not
comprehensive parser coverage or an absence of bugs.

Seed files are public, reproducible fixtures. Regenerate them with
`cargo run --manifest-path fuzz/Cargo.toml --locked --example seed_corpus`.
Commit seed or minimised reproducer changes only after inspection. The harness
does not prove cryptographic security, policy compilation correctness, platform
FFI safety, constant-time execution, or production readiness.
