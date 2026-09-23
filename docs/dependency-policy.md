# Dependency checks

Run `python3 scripts/check-dependencies.py` from a checkout with the pinned Rust
toolchain and `cargo-deny 0.19.4` installed. On Windows, `python` can run the same
script. Install the checker with `cargo install cargo-deny --version 0.19.4 --locked`.
The [workflow](../.github/workflows/dependencies.yml) runs on pull requests, pushes,
manual dispatch, and weekly to detect newly published advisories in unchanged code.

The checker uses the root `Cargo.lock` and the isolated `fuzz/Cargo.lock` without
modifying either. It checks the application workspace graph, including test and
build dependencies, for the supported Linux and Windows targets. It separately
checks the fuzz workspace with **all features enabled**, including the optional
`libfuzzer-sys` runner that ordinary deterministic parser tests do not compile.
It fetches the current RustSec database and fails on vulnerabilities, unsoundness,
unmaintained packages, yanked releases, unknown registries or Git sources, and
licenses outside the explicit allowlist in [deny.toml](../deny.toml). Fetch failures
fail the job. This is advisory and policy evidence, not an audit of dependency code.

Registry and Git dependencies must have a version requirement; unrestricted `*`
requirements fail. Internal workspace path dependencies can omit a registry version.
Duplicate crate versions produce visible warnings because the cryptographic and
platform dependencies currently use incompatible API generations. Do not force
deduplication through unrelated upgrades. VOPRF's deterministic `danger` API,
general serialization, default feature set, and other suite features are denied.

There are no advisory exceptions. An exception must name the exact advisory or
yanked crate version in `deny.toml`, explain its applicability and mitigation here,
name an owner and review deadline, and receive review alongside the dependency
change. Do not add broad severity exemptions or disable a check to make CI pass.
Unused advisory exceptions are errors and must be removed. License exceptions
must identify the package/version and the license evidence; a policy pass does not
replace review of distribution obligations.

The license allowlist includes four package-specific exceptions, checked against
the published package files:
`minicbor =0.26.5` uses `BlueOak-1.0.0`; `target-lexicon =0.12.16` uses
`Apache-2.0 WITH LLVM-exception`; `webpki-roots =1.0.9` uses
`CDLA-Permissive-2.0`; the isolated runner `libfuzzer-sys =0.4.13` is allowed
`NCSA` and `Apache-2.0 WITH LLVM-exception` in addition to the ordinary MIT/Apache
allowlist. These exceptions do not suppress advisories and do not permit
other packages to introduce those licenses without review. Review their license
evidence again when the specified versions change.

The `libfuzzer-sys 0.4.13` package's `Cargo.toml` declares
`(MIT OR Apache-2.0) AND NCSA`. Its shipped `README.md` license section attributes
NCSA to the bundled `libfuzzer` directory; `LICENSE-MIT` and `LICENSE-APACHE` supply
the Rust wrapper's license texts. The shipped C++ files, including
`libfuzzer/FuzzerDriver.cpp`, instead carry the SPDX identifier
`Apache-2.0 WITH LLVM-exception` and refer to the LLVM project license. This
manifest/header difference is recorded rather than treated as one uniform
license. The exception is restricted to this test-only package version; review
the bundled source notices before distributing a fuzz-runner binary. The
application binaries do not depend on this isolated runner.

The first scan found Hickory `0.25.2` advisories `RUSTSEC-2026-0118` and
`RUSTSEC-2026-0119`, plus unmaintained `rustls-pemfile` (`RUSTSEC-2025-0134`).
Leelo's transport uses the patched Hickory `0.26` line through reqwest's custom
asynchronous resolver interface, and PEM parsing uses the maintained
`rustls::pki_types::pem::PemObject` API. No advisory was suppressed.

References: [cargo-deny advisory policy](https://embarkstudios.github.io/cargo-deny/checks/advisories/cfg.html),
[feature and dependency policy](https://embarkstudios.github.io/cargo-deny/checks/bans/cfg.html),
[RustSec advisory database](https://github.com/RustSec/advisory-db).
