# Leelo

Leelo unlocks LUKS2 volumes with TPM2 and network factors. The implementation uses Rust. Machine-checked contracts cover policy decisions and compilation certificates, field arithmetic and interpolation kernels, and context-bound release order.

**Leelo is experimental. It is not a production-ready disk-unlock service.** The implemented profile requires the local TPM **and** a threshold of network evaluators.

The fresh-attestation profile is planned. The production adapter rejects this profile until its authorization protocol is implemented. The [implementation ledger](docs/implementation.md) separates implemented functions, completed checks, and remaining gaps.

## Implemented functions

* Online enrollment and recovery use RFC 9497 P-384 VOPRF evaluations and pinned evaluator keys. The profile uses HKDF-SHA384, ChaCha20-Poly1305, and Ed25519-signed deterministic CBOR envelopes.
* Network policies support nested thresholds. The TPM factor is mandatory. The implementation uses fixed-size Shamir shares. It does not parse JWT/JOSE or use shell commands for cryptographic operations.
* TPM2-TSS seals and unseals data through encrypted sessions. TPM policies require PCR equality and policy-only objects.
* The libcryptsetup adapter adds LUKS2 slots, stores tokens, checks credentials, and activates mappings on explicit request. Enrollment preserves existing recovery slots. A durable encrypted pending bundle permits resumption of interrupted token attachment.
* The TLS 1.3 evaluator frontend uses a separate private-key worker. Unix IPC has size limits and checks the peer UID. Use separate OS accounts for deployment isolation. Refer to the [service guide](crates/leelod/README.md).
* Unlock runs at most four network evaluations at once. It cancels pending evaluations after quorum. A five-second provider deadline covers the complete response. One 30-second operation budget covers the network phase and release checks. Synchronous TPM driver calls cannot be interrupted by that budget.
* Optional local events, protected daemon metrics, a valid-evaluation probe, and bounded reconciliation support operational monitoring. Telemetry delivery cannot control credential release. Refer to the [observability guide](docs/observability.md).

Network-bound mode supplies a network factor. It does not provide continuous attestation or per-device revocation. An authorized client can retain recovered material.

The network-bound evaluator does not enroll devices or authorize individual bindings. This behavior is intentional.

## Build and check

Use Linux for the real TPM and LUKS adapters. Windows can build and test the portable core. `rust-toolchain.toml` pins Rust. The repository includes `Cargo.lock`.

On Ubuntu 24.04, install the build dependencies. Then build the workspace and run the checks:

```sh
sudo apt-get install build-essential pkg-config libssl-dev libtss2-dev libcryptsetup-dev
cargo build --workspace --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
```

Ordinary tests do not access a hardware TPM or format a disk. The explicit integration scripts use disposable software TPMs on loopback addresses. They also use temporary regular-file LUKS2 images.

Install the integration dependencies. Then run the scripts:

```sh
sudo apt-get install swtpm swtpm-tools tpm2-tools cryptsetup-bin openssl python3
bash scripts/test-tpm.sh
bash scripts/test-luks.sh
bash scripts/test-enrollment-persistence.sh
bash scripts/test-e2e.sh
bash scripts/test-observability.sh
```

The end-to-end script creates TLS certificates, an evaluator key, a signing key, an old recovery credential, and a disk image. The script tests enrollment, recovery, token repair, and network failure. It does not accept a disk path from the caller.

These test fixtures do not establish hardware, firmware, or initramfs boot compatibility.

The [Fedora 44 two-VM run](docs/fedora-vm-test-report.md) also passed device-mapper activation and filesystem persistence tests. It passed automatic data-volume unlock after reboot and evaluator UID isolation tests. Outage, tamper, and PCR rejection tests preserved recovery access.

The [review-fix VM run](docs/fedora-review-fixes-test-report.md) repeats those checks with the updated binaries.
It also tests DNS cancellation, worker readiness, writer exclusion, and a second enrollment on the same virtual disk.

The [VM harness](scripts/fedora/README.md) reproduces this run with disposable disks and software TPMs. SELinux stays enforcing. These results do not qualify encrypted-root boot, initramfs boot, or hardware TPMs.

## Formal verification

Install the proof toolchain. Then run the proof script:

```powershell
rustup toolchain install 1.96.0 --profile minimal
pwsh -File scripts/verify.ps1 -InstallVerus
```

On Linux, run `bash scripts/verify.sh --install-verus`. The installation switch downloads the pinned official Verus archive and checks its pinned SHA-256. Omit the switch on subsequent runs.

The application uses Rust 1.95. The proof tool uses a separately pinned Rust 1.96 toolchain.

The current proof suite checks **28 policy, 38 sharing-arithmetic, and 8 release obligations, with zero errors**. It uses Verus `--no-cheating` and the actual source compiled into the application. The compiler certificate establishes source-to-plan decision equivalence for every response assignment.

The arithmetic proofs cover multiplication, nonzero inversion, interpolation kernels, and the mandatory 2-of-2 root. The release gate checks context, order, and release at most once. These 74 obligations are not independent whole-system security theorems.

The proofs do not establish whole-system confidentiality, protocol composition, general t-of-n reconstruction, or TPM/FFI correctness. They do not establish Shamir secrecy, zeroization, or machine-code timing. Refer to the exact [proof boundary and reproducibility instructions](verification/README.md).

The [comparison lessons](docs/comparison-lessons.md) describe the private operation owner, extended proofs, [frozen protocol vector](test-vectors/README.md), parser fuzzing, fault tests, and [dependency policy](docs/dependency-policy.md).

## CLI

Run `leelo --help` to list the commands. Enrollment uses a trusted local evaluator configuration and an administrative signing key. This prototype does not implement TPM-attested remote intake.

```json
{
  "providers": [{
    "provider_id": "<32-byte operator-assigned ID, hex>",
    "key_id": "<32-byte ID printed by leelod keygen, hex>",
    "public_key": "<49-byte pinned evaluator public key, hex>",
    "url": "https://evaluator.example:8443",
    "ca_file": "evaluator-ca.pem"
  }]
}
```

Keep this configuration and the envelope-signing public key in the trusted boot image. Obtain paths and URLs from trusted local configuration. Do not obtain them from the disk token.

The client uses asynchronous DNS with the configured name servers and hosts file.
It does not call system NSS modules, such as mDNS or LDAP name services.
Use DNS names, hosts-file entries, or IP addresses that match the evaluator certificate.

Store secrets in regular files with mode 0600 or stricter. Commands accept secret file paths. They do not accept secret values in arguments or print recovered credentials.

`enroll` adds a slot only after successful TPM and network recovery. `unlock --check-only` tests the credential without creating a mapping. `unlock --mapping NAME` activates the mapping.

`resume-enrollment` authenticates a saved pending bundle and tests its exact signed slot before token attachment. It is idempotent when the token is already attached. It cannot resume enrollment if the interruption occurred before slot creation.

The default PCR mask is 2176: SHA256 PCRs 7 and 11. Enrollment records their **current** values.

With systemd measured boot, PCR11 can have different values in the running OS and during initramfs unlock. Successful enrollment in the running OS does not establish that the next boot can unlock.

Boot-phase measurement policies, signed PCR updates, and initramfs integration remain required work.

## Repository map

| Component | Responsibility |
|---|---|
| `leelo-policy` | Validated policy, private sharing plan, verified evaluator, and release gate |
| `leelo-sss` | Zeroizing shares, verified GF multiplication, and interpolation |
| `leelo-crypto` | Fixed cryptographic profile and primitive vectors |
| `leelo-envelope` | Bounded canonical encoding and authentication with an external key |
| `leelo-engine` | Enrollment and recovery orchestration |
| `leelo-tpm` / `leelo-luks` | Linux integration boundaries |
| `leelo-net` / `leelod` | HTTPS client, frontend, and key worker |
| `leelo-protocol` | Shared evaluator wire format and public key identity |
| `leelo-cli` | Explicit administrative and unlock commands |

Read the [target architecture](docs/design.md) for design intentions. Read the [wire format](docs/wire-format.md) for encoding details. Read the [implementation gaps](docs/implementation.md) and [verification ledger](verification/README.md) for implementation and assurance evidence.

The [architecture-fix report](docs/architecture-fixes.md) records the review changes and their limits.

These documents are separate to distinguish design intentions from implementation evidence.

Use the [documentation style guide](docs/writing-style.md) for future documentation and comment changes.

Leelo is licensed under MIT or Apache-2.0, at your option.
