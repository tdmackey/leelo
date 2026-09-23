# Fedora 44 VM validation

The Leelo network-bound profile passed the two-VM integration run on **2026-09-22 Pacific / 2026-09-23 UTC**.

The client enrolled a dedicated LUKS2 disk through its guest TPM2 and a separate network evaluator. Leelo activated an actual device-mapper mapping. After reboot, the client automatically unlocked and mounted the disk.

All requested failure checks preserved recovery access. The run required no production Rust code changes.

This report records experimental integration evidence. It does not establish production qualification or a whole-system security proof. Refer to [scripts/fedora](../scripts/fedora/README.md) for reproduction instructions and the guarded test scripts.

## Environment and source provenance

Two independent Fedora 44 Cloud x86_64 guests ran under QEMU/KVM on Ubuntu 24.04 WSL2. Each guest had its own persistent software TPM2 instance and private root disk.

The client used `/dev/tpmrm0` through TPM2-TSS. Its secondary virtio disk was blank, had a capacity of 1 GiB, and had serial `leelo-test-data`.

No host disk or hardware TPM was attached. The client had 6 vCPUs and 8 GiB RAM. The evaluator had 2 vCPUs and 3 GiB RAM.

VM processes ran under an unprivileged host user. The QEMU syscall sandbox was enabled.

The base image was `Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2`. The image came from [Fedora's Cloud distribution](https://fedoraproject.org/cloud/download/).

The [signed checksum file](https://dl.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/Fedora-Cloud-44-1.7-x86_64-CHECKSUM) was verified with the Fedora signing key. The image SHA-256 matched this value:

```text
28680fe5b371a5a82ebf43a31926e086a168e59949d03969c5093e7071f90b7f
```

The Fedora 44 signing key had primary fingerprint `36F612DCF27F7D1A48A835E4DBFCF71C6D9F90A6`. The test harness pins the expected image hash and checks the signed checksum.

| Component | Observed version or configuration |
|---|---|
| Guest kernel | `6.19.10-300.fc44.x86_64` |
| Rust runtime build | `1.95.0`, debug binaries, locked dependencies |
| GCC / glibc | `16.2.1-2.fc44` / `2.43-8.fc44` |
| TPM2-TSS | `4.1.3-9.fc44` |
| cryptsetup | `2.8.8-1.fc44` |
| OpenSSL | `3.5.8-1.fc44` |
| Guest-local swtpm test binary | `0.10.2-1.fc44` |
| systemd | `259.9-1.fc44` |
| SELinux policy | `43.3-1.fc44`, enforcing throughout |
| Firmware | OVMF UEFI; Secure Boot was not enabled or qualified |
| TPM policy | SHA-256 PCRs 7 and 11, mask `2176` |

The evaluator frontend and key worker used distinct non-root UIDs.

The client received only the CA certificate and pinned public evaluator configuration. The trusted VM control channel carried this material.

The evaluator TLS forwarding port was bound to host loopback. The client used its isolated QEMU user-network gateway to reach this port.

This run used one evaluator. It did not test a multi-server quorum.

## Completed checks

| Check | Result and evidence |
|---|---|
| Native Fedora compilation, workspace tests, formatting, and strict Clippy | `scripts/check.sh` passed. `scripts/test-tpm.sh` explicitly ran the software-TPM test that ordinary tests ignore. |
| Existing local end-to-end suite | TLS, worker, TPM, and LUKS2 enrollment tests passed. Credential recovery, interrupted token-attachment repair, idempotent resume, and network failure tests passed. |
| Native Linux formal verification | Verus reported `10 verified, 0 errors` for policy. It reported `11 verified, 0 errors` for field arithmetic. Both used `--no-cheating`. |
| Evaluator process separation | Live process UID fields, executable, and subcommand matched the two systemd accounts. Unix socket ownership and mode `0660` matched the test fixture. |
| Key-file isolation | An actual file-open attempt under the frontend UID could not access the worker private evaluation key. |
| IPC peer authorization | A third account in the IPC group connected successfully. The worker then closed the connection because the kernel UID was unauthorized. |
| TLS service | TLS 1.3 evaluation validated the CA and hostname and returned the expected response framing. The independent client then verified VOPRF proofs during enrollment and unlock. |
| Cross-VM enrollment | Enrollment added Leelo slot 1 and its signed token. It preserved original recovery slot 0 and its metadata. The commands did not print recovered credentials. |
| Device activation and persistence | Leelo created an actual device-mapper mapping. The test formatted ext4 and wrote a random marker. It closed and reopened the mapping, mounted the filesystem, and compared the stored marker. |
| Automatic reboot unlock | The enabled data-volume service ran after networking on the next boot. It unlocked, mounted, and read the persistent marker without manual service start. The check required a new boot ID and a result from that exact boot. |
| Evaluator outage | Automatic unlock failed with `InsufficientFactors` while the HTTP service was stopped. The recovery credential worked. Enrolled LUKS metadata did not change. |
| Incorrect envelope trust key | Unlock failed with `Envelope(InvalidSignature)`. Recovery still worked. |
| Modified signed token | A byte mutation in the token envelope failed with `Envelope(InvalidSignature)`. Restoring the original token restored automatic credential verification. Metadata matched the enrolled state. |
| Changed PCR11 | Extending PCR11 caused TPM `PolicyPCR` failure (`0x000001c4`) and automatic unlock rejection. Recovery still worked. Metadata did not change. |
| SELinux | SELinux stayed enforcing. Captured AVC searches for the evaluated service and test boots returned no matches. |

The automatic service journal records activation and successful marker reading at `2026-09-23 05:33:14–05:33:15 UTC`.

Enrollment and successful automatic unlock had different boot IDs:

```text
enrollment: 960c55da-6eb3-4c46-9cf6-9d600861c8d7
unlock:     6cc5e121-d3fe-436b-bea7-16d17922d0e4
```

PCR7 did not change across this reboot:

`127c18eba2300e30767fafe71f4e5975776f665d22c7ca9017c7c24846b96fa1`.

PCR11 was **all zero** at enrollment and after ordinary boot. The deliberate PCR11 extension caused unlock rejection.

This image did not demonstrate a populated UKI or systemd measured-boot PCR11 policy. No policy was weakened to make the reboot succeed.

## Formal evidence and source identity

The Fedora proof run used pinned Verus `0.2026.06.28.1847ab3` for `linux_x86_64`. It used Rust `1.96.0` and the bundled solver.

The official verifier archive passed the checksum in `verification/toolchain.json`. Both proofs include the actual production Rust source.

The following SHA-256 values came from the guest. At the time of the run, the corresponding production source hashes matched the checkout.

These historical hashes identify the tested revision before later documentation and source-comment edits. They are retained as evidence for this run.

```text
Cargo.lock
e1bceee0e58c31aec216fe136a2e97187b13ae58c3d85ae55bf5dcdf8cb57793
crates/leelo-policy/src/verified.rs
9483f19651c9bd7e14cff990fab399a5359a1584a79c5a9fd43a498e4b95dfad
crates/leelo-sss/src/gf256.rs
48fee3530429a879a9b2fba42af65bccfecc8fc9268c39f1d83c4f3ab9f855a1
target/debug/leelo (Fedora ELF)
fc7614c0132ffd426f0d3449788a0e7490389870f1f3573bf938e43fe364e0bf
target/debug/leelod (Fedora ELF)
ab6dd3c93f732759ba9d78490df710216ddceb13356e0b38c5dfe7015750e91b
```

The 21 reported obligations do not represent 21 independent security theorems. They cover the policy contracts and GF(256) multiplication refinement in the [proof boundary](../verification/README.md).

The proofs do not establish the full Shamir construction, cryptographic composition, FFI correctness, TPM firmware correctness, or initramfs correctness. They do not establish kernel correctness, secret erasure, or machine-code timing.

## Scope and retained evidence

This was a **late-boot data-volume** test. The run tested only the network-bound profile.

Encrypted-root and initramfs boot remain unqualified. Secure Boot, signed PCR updates, real TPM hardware, firmware upgrades, and power-loss recovery also remain unqualified.

Fresh TPM-attested onboarding and per-unlock authorization are not implemented. The production adapter explicitly rejects them.

The evaluator processes ran in SELinux `unconfined_service_t`. Successful operation in enforcing mode demonstrates compatibility. It does not establish a custom SELinux confinement boundary.

The key-separation tests used Unix permissions, distinct UIDs, worker peer checks, and the supplied systemd units.

Development of the test harness corrected four issues:

* WSL required a foreground keepalive.
* An unclean initial guest shutdown required restoration of test-only SSH bootstrap files.
* The test fixture had to resolve its guarded virtio path before calling the Leelo device interface, which rejects symlinks.
* Process readiness checks required actual UID fields instead of `/proc` directory ownership.

Temporary offline recovery helpers were removed from the reproducible harness. No guest SELinux policy was disabled or replaced.

The local ignored file `.tools/fedora-vms/build.log` contains compiler, test, and proof output.

The directory `.tools/fedora-vms/results/` contains collected phase logs, service journals, PCR snapshots, environment details, SELinux records, and LUKS metadata comparisons.

Report collection excludes private signing keys, evaluator keys, recovery keys, and TPM state.

Private VM disks and credentials remain in the private lab directory for local investigation. Do not publish them. The VMs were shut down after collection.
