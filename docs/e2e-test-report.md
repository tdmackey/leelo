# Disposable Linux integration test

On 2026-09-22, `bash scripts/test-e2e.sh` passed with the actual `leelo` and `leelod` binaries. The binaries came from `cargo build --locked`. The script also passed `bash -n`.

## Test configuration

The test connected a TLS 1.3 frontend to a separately started evaluation worker through a Unix socket. It used a fresh software TPM through TPM2-TSS ESAPI.

The test added a credential and token to an actual LUKS2 header through libcryptsetup.

The test created its own certificate authority and a separate server certificate. The server certificate SAN contained the loopback address. The client used this explicit trust root.

## Results

| Check | Result |
| --- | --- |
| Enrollment, signed pending bundle, and authenticated inspection | Passed |
| Automatic credential recovery and LUKS2 `--check-only` unlock | Passed |
| Original recovery credential remains valid | Passed |
| Original slot metadata remains unchanged | Passed |
| Delete only the fixture token, retain both slots, and resume from the signed pending bundle | Passed |
| Second resume returns the same token and identical metadata | Passed |
| Stop the TLS frontend; automatic unlock fails | Passed |
| Offline recovery credential works; failed unlock does not change metadata | Passed |

## Environment

The test used Ubuntu 24.04 under WSL2. The x86-64 Linux kernel was `6.18.33.2-microsoft-standard-WSL2`.

| Component | Version |
| --- | --- |
| Rust | 1.95.0 |
| cryptsetup | 2.7.0 |
| swtpm | 0.7.3 |
| TPM2-TSS ESAPI | 4.0.1 |
| OpenSSL | 3.0.13 |

`Cargo.lock` records the Rust dependency versions.

## Repeat the test

Install the Rust toolchain and dependencies on Linux. Run this command from the repository root:

```sh
bash scripts/test-e2e.sh
```

The script does not accept a disk argument. It creates a 64 MiB regular file in its private `/tmp/leelo-e2e.*` directory.

Before each format or metadata change, the script checks the target. The target must be that exact file, with one hard link and the expected size.

The script uses a software TPM and servers on loopback addresses. On exit, it stops its own background processes and removes the test fixture.

The deliberately inexpensive PBKDF applies only to the random recovery credential on the disposable image.

## Evidence limits

This run provides evidence for userspace integration and repair of a missing token.

The run did not test a physical TPM, boot phase, initramfs, device-mapper activation, power failure, or production privilege separation.

The worker and frontend used the same test UID. Production deployment requires separate identities.

The test measured and reused PCR values within one simulator session. It does not establish that a policy captured after boot can unseal during an earlier boot phase.

The test simulated a committed keyslot without its token. It did not inject a crash into every storage operation. It does not prove filesystem or device durability.
