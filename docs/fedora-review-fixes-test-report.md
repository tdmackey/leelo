# Fedora review-fix validation

Date: 2026-09-23.

The review fixes passed validation in the existing Fedora 44 evaluator and client VMs.
The test retained the evaluation key, TPM state, original enrollment, recovery credential, and encrypted filesystem.
Both VMs and both software TPM services are stopped.

This report supplements the [original Fedora test report](fedora-vm-test-report.md).
The original report and its evidence remain available.

## Environment

| Component | Tested value |
| --- | --- |
| Guests | Fedora 44 Cloud, separate evaluator and client |
| Kernel | `6.19.10-300.fc44.x86_64` |
| Rust build toolchain | `1.95.0`, rustc `59807616e` |
| Verus toolchain | Rust `1.96.0`, Verus `0.2026.06.28.1847ab3` |
| libcryptsetup | `2.8.8-1.fc44` |
| TPM2 TSS | `4.1.3-9.fc44` |
| swtpm | `0.10.2-1.fc44` |
| OpenSSL | `3.5.8-1.fc44` |
| systemd | `259.9-1.fc44` |
| SELinux | Enforcing throughout the test |
| Test disk | Dedicated 1 GiB virtio block device, serial `leelo-test-data` |

The host used the existing QEMU/KVM lab.
The test created no additional VMs and did not format the disk again.

## Build and test results

The [guest build script](../scripts/fedora/guest-build.sh) ran these commands inside Fedora:

| Command | Result |
| --- | --- |
| `bash scripts/check.sh` | 59 workspace tests and 4 compile-fail documentation tests passed; formatting and strict Clippy passed |
| `bash scripts/test-tpm.sh` | 2 tests passed, including the real isolated swtpm integration test |
| `bash scripts/test-luks.sh` | All 6 disposable regular-file storage tests passed |
| `bash scripts/test-e2e.sh` | Enrollment, recovery, pending-bundle repair, idempotent resume, and outage checks passed |
| `bash scripts/verify.sh --install-verus` | Both proof suites passed: 11 verified and 11 verified, with no errors |

The normal workspace run skipped seven integration tests that need explicit fixtures.
The TPM and LUKS scripts ran all seven with those fixtures.
The TPM script also repeated its input-validation test.

The storage tests include token-table exhaustion, metadata limits, long foreign JSON numbers, writer exclusion, changed metadata, and token repair.
The long-number test checks capacity with the original libcryptsetup JSON length.

The daemon integration tests include a real TLS response that sends body bytes slowly.
The client rejected that response at its 350 ms deadline.
The tests also verified that failed worker startup cannot send a readiness notification.

## Installed service checks

The evaluator received the tested `leelod` binary and current service units.
The existing evaluation key and public identity remained unchanged.

The worker used `Type=notify` and `NotifyAccess=main`.
Starting `leelo-http.service` also started its required worker.
The worker entered the active state at monotonic timestamp `825373232` microseconds.
The frontend process started at `825374225` microseconds, after that readiness event.

The [evaluator verification helper](../scripts/fedora/evaluator-setup.sh) confirmed these results:

| Check | Result |
| --- | --- |
| Worker process | PID 1336; real, effective, saved, and filesystem UID 991 |
| Frontend process | PID 1340; all four UID fields 990 |
| IPC socket | Worker-owned Unix socket; mode `0660`; group `leelo-ipc` |
| Evaluation key | Worker-owned file; mode `0600`; frontend UID could not read it |
| Unauthorized IPC peer | Separate group member connected; worker rejected its kernel UID |
| TLS evaluation | TLS 1.3, trusted CA, hostname validation, and expected response framing passed |

SELinux remained enforcing, and the recorded AVC searches had no matches.
Both daemon processes used `unconfined_service_t`.
These results do not establish a custom SELinux confinement policy.

## Real reboot and block-device checks

The client received the tested `leelo` binary and boot helper.
Its boot ID changed from `b90bcd44-a509-4093-91ee-efa078a65f4e` to `486dde3c-42c5-42f2-807a-bc0953643823`.

The enabled service automatically unlocked and mounted the original enrollment after reboot.
It read the existing filesystem marker.
The [reboot check](../scripts/fedora/guest-test.sh) observed the automatic service and did not start it manually.
The original recovery credential still worked.
The check then closed the mapping.

The next test used the same dedicated block device:

1. Hold an OFD write lock on the block-device inode.
2. Run the installed CLI's resume operation against the original pending bundle.
3. Require `WriterBusy` and unchanged LUKS JSON metadata.
4. Release the lock and enroll once with a fresh journal.
5. Check both Leelo tokens and the original recovery credential.
6. Resume the new enrollment twice and compare the complete metadata after each operation.
7. Open the new token's mapping and read the existing filesystem marker.
8. Close the mapping.

All steps passed.

| State | Keyslots | Tokens |
| --- | --- | --- |
| Before the additional enrollment | Recovery slot 0; original Leelo slot 1 | Token 0 references slot 1 |
| After the additional enrollment | Original slots 0 and 1; new Leelo slot 2 | Original token 0; new token 1 references slot 2 |
| After both resume calls and negative tests | Slots 0, 1, and 2 | Tokens 0 and 1 |

The original slot entries and token 0 were unchanged.
Both resume calls returned slot 2 and token 1.
Each resume left the complete JSON metadata unchanged.
The test retained the original baseline and recorded a separate baseline after the additional enrollment.

## DNS and failure checks

The [DNS timeout helper](../scripts/fedora/guest-dns-timeout.sh) ran the installed production CLI in a private mount namespace.
Only that namespace used a temporary resolver file.
The file selected a local UDP sink and requested a 30-second resolver timeout with five attempts.
The temporary provider URL used a unique `.test` hostname.

The sink discarded two DNS queries.
The complete CLI process, including runtime destruction, exited with status 1 after **3.045 seconds**.
No forced termination was needed.
The bounded diagnostic identified the public provider and the `Timeout` category.
The guest resolver hash and complete LUKS JSON metadata remained unchanged.

The remaining checks passed after the additional enrollment:

| Trigger | Automatic unlock | Recovery and metadata |
| --- | --- | --- |
| Evaluator HTTP service stopped | Rejected with `Unavailable` | Recovery worked; metadata unchanged |
| Incorrect administrative trust key | Rejected | Recovery worked |
| Modified signed token | Rejected | Original token restored; recovery worked; metadata unchanged |
| Guest PCR11 extended | Rejected with TPM policy error `0x000001c4` | Recovery worked; metadata unchanged |

The PCR change was the final negative test.
The test changed only the disposable guest TPM.
No device-mapper mapping remained open at shutdown.

## Commands and evidence

The [host driver](../scripts/fedora/vm-lab.sh) operated the existing lab.
On the Linux host, the start command and foreground hold were:

```sh
sudo bash scripts/fedora/vm-lab.sh start
sudo bash scripts/fedora/vm-lab.sh keepalive
```

The foreground hold remained active until the shutdown command completed.
The remaining host commands were:

```sh
sudo bash scripts/fedora/vm-lab.sh wait
sudo bash scripts/fedora/vm-lab.sh stage
sudo bash scripts/fedora/vm-lab.sh build
sudo bash scripts/fedora/vm-lab.sh install-evaluator-binary
```

The retained `upgrade-evaluator.sh` and `upgrade-client.sh` scripts installed the binaries and units without changing existing keys or enrollment.
The retained `block-enrollment.sh` script performed the additional slot test.
Each script is in the local run directory listed below.
The host sent each script to its guest with `vm-lab.sh ssh ROLE 'sudo bash -s'` and standard input redirection.

The checked-in guest phases were:

```sh
sudo bash scripts/fedora/vm-lab.sh ssh evaluator 'sudo bash /home/leelo/leelo/scripts/fedora/evaluator-setup.sh verify-existing'
sudo bash scripts/fedora/vm-lab.sh ssh client 'sudo systemctl reboot'
sudo bash scripts/fedora/vm-lab.sh wait
sudo bash scripts/fedora/vm-lab.sh ssh client 'sudo /usr/local/libexec/leelo-vm-test reboot-check'
sudo bash scripts/fedora/vm-lab.sh ssh client 'sudo bash /home/leelo/leelo/scripts/fedora/guest-dns-timeout.sh'
# The additional block-device enrollment ran here.
sudo bash scripts/fedora/vm-lab.sh ssh evaluator 'sudo systemctl stop leelo-http.service'
sudo bash scripts/fedora/vm-lab.sh ssh client 'sudo /usr/local/libexec/leelo-vm-test network-off-check'
sudo bash scripts/fedora/vm-lab.sh ssh evaluator 'sudo systemctl start leelo-http.service'
sudo bash scripts/fedora/vm-lab.sh ssh client 'sudo /usr/local/libexec/leelo-vm-test negative-tests'
sudo bash scripts/fedora/vm-lab.sh ssh client 'sudo /usr/local/libexec/leelo-vm-test capture'
sudo bash scripts/fedora/vm-lab.sh collect
sudo bash scripts/fedora/vm-lab.sh down
```

The local evidence directory is `.tools/fedora-vms/runs/review-fixes-20260923/`.
It contains the final build log, source archive, source hashes, collected guest results, scripts, and shutdown record.
Its `prior-results/` and `prior-build.log` retain the previous run.
Its `initial-build.log` retains the successful intermediate run before the final storage and DNS corrections.
These ignored files are local evidence and are not part of the repository.

All four host units reported `inactive` after shutdown: evaluator QEMU, client QEMU, evaluator swtpm, and client swtpm.

## Artifact identities

These SHA-256 values identify the tested source snapshot and installed debug binaries:

| Artifact | SHA-256 |
| --- | --- |
| Final `source.tar.gz` | `57fbe6dad482d8711f7446402f5384f070d2f652ea5f94f4301be15c31ad572b` |
| `Cargo.lock` in both guests | `97b810ca2f73b1776930088ee8b4fe7872fdf14a5600f7c3f1b7942d46fcb603` |
| Installed client `leelo` | `88ab524b6eefd31f388ae56cd66f65616b0c250b929c800da59620e201162348` |
| Installed evaluator `leelod` | `e1afa851542d1176b77c136f66650d76426bdbe961b177aecc61e1b099000cb3` |
| `crates/leelo-net/src/lib.rs` | `616efcc74746fa8574f2bd00429bb2147c3d37375b2ee6e5edc09b7b5d0f41bd` |
| `crates/leelo-luks/src/linux.rs` | `96f90e465b7672ffbfb450e31d4a74e31fe5322338d872591e1c5f10371f5cbd` |
| `crates/leelod/src/service.rs` | `f65903418854f864ef12d869c3e553a5f98173e157023076257314a5677380b7` |

Later documentation edits do not change these tested product files.

## Assurance limits

This run tests late-boot data-volume unlock.
It does not test initramfs, encrypted-root boot, physical TPMs, Secure Boot qualification, or the future remote attestation mode.

The block-device test exercised a normal successful capacity check.
Capacity rejection, token-table exhaustion, and metadata-race cases used disposable regular-file LUKS2 images.
The OFD lock coordinates Leelo writers; native cryptsetup writers use their own metadata locks.

The proof results apply only to the recorded proof suites and their stated assumptions.
They do not prove the complete daemon, DNS resolver, TPM stack, LUKS adapter, operating system, or VM environment.
The test results do not establish production readiness or replace an independent security audit.
