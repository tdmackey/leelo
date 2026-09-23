# Fedora VM integration tests

These scripts test two disposable Fedora guests: one evaluator and one client.
Do not use these scripts to install Leelo on an existing machine.
Run each guest phase as root through `sudo`.
Keep SELinux in enforcing mode.

## Start the guests

`vm-lab.sh` creates QEMU/KVM guests with OVMF firmware.
Each guest has a separate persistent software TPM and a private root disk.
The client also has a dedicated data disk.
The script checks Fedora's signature and the specified SHA-256 checksum before it uses the Fedora 44 Cloud 1.7 image.

The VM processes use the checkout owner's unprivileged account.
To select another account, set `LEELO_LAB_HOST_USER`.
QEMU's syscall sandbox is enabled.
The host must have KVM and systemd.
On Ubuntu, install these packages: `qemu-system-x86`, `qemu-utils`, `ovmf`, `cloud-image-utils`, `swtpm`, and `gnupg`.

From the repository root, run these commands in one terminal:

```sh
sudo bash scripts/fedora/vm-lab.sh download
sudo bash scripts/fedora/vm-lab.sh run
```

Keep the second command active.
On WSL, background systemd services alone do not keep the WSL instance active.

Run these commands in another terminal:

```sh
sudo bash scripts/fedora/vm-lab.sh wait
sudo bash scripts/fedora/vm-lab.sh stage
sudo bash scripts/fedora/vm-lab.sh provision
sudo bash scripts/fedora/vm-lab.sh build
sudo bash scripts/fedora/vm-lab.sh install-evaluator-binary
sudo bash scripts/fedora/vm-lab.sh ssh evaluator 'sudo bash /home/leelo/leelo/scripts/fedora/evaluator-setup.sh'
sudo bash scripts/fedora/vm-lab.sh handoff
sudo bash scripts/fedora/vm-lab.sh ssh client 'sudo bash /home/leelo/leelo/scripts/fedora/guest-test.sh client-enroll'
```

`build` compiles the workspace inside Fedora.
It runs workspace tests, strict lint checks, disposable local integration tests, and both Verus proof suites.
Continue with the guest phases below through `vm-lab.sh ssh ROLE COMMAND`.
After all phases, collect the reports and stop the guests:

```sh
sudo bash scripts/fedora/vm-lab.sh collect
sudo bash scripts/fedora/vm-lab.sh down
```

The SSH forwards use ports 38221 and 38222.
The evaluator forward uses port 38443.
All three forwards listen only on host loopback.
The launcher creates SSH host keys before boot.
It records these keys in a private known-hosts file and requires them for later connections.

The launcher keeps VM credentials, disk overlays, and TPM state in a private `/var/tmp/leelo-fedora44.*` directory.
The ignored `.tools/fedora-vms/` directory contains its path, the public image cache, the build log, and collected reports.
Do not publish the private lab directory or its disks.

## Prepare the guests

The client must have a persistent TPM2 resource-manager device at `/dev/tpmrm0`.
The client must also have a **blank 1 GiB secondary virtio disk** with serial `leelo-test-data`.
The harness refuses to format a disk with another serial or size.
Before formatting, it rejects partitions, holders, existing signatures, and mounted targets.
Do not attach a host TPM or a real host data disk to these guests.

The default source path is `/home/leelo/leelo`.
To select another checkout, set `LEELO_TEST_REPO`.
Install the packages through `sudo`.
Build the debug binaries as the ordinary `leelo` user:

```sh
sudo dnf install -y gcc pkgconf-pkg-config openssl-devel tpm2-tss-devel \
  cryptsetup-devel cryptsetup tpm2-tools openssl python3 rustup \
  audit policycoreutils e2fsprogs util-linux
rustup-init -y --default-toolchain none --profile minimal --no-modify-path
export PATH="$HOME/.cargo/bin:$PATH"
rustup toolchain install 1.95.0 --profile minimal --component rustfmt --component clippy
cargo build --workspace --locked
```

## Configure the evaluator

Run this command on the evaluator:

```sh
sudo bash scripts/fedora/guest-test.sh evaluator-setup
```

The evaluator helper creates separate worker and HTTP service accounts.
It also creates TLS certificates and service configuration.
The default public endpoint is `https://10.0.2.2:38443/`.
This endpoint uses isolated QEMU user networking.
The host forward connects to evaluator port 8443.

If you use another network topology, set `LEELO_TEST_ENDPOINT` during setup.
The certificate SAN and provider configuration must match the endpoint that the client contacts.

Use the trusted VM control channel to copy these evaluator files:

* `/var/lib/leelo-vm-test/public/ca.pem`
* `/var/lib/leelo-vm-test/public/providers.json`

Put both files in the client's `/var/lib/leelo-vm-test/trust/` directory.
Make root the owner of the files.
This procedure supplies trusted enrollment data.
It does not discover or trust an unauthenticated service.

## Enroll the client and test reboot

Run these commands on the client:

```sh
sudo bash scripts/fedora/guest-test.sh client-enroll
sudo reboot
```

After the client starts again, run this command:

```sh
sudo bash scripts/fedora/guest-test.sh reboot-check
```

If you control the test from the host, run `vm-lab.sh wait` after the reboot command.
The check waits a maximum of 100 seconds for the automatic service to start.
The check does not start or restart the service.

`client-enroll` creates a LUKS2 header.
It enrolls through the remote TLS service and guest TPM.
It opens a device-mapper mapping and formats an ext4 filesystem.
It writes a random marker, closes the mapping, opens the mapping again, and checks the stored marker.
It preserves and tests the original recovery credential.
It also compares the original keyslot metadata.

The test uses a low-cost PBKDF only for the random recovery credential on this disposable disk.

The installed `leelo-vm-data.service` unlocks and mounts the data volume after the network starts on the next boot.
`reboot-check` requires a different boot ID.
It checks that the service ran during that boot and read the persistent marker.
It then stops the mapping.
This is a **late-boot data-volume test**.
It does not test initramfs or encrypted-root boot.

The script records PCRs 7 and 11 at enrollment and after reboot.
A legitimate change to a measurement can cause an exact PCR policy to fail.
The script records that failure.
It does not enroll a weaker policy to make the test pass.

## Test failures

Stop the evaluator's HTTP service.
Then run this command on the client:

```sh
sudo bash scripts/fedora/guest-test.sh network-off-check
```

Restart the evaluator's HTTP service.
Then run this command on the client:

```sh
sudo bash scripts/fedora/guest-test.sh negative-tests
```

To control the reboot and failure tests from the host, use these commands:

```sh
sudo bash scripts/fedora/vm-lab.sh ssh client 'sudo systemctl reboot'
sudo bash scripts/fedora/vm-lab.sh wait
sudo bash scripts/fedora/vm-lab.sh ssh client 'sudo bash /home/leelo/leelo/scripts/fedora/guest-test.sh reboot-check'
sudo bash scripts/fedora/vm-lab.sh ssh evaluator 'sudo systemctl stop leelo-http.service'
sudo bash scripts/fedora/vm-lab.sh ssh client 'sudo bash /home/leelo/leelo/scripts/fedora/guest-test.sh network-off-check'
sudo bash scripts/fedora/vm-lab.sh ssh evaluator 'sudo systemctl start leelo-http.service'
sudo bash scripts/fedora/vm-lab.sh ssh client 'sudo bash /home/leelo/leelo/scripts/fedora/guest-test.sh negative-tests'
```

To repeat only the evaluator isolation and TLS checks, run `evaluator-setup.sh verify-existing` inside that guest.
This command does not create keys or change services.
Without this option, the setup helper refuses an existing evaluation key.

Both guest helpers require the `/var/lib/leelo-disposable-vm` marker that the host launcher creates.
The marker prevents accidental use on another machine.
It does not supply authorization.

The negative tests check rejection of an incorrect envelope trust key and a modified signed token.
The tests restore the original token.
They then extend PCR11 on the disposable guest TPM and require automatic unlock to fail.
The recovery credential must still work.
The LUKS metadata must match the enrolled state.

The PCR change is the last test.
It blocks the existing automatic policy until the guest boots into the original measured state again.

## Read the results

`/var/lib/leelo-vm-test/results/` contains reports, phase logs, package and kernel versions, SELinux AVC records, and service journals.
The recovery credentials, administrative private keys, and pending enrollment state remain outside that report directory.
Do not publish those secrets.
The harness keeps the VM fixtures until the host driver collects the report.
The VM manager then stops the guests.

Successful tests with SELinux enforcing do not establish a custom Leelo confinement policy.
Examine the recorded process domains and AVCs.
The tests do not disable SELinux or generate unreviewed allow rules.

Refer to the [Fedora 44 test results](../../docs/fedora-vm-test-report.md) for versions, evidence, and limits.
