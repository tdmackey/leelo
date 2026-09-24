#!/usr/bin/env bash
# Build and test inside the disposable Fedora client as the unprivileged leelo user.
set -euo pipefail
[[ -f /var/lib/leelo-disposable-vm && $(id -u) -ne 0 ]] || exit 1
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo"
mkdir -p test-results
exec > >(tee test-results/build.log) 2>&1
export PATH="$HOME/.cargo/bin:$PATH"
if ! command -v rustup >/dev/null; then
    rustup-init -y --default-toolchain none --profile minimal --no-modify-path
fi
rustup toolchain install 1.95.0 --profile minimal --component rustfmt --component clippy
export PATH="$(dirname "$(rustup which --toolchain 1.95.0 cargo)"):$PATH"
rustc --version
cargo --version
cat /etc/fedora-release
uname -a
getenforce
rpm -q gcc glibc tpm2-tss tpm2-tss-devel cryptsetup cryptsetup-libs openssl swtpm systemd selinux-policy
bash scripts/check.sh
bash scripts/test-tpm.sh
bash scripts/test-luks.sh
bash scripts/test-enrollment-persistence.sh
bash scripts/test-e2e.sh
rustup toolchain install 1.96.0 --profile minimal
bash scripts/verify.sh --install-verus
echo 'PASS: Fedora build, workspace checks, swtpm and local e2e'
