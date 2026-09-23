#!/usr/bin/env bash
# Test actual pending-bundle/journal I/O failures and resume on disposable files.
# No host block device, device-mapper activation, network service, or TPM is used.
set -euo pipefail
umask 077
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
for command in cargo cryptsetup; do
    command -v "$command" >/dev/null || { echo "missing dependency: $command" >&2; exit 1; }
done
cd -- "$repo_dir"
cargo test --locked -p leelo-cli enrollment::tests -- --include-ignored --test-threads=1
