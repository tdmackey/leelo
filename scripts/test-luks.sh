#!/usr/bin/env bash
# Run storage regressions on new regular-file images under /tmp.
# These tests do not use a host block device, TPM, or device-mapper mapping.
set -euo pipefail
umask 077
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
for command in cargo cryptsetup; do
    command -v "$command" >/dev/null || { echo "missing dependency: $command" >&2; exit 1; }
done
cd -- "$repo_dir"
cargo test --locked -p leelo-luks --lib -- --ignored --test-threads=1
