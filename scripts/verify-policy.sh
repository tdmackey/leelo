#!/usr/bin/env bash
set -euo pipefail

leelo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
verus_version='0.2026.06.28.1847ab3'
verus_hash='b12a622a2f44c31e72a459fc8b764e8d4bd2275e54995d21c405771b316a81e7'
verus_archive="$leelo_root/.tools/verus-$verus_version-x86-linux.zip"
verus_dir="$leelo_root/.tools/verus-$verus_version-linux"
verus_exe="$verus_dir/verus-x86-linux/verus"

if [[ ! -f "$verus_exe" ]]; then
    if [[ "${1:-}" != '--install-verus' ]]; then
        echo 'Pinned verifier absent; use --install-verus. Rust 1.96.0 must already be available through rustup.' >&2
        exit 1
    fi
    mkdir -p -- "$leelo_root/.tools" "$verus_dir"
    curl --fail --location --proto '=https' --tlsv1.2 \
        "https://github.com/verus-lang/verus/releases/download/release/$verus_version/verus-$verus_version-x86-linux.zip" \
        --output "$verus_archive"
    printf '%s  %s\n' "$verus_hash" "$verus_archive" | sha256sum --check --strict
    unzip -q -o "$verus_archive" -d "$verus_dir"
fi

version_output="$($verus_exe --version)"
[[ "$version_output" == *"$verus_version"* ]] || { echo 'Wrong verifier version.' >&2; exit 1; }
printf '%s\n' "$version_output"
if grep -En '\b(assume|admit)\s*\(|external_body|assume_specification|verifier::external' \
    "$leelo_root/verification/policy.rs" "$leelo_root/crates/leelo-policy/src/verified.rs"; then
    echo 'Unreviewed local proof bypass found.' >&2
    exit 1
fi
cd -- "$leelo_root"
"$verus_exe" --edition=2024 verification/policy.rs --rlimit 40 --no-cheating
