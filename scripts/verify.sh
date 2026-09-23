#!/usr/bin/env bash
set -euo pipefail
leelo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
bash "$leelo_root/scripts/verify-policy.sh" "${1:-}"
verus_exe="$leelo_root/.tools/verus-0.2026.06.28.1847ab3-linux/verus-x86-linux/verus"
if grep -En '\b(assume|admit)\s*\(|external_body|assume_specification|verifier::external' \
    "$leelo_root/verification/gf256.rs" "$leelo_root/crates/leelo-sss/src/gf256.rs"; then
    echo 'Unreviewed arithmetic proof bypass found.' >&2
    exit 1
fi
cd -- "$leelo_root"
"$verus_exe" --edition=2024 verification/gf256.rs --rlimit 15 --no-cheating
