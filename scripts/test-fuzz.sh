#!/usr/bin/env bash
set -euo pipefail
leelo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd -- "$leelo_root"
nightly=nightly-2026-09-22
seconds="${LEELO_FUZZ_SECONDS:-10}"
runs="${LEELO_FUZZ_RUNS:-2000}"
if [[ ! "$seconds" =~ ^[1-9][0-9]*$ || ! "$runs" =~ ^[1-9][0-9]*$ ]]; then
    echo 'LEELO_FUZZ_SECONDS and LEELO_FUZZ_RUNS must be positive integers.' >&2
    exit 1
fi
if [[ "$(cargo fuzz --version)" != 'cargo-fuzz 0.13.2' ]]; then
    echo 'Install the pinned runner: cargo install cargo-fuzz --version 0.13.2 --locked' >&2
    exit 1
fi
cargo test --manifest-path fuzz/Cargo.toml --locked
cargo fetch --manifest-path fuzz/Cargo.toml --locked
lock_digest="$(sha256sum fuzz/Cargo.lock)"
for target in envelope wire crypto_encodings luks_token policy; do
    case "$target" in
        envelope) max_len=65537 ;;
        wire) max_len=154 ;;
        crypto_encodings) max_len=200 ;;
        luks_token) max_len=92161 ;;
        policy) max_len=1024 ;;
    esac
    corpus="$leelo_root/.tools/fuzz-corpus/$target"
    mkdir -p -- "$corpus"
    cp -- "$leelo_root/fuzz/seeds/$target/"* "$corpus/"
    CARGO_NET_OFFLINE=true cargo +"$nightly" fuzz run "$target" "$corpus" --fuzz-dir "$leelo_root/fuzz" \
        --features fuzzing -- -max_total_time="$seconds" -runs="$runs" \
        -max_len="$max_len" -timeout=5 -rss_limit_mb=2048 -seed=1
    if [[ "$(sha256sum fuzz/Cargo.lock)" != "$lock_digest" ]]; then
        echo 'Fuzz build changed the reviewed lockfile.' >&2
        exit 1
    fi
done
