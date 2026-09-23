#!/usr/bin/env bash
# Start only a disposable software TPM on loopback. Do not use the host TPM.
set -euo pipefail
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
scratch=$(mktemp -d /tmp/leelo-swtpm.XXXXXXXX)
swtpm_pid=
cleanup() {
    if [[ -n "$swtpm_pid" ]]; then
        kill "$swtpm_pid" 2>/dev/null || true
        wait "$swtpm_pid" 2>/dev/null || true
    fi
    case "$scratch" in /tmp/leelo-swtpm.*) rm -rf -- "$scratch" ;; esac
}
trap cleanup EXIT
chmod 700 "$scratch"
# Reserve and check adjacent command and control ports before you start the simulator.
# Another process can take a port after this check closes it. In that case, swtpm fails.
port=$(python3 - <<'PY'
import socket
for _ in range(100):
    with socket.socket() as command, socket.socket() as control:
        command.bind(('127.0.0.1', 0))
        port = command.getsockname()[1]
        if port == 65535:
            continue
        try:
            control.bind(('127.0.0.1', port + 1))
        except OSError:
            continue
        print(port)
        break
else:
    raise SystemExit('no adjacent loopback ports available')
PY
)
swtpm socket --tpm2 --tpmstate "dir=$scratch" \
    --server "type=tcp,bindaddr=127.0.0.1,port=$port" \
    --ctrl "type=tcp,bindaddr=127.0.0.1,port=$((port + 1))" \
    --flags not-need-init,startup-clear >"$scratch/swtpm.log" 2>&1 &
swtpm_pid=$!
for _ in $(seq 1 50); do
    if ! kill -0 "$swtpm_pid" 2>/dev/null; then
        cat "$scratch/swtpm.log" >&2
        exit 1
    fi
    if python3 - "$port" <<'PY'
import socket, sys
try:
    connection = socket.create_connection(('127.0.0.1', int(sys.argv[1])), timeout=0.1)
    connection.close()
except OSError:
    raise SystemExit(1)
PY
    then break; fi
    sleep 0.1
done
export LEELO_TEST_SWTPM="swtpm:host=127.0.0.1,port=$port"
cd -- "$repo_dir"
cargo test -p leelo-tpm --lib -- --include-ignored --test-threads=1
