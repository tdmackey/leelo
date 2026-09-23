#!/usr/bin/env bash
# Test the full userspace path in a new /tmp fixture.
# The test does not use a host TPM, block device, device-mapper mapping, or existing LUKS header.
set -euo pipefail
umask 077
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
for command in cargo cryptsetup swtpm openssl python3 truncate; do
    command -v "$command" >/dev/null || { echo "missing dependency: $command" >&2; exit 1; }
done
cd -- "$repo_dir"
cargo build --locked -p leelo-cli -p leelod
target_dir=$(cargo metadata --locked --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
leelo="$target_dir/debug/leelo"
leelod="$target_dir/debug/leelod"
scratch=$(mktemp -d /tmp/leelo-e2e.XXXXXXXX)
scratch=$(realpath -- "$scratch")
image="$scratch/volume.luks"
swtpm_pid=
worker_pid=
frontend_pid=
cleanup() {
    status=$?
    trap - EXIT
    if [[ "$status" -ne 0 ]]; then
        echo "e2e failed (exit $status); fixture process logs:" >&2
        for log in swtpm worker frontend; do
            if [[ -f "$scratch/$log.log" ]]; then
                echo "$log:" >&2
                tail -n 30 -- "$scratch/$log.log" >&2
            fi
        done
    fi
    for pid in "$frontend_pid" "$worker_pid" "$swtpm_pid"; do
        if [[ -n "$pid" ]]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    # The code above created this directory. No argument supplied the path.
    case "$scratch" in /tmp/leelo-e2e.*)
        if [[ -d "$scratch" && ! -L "$scratch" ]]; then rm -rf -- "$scratch"; fi ;;
        *) echo "refusing unexpected cleanup path" >&2 ;;
    esac
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

guard_image() {
    python3 - "$scratch" "$image" <<'PY'
import os, pathlib, stat, sys
root, image = map(pathlib.Path, sys.argv[1:])
assert root.parent == pathlib.Path('/tmp') and root.name.startswith('leelo-e2e.')
assert root.resolve() == root and not root.is_symlink()
assert image == root / 'volume.luks' and image.resolve() == image
st = image.lstat()
assert stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and st.st_nlink == 1
assert st.st_size == 64 * 1024 * 1024
PY
}
wait_tcp() {
    python3 - "$1" "$2" <<'PY'
import os, socket, sys, time
port, pid = map(int, sys.argv[1:])
for _ in range(100):
    os.kill(pid, 0)
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=0.1):
            break
    except OSError:
        time.sleep(0.05)
else:
    raise SystemExit('fixture listener did not become ready')
PY
}
metadata() {
    guard_image
    cryptsetup luksDump --dump-json-metadata "$image" >"$1"
}
check_recovery() {
    guard_image
    cryptsetup open --test-passphrase --key-slot 0 --key-file "$scratch/recovery.key" "$image"
}
unlock() {
    "$leelo" unlock --device "$image" --config "$scratch/providers.json" \
        --trust-key "$scratch/admin.pub" --token "$token" --tcti "$tcti" --check-only
}
resume() {
    guard_image
    "$leelo" resume-enrollment --device "$image" --config "$scratch/providers.json" \
        --trust-key "$scratch/admin.pub" --pending-bundle "$pending" --tcti "$tcti"
}

read -r tpm_port tls_port < <(python3 - <<'PY'
import socket
for _ in range(100):
    with socket.socket() as command, socket.socket() as control, socket.socket() as tls:
        command.bind(('127.0.0.1', 0))
        port = command.getsockname()[1]
        if port == 65535:
            continue
        try:
            control.bind(('127.0.0.1', port + 1))
        except OSError:
            continue
        tls.bind(('127.0.0.1', 0))
        print(port, tls.getsockname()[1])
        break
else:
    raise SystemExit('no fixture ports available')
PY
)
mkdir "$scratch/tpm"
swtpm socket --tpm2 --tpmstate "dir=$scratch/tpm" \
    --server "type=tcp,bindaddr=127.0.0.1,port=$tpm_port" \
    --ctrl "type=tcp,bindaddr=127.0.0.1,port=$((tpm_port + 1))" \
    --flags not-need-init,startup-clear >"$scratch/swtpm.log" 2>&1 &
swtpm_pid=$!
wait_tcp "$tpm_port" "$swtpm_pid"
tcti="swtpm:host=127.0.0.1,port=$tpm_port"

# A real CA and a separate server certificate test hostname and root validation.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$scratch/ca.key" -out "$scratch/ca.pem" -days 1 \
    -subj '/CN=Leelo disposable fixture CA' \
    -addext 'basicConstraints=critical,CA:TRUE' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' >"$scratch/cert.log" 2>&1
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "$scratch/server.key" -out "$scratch/server.csr" \
    -subj '/CN=localhost' >>"$scratch/cert.log" 2>&1
cat >"$scratch/leaf.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF
openssl x509 -req -in "$scratch/server.csr" -CA "$scratch/ca.pem" \
    -CAkey "$scratch/ca.key" -CAcreateserial -days 1 -sha256 \
    -extfile "$scratch/leaf.ext" -out "$scratch/server.pem" >>"$scratch/cert.log" 2>&1
"$leelod" keygen --key "$scratch/evaluation.key" >"$scratch/server-public.json"
"$leelod" worker --key "$scratch/evaluation.key" --socket "$scratch/worker.sock" \
    --allow-uid "$(id -u)" >"$scratch/worker.log" 2>&1 &
worker_pid=$!
python3 - "$scratch/worker.sock" "$worker_pid" <<'PY'
import os, pathlib, sys, time
for _ in range(100):
    os.kill(int(sys.argv[2]), 0)
    if pathlib.Path(sys.argv[1]).is_socket():
        break
    time.sleep(0.05)
else:
    raise SystemExit('fixture worker did not become ready')
PY
"$leelod" serve --listen "127.0.0.1:$tls_port" --cert "$scratch/server.pem" \
    --tls-key "$scratch/server.key" --worker-socket "$scratch/worker.sock" \
    >"$scratch/frontend.log" 2>&1 &
frontend_pid=$!
wait_tcp "$tls_port" "$frontend_pid"
python3 - "$scratch" "$tls_port" <<'PY'
import json, pathlib, secrets, sys
root = pathlib.Path(sys.argv[1])
public = json.loads((root / 'server-public.json').read_text())
provider = dict(provider_id=secrets.token_hex(32), **public,
                url=f'https://127.0.0.1:{sys.argv[2]}/', ca_file=str(root / 'ca.pem'))
(root / 'providers.json').write_text(json.dumps(dict(providers=[provider])))
(root / 'recovery.key').write_bytes(secrets.token_bytes(32))
PY
"$leelo" keygen --private "$scratch/admin.key" --public "$scratch/admin.pub"
truncate -s 64M -- "$image"
guard_image
# This low-cost KDF applies only to the random credential in this disposable fixture.
cryptsetup luksFormat --type luks2 --batch-mode --key-file "$scratch/recovery.key" \
    --pbkdf pbkdf2 --pbkdf-force-iterations 1000 "$image"
metadata "$scratch/before.json"
guard_image
"$leelo" enroll --device "$image" --config "$scratch/providers.json" \
    --existing-key-file "$scratch/recovery.key" --signing-key "$scratch/admin.key" \
    --journal "$scratch/enrollment.journal" --tcti "$tcti" --pcr-mask 2176 --threshold 1 \
    >"$scratch/enrollment.json"
read -r token slot pending < <(python3 - "$scratch/enrollment.json" <<'PY'
import json, pathlib, sys
data = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert data['enrolled'] and data['old_slots_preserved']
assert data['production_boot_test_required']
assert data['slot'] == 1 and 0 <= data['token'] < 32
print(data['token'], data['slot'], data['pending_bundle'])
PY
)
[[ "$pending" == "$scratch/enrollment.pending.leelo" && -f "$pending" ]]
"$leelo" inspect --envelope "$pending" --trust-key "$scratch/admin.pub" >"$scratch/inspect.json"
unlock
check_recovery
metadata "$scratch/enrolled.json"
python3 - "$scratch/before.json" "$scratch/enrolled.json" "$token" "$slot" <<'PY'
import json, pathlib, sys
before, after = [json.loads(pathlib.Path(p).read_text()) for p in sys.argv[1:3]]
assert set(before['keyslots']) == {'0'} and not before['tokens']
assert set(after['keyslots']) == {'0', sys.argv[4]}
assert after['keyslots']['0'] == before['keyslots']['0']
assert set(after['tokens']) == {sys.argv[3]}
assert after['tokens'][sys.argv[3]]['keyslots'] == [sys.argv[4]]
PY
echo 'PASS: TLS + worker + TPM + LUKS2 enrollment; original recovery slot preserved'

# Simulate an interrupted commit with a durable slot and a missing token.
# Do not remove or overwrite a keyslot, including the newly enrolled slot.
guard_image
cryptsetup token remove --token-id "$token" "$image"
metadata "$scratch/orphan.json"
python3 - "$scratch/orphan.json" <<'PY'
import json, pathlib, sys
data = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert set(data['keyslots']) == {'0', '1'} and not data['tokens']
PY
resume >"$scratch/resume.json"
token=$(python3 - "$scratch/resume.json" <<'PY'
import json, pathlib, sys
data = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert data['resumed'] and data['enrolled'] and data['slot'] == 1
assert 0 <= data['token'] < 32
print(data['token'])
PY
)
unlock
check_recovery
metadata "$scratch/resumed.json"
resume >"$scratch/resume-again.json"
metadata "$scratch/resumed-again.json"
python3 - "$scratch" "$token" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
first = json.loads((root / 'resumed.json').read_text())
second = json.loads((root / 'resumed-again.json').read_text())
assert first == second and set(second['keyslots']) == {'0', '1'}
assert set(second['tokens']) == {sys.argv[2]}
assert json.loads((root / 'resume-again.json').read_text())['token'] == int(sys.argv[2])
PY
echo 'PASS: signed pending-bundle repair and idempotent resume; no additional slot/token'

kill "$frontend_pid"
wait "$frontend_pid" 2>/dev/null || true
frontend_pid=
if unlock >"$scratch/offline.out" 2>"$scratch/offline.err"; then
    echo 'network-off unlock unexpectedly succeeded' >&2
    exit 1
fi
check_recovery
metadata "$scratch/offline.json"
cmp -- "$scratch/resumed-again.json" "$scratch/offline.json"
echo 'PASS: absent network refuses automatic unlock; recovery credential still works'
echo 'All disposable e2e checks passed (credential verification only; no real boot or mapping).'
