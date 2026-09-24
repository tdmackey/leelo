#!/usr/bin/env bash
# Exercise observability with only disposable software-TPM and regular-file LUKS fixtures.
# No host TPM, block device, existing service, or device-mapper mapping is used.
# Fixture roles share the caller UID; this does not qualify production role isolation.
set -euo pipefail
umask 077
repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
for command in cargo cryptsetup swtpm openssl python3 truncate timeout; do
    command -v "$command" >/dev/null || { echo "missing dependency: $command" >&2; exit 1; }
done
cd -- "$repo_dir"
cargo build --locked -p leelo-cli -p leelod -p leelo-collector
target_dir=$(cargo metadata --locked --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')
collector="$target_dir/debug/leelo-collector"
scratch=$(mktemp -d /tmp/leelo-observability.XXXXXXXX)
scratch=$(realpath -- "$scratch")
collector_pid=
full_sink_pid=
cleanup() {
    status=$?
    trap - EXIT
    if [[ "$status" -ne 0 ]]; then
        echo "observability fixture failed (exit $status)" >&2
        for log in collector collected absent full full-sink; do
            if [[ -f "$scratch/$log.log" ]]; then
                echo "$log:" >&2
                tail -n 30 -- "$scratch/$log.log" >&2
            fi
        done
    fi
    for pid in "$collector_pid" "$full_sink_pid"; do
        if [[ -n "$pid" ]]; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        fi
    done
    # Only this script's canonical, private mktemp directory is eligible for removal.
    case "$scratch" in /tmp/leelo-observability.*)
        if [[ -d "$scratch" && ! -L "$scratch" ]]; then rm -rf -- "$scratch"; fi ;;
        *) echo 'refusing unexpected cleanup path' >&2 ;;
    esac
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -- "$scratch/state"
uid=$(id -u)
"$collector" events --socket "$scratch/events.sock" --state-dir "$scratch/state" \
    --source "client:$uid" --source "worker:$uid" --source "frontend:$uid" --source "leelod:$uid" \
    >"$scratch/collector.log" 2>&1 &
collector_pid=$!
python3 - "$scratch/events.sock" "$scratch/state/events.prom" "$collector_pid" <<'PY'
import os, pathlib, sys, time
socket, metrics = map(pathlib.Path, sys.argv[1:3])
for _ in range(100):
    os.kill(int(sys.argv[3]), 0)
    if socket.is_socket() and metrics.is_file():
        break
    time.sleep(0.05)
else:
    raise SystemExit('collector did not become ready within five seconds')
PY

LEELO_EVENTS_SOCKET="$scratch/events.sock" timeout 180 bash scripts/test-e2e.sh >"$scratch/collected.log" 2>&1
python3 - "$scratch/state" "$collector_pid" "$uid" <<'PY'
import collections, json, math, os, pathlib, re, sys, time
state = pathlib.Path(sys.argv[1])
expected = {('enroll', 'success'): 1, ('resume', 'success'): 2,
            ('check', 'success'): 2, ('check', 'failure'): 1}

def load():
    path = state / 'events.jsonl'
    if not path.exists():
        return []
    # A final incomplete append is retried while the collector is alive.
    lines = path.read_bytes().splitlines(keepends=True)
    return [json.loads(line) for line in lines if line.endswith(b'\n')]

for _ in range(100):
    os.kill(int(sys.argv[2]), 0)
    received = load()
    records = [item['record'] for item in received]
    terminal = [item for item in records if item['component'] == 'client'
                and item['event'] == 'operation_completed']
    counts = collections.Counter((item['operation'], item['outcome']) for item in terminal)
    metrics = (state / 'events.prom').read_text()
    if counts == expected and 'leelo_client_operations_total{operation="check",mode="network_bound",outcome="failure"} 1' in metrics:
        break
    time.sleep(0.05)
else:
    raise SystemExit(f'expected terminal outcomes were not collected: {dict(counts)}')

record_keys = {'schema_version', 'component', 'event', 'operation', 'stage', 'outcome',
               'reason', 'duration_seconds', 'mode', 'provider_index', 'storage_state',
               'awaiting_boot_test', 'degraded', 'native_code', 'software_version',
               'attempt_id', 'boot_id', 'sequence', 'unix_time_ms', 'dropped_before'}
assert received, 'collector recorded no events'
for item in received:
    assert set(item) == {'source_uid', 'source_pid', 'received_at_ms', 'record'}, item.keys()
    assert item['source_uid'] == int(sys.argv[3]) and item['source_pid'] > 0
    event = item['record']
    # Exact field allowlisting excludes volume/binding identities and every secret/body field.
    assert set(event) == record_keys, event.keys()
    assert event['schema_version'] == 1
    assert len(json.dumps(event).encode()) <= 4096
    for field in ('component', 'event', 'operation', 'stage', 'outcome', 'reason', 'mode', 'storage_state'):
        assert re.fullmatch(r'[a-z0-9_]{1,48}', event[field]), field
    assert re.fullmatch(r'[A-Za-z0-9_.-]{1,48}', event['software_version'])
    assert math.isfinite(event['duration_seconds']) and 0 <= event['duration_seconds'] <= 604800
    for field in ('attempt_id', 'boot_id'):
        assert event[field] is None or (len(event[field]) == 16 and all(type(b) is int and 0 <= b < 256 for b in event[field]))
    assert event['attempt_id'] is not None, 'fixture events need replay identity'
    assert type(event['awaiting_boot_test']) is bool and type(event['degraded']) is bool

client = [item for item in records if item['component'] == 'client']
assert not any(item['operation'] == 'activate' for item in client), 'check-only fixture must not report activation'
assert all(item['storage_state'] == 'committed' and item['awaiting_boot_test']
           for item in terminal if item['operation'] in ('enroll', 'resume'))
assert all(item['stage'] == 'check' for item in terminal if item['operation'] == 'check' and item['outcome'] == 'success')
assert all(item['stage'] == 'recover' and item['reason'] == 'insufficient_factors'
           for item in terminal if item['operation'] == 'check' and item['outcome'] == 'failure')
assert sum(item['event'] == 'enrollment_state' and item['stage'] == 'storage_committed'
           and item['storage_state'] == 'committed' for item in client) == 3
assert any(item['event'] == 'enrollment_state' and item['stage'] == 'pending_bundle_durable' for item in client)
assert any(item['event'] == 'enrollment_state' and item['stage'] == 'final_journal_durable' for item in client)
providers = [item for item in client if item['event'] == 'provider_completed']
assert all(item['provider_index'] == 1 for item in providers), 'fixture has one configured provider'
assert any(item['outcome'] == 'authenticated' and item['stage'] == 'prepare' for item in providers)
assert any(item['outcome'] == 'authenticated' and item['stage'] == 'recover' for item in providers)
assert any(item['outcome'] == 'failed' and item['reason'] == 'unavailable' for item in providers)
phases = [item for item in client if item['event'] == 'phase_completed']
for stage in ('share_generation', 'prepare_payload', 'network', 'tpm_seal', 'tpm_unseal', 'authenticate_payload'):
    assert any(item['stage'] == stage and item['outcome'] == 'success' for item in phases), stage
assert any(item['stage'] == 'network' and item['outcome'] == 'failure' for item in phases)
for final in terminal:
    attempt = [item for item in client if item['attempt_id'] == final['attempt_id']]
    starts = [item for item in attempt if item['event'] == 'operation_started']
    assert len(starts) == 1 and starts[0]['sequence'] < final['sequence']
    assert sum(item['event'] == 'operation_completed' for item in attempt) == 1
    assert final['sequence'] == max(item['sequence'] for item in attempt)
assert not any(label in metrics for label in ('binding_id=', 'volume_uuid=', 'attempt_id=', 'boot_id=', 'path=', 'url='))
assert 'leelo_collector_events_total{outcome="rejected"} 0' in metrics
print('PASS: actual enrollment, resume, check and failure events; bounded safe schema and truthful terminal outcomes')
print('PASS: storage commit/boot-test state, authenticated provider evidence, network/TPM stages and aggregate metrics')
PY
kill "$collector_pid"
wait "$collector_pid" 2>/dev/null || true
collector_pid=

# Repeat the same real credential operations with no collector at all.
LEELO_EVENTS_SOCKET="$scratch/absent.sock" timeout 180 bash scripts/test-e2e.sh >"$scratch/absent.log" 2>&1
echo 'PASS: absent collector preserves complete enrollment, resume, credential checks and expected network failure'

# A bound datagram socket with a full receive queue simulates a collector that has stopped reading.
python3 - "$scratch/full.sock" "$scratch/full.ready" >"$scratch/full-sink.log" 2>&1 <<'PY' &
import pathlib, signal, socket, sys
receiver = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
receiver.bind(sys.argv[1])
sender = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
sender.setblocking(False)
for _ in range(65536):
    try:
        sender.sendto(b'fixture queue saturation', sys.argv[1])
    except BlockingIOError:
        pathlib.Path(sys.argv[2]).touch()
        break
else:
    raise SystemExit('could not saturate fixture datagram queue')
signal.pause()
PY
full_sink_pid=$!
python3 - "$scratch/full.ready" "$full_sink_pid" <<'PY'
import os, pathlib, sys, time
for _ in range(100):
    os.kill(int(sys.argv[2]), 0)
    if pathlib.Path(sys.argv[1]).is_file():
        break
    time.sleep(0.05)
else:
    raise SystemExit('full datagram fixture did not become ready within five seconds')
PY
LEELO_EVENTS_SOCKET="$scratch/full.sock" timeout 180 bash scripts/test-e2e.sh >"$scratch/full.log" 2>&1
echo 'PASS: full collector queue preserves complete enrollment, resume, credential checks and expected network failure'
echo 'All disposable observability checks passed (credential verification only; no real boot or mapping).'
