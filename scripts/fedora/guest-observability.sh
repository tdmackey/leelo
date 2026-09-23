#!/usr/bin/env bash
# Validate observations in the existing disposable Fedora lab. Never formats or enrolls a disk.
set -Eeuo pipefail
umask 077
[[ $(id -u) == 0 ]] || { echo 'run as root inside the disposable guest' >&2; exit 1; }
source /etc/os-release
[[ ${ID:-} == fedora && ${VERSION_ID:-} == 44 && -f /var/lib/leelo-disposable-vm && ! -L /var/lib/leelo-disposable-vm ]] || exit 1
[[ $(getenforce) == Enforcing ]] || { echo 'SELinux must remain enforcing' >&2; exit 1; }
phase=${1:?usage: guest-observability.sh evaluator-install|evaluator-collector-update|evaluator-verify|client-test|capture}
repo=${LEELO_TEST_REPO:-/home/leelo/leelo}
base=/var/lib/leelo-vm-test
results=$base/results/observability
state=/var/lib/leelo-observe-vm
socket=/run/leelo-observe/events.sock
mkdir -p "$results"
chmod 0700 "$results"
exec > >(tee -a "$results/$phase.log") 2>&1
trap 'printf "FAIL: observability phase %s line %s status %s\n" "$phase" "$LINENO" "$?" >&2' ERR

collector_account() {
    getent group leelo-observe >/dev/null || groupadd --system leelo-observe
    getent passwd leelo-collector >/dev/null || useradd --system --gid leelo-observe --home-dir /nonexistent --shell /usr/sbin/nologin leelo-collector
    [[ $(id -u leelo-collector) != 0 ]]
    ! id -nG leelo-collector | tr ' ' '\n' | grep -Fx leelo-ipc >/dev/null
}

install_collector() {
    local sources=$1
    collector_account
    systemctl stop leelo-observe-vm.service 2>/dev/null || true
    install -m 0755 "$repo/target/debug/leelo-collector" /usr/local/bin/leelo-collector
    cat >/etc/systemd/system/leelo-observe-vm.service <<UNIT
[Unit]
Description=Leelo disposable observability validation collector
[Service]
User=leelo-collector
Group=leelo-observe
RuntimeDirectory=leelo-observe
RuntimeDirectoryMode=0750
StateDirectory=leelo-observe-vm
StateDirectoryMode=0700
ExecStart=/usr/local/bin/leelo-collector events --socket $socket --state-dir $state $sources
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictAddressFamilies=AF_UNIX
IPAddressDeny=any
CapabilityBoundingSet=
LimitCORE=0
UMask=0077
UNIT
    restorecon -F /usr/local/bin/leelo-collector /etc/systemd/system/leelo-observe-vm.service
    systemctl daemon-reload
    systemctl start leelo-observe-vm.service
    for _ in $(seq 1 50); do [[ -S $socket ]] && return; sleep 0.1; done
    echo 'collector socket failed to become ready' >&2
    return 1
}

capture() {
    {
        date --iso-8601=seconds
        uname -a
        getenforce
        id leelo-collector
        systemctl show leelo-key.service leelo-http.service leelo-observe-vm.service -p User -p Group -p SupplementaryGroups -p MainPID -p Type -p ActiveState -p RestrictAddressFamilies -p IPAddressDeny -p NoNewPrivileges -p MemoryMax -p TasksMax
    } >"$results/environment.txt" 2>&1
    journalctl -b -u leelo-key.service -u leelo-http.service -u leelo-observe-vm.service --no-pager >"$results/services.txt"
    if [[ -f $state/events.jsonl ]]; then install -m 0600 "$state/events.jsonl" "$results/events.jsonl"; fi
    if [[ -f $state/events.prom ]]; then install -m 0600 "$state/events.prom" "$results/events.prom"; fi
    [[ $(getenforce) == Enforcing ]]
}

case "$phase" in
evaluator-install)
    [[ -s /var/lib/leelo-key/evaluation.key && -s $base/public/server-public.json ]]
    key_before=$(sha256sum /var/lib/leelo-key/evaluation.key | cut -d' ' -f1)
    systemctl stop leelo-http.service leelo-key.service
    install -m 0755 "$repo/target/debug/leelod" /usr/local/bin/leelod
    install_collector "--source worker:$(id -u leelo-key) --source frontend:$(id -u leelo-http)"
    install -d -m 0755 /etc/leelo-observe /etc/systemd/system/leelo-key.service.d /etc/systemd/system/leelo-http.service.d
    printf 'LEELO_COLLECTOR_UID=%s\n' "$(id -u leelo-collector)" >/etc/leelo-observe/collector.env
    printf 'LEELO_COLLECTOR_GID=%s\n' "$(getent group leelo-observe | cut -d: -f3)" >>/etc/leelo-observe/collector.env
    chmod 0644 /etc/leelo-observe/collector.env
    install -m 0644 "$repo/crates/leelod/systemd/leelo-key.service" /etc/systemd/system/leelo-key.service
    install -m 0644 "$repo/crates/leelod/systemd/leelo-http.service" /etc/systemd/system/leelo-http.service
    install -m 0644 "$repo/crates/leelod/systemd/leelo-key-observability.conf" /etc/systemd/system/leelo-key.service.d/observability.conf
    install -m 0644 "$repo/crates/leelod/systemd/leelo-http-observability.conf" /etc/systemd/system/leelo-http.service.d/observability.conf
    restorecon -RF /usr/local/bin/leelod /etc/leelo-observe /etc/systemd/system/leelo-key.service /etc/systemd/system/leelo-http.service /etc/systemd/system/leelo-key.service.d /etc/systemd/system/leelo-http.service.d
    systemctl daemon-reload
    systemctl start leelo-key.service leelo-http.service
    [[ $(sha256sum /var/lib/leelo-key/evaluation.key | cut -d' ' -f1) == "$key_before" ]]
    echo 'PASS: existing evaluation key preserved; updated services and separate-UID collector started'
    ;;
evaluator-collector-update)
    daemon_before=$(sha256sum /usr/local/bin/leelod)
    systemctl stop leelo-observe-vm.service
    install -m 0755 "$repo/target/debug/leelo-collector" /usr/local/bin/leelo-collector
    restorecon -F /usr/local/bin/leelo-collector
    systemctl start leelo-observe-vm.service
    for _ in $(seq 1 50); do [[ -S $socket ]] && break; sleep 0.1; done
    [[ -S $socket ]]
    systemctl start leelo-key.service leelo-http.service
    [[ $(sha256sum /usr/local/bin/leelod) == "$daemon_before" ]]
    echo 'PASS: collector updated; deployed daemon binary unchanged'
    ;;
evaluator-verify)
    systemctl is-active --quiet leelo-key.service leelo-http.service leelo-observe-vm.service
    for role in key http; do
        case "$role" in key) expected_role=worker; wrong_role=frontend ;; http) expected_role=frontend; wrong_role=worker ;; esac
        runuser -u leelo-collector -- /usr/local/bin/leelo-collector snapshot --socket "/run/leelo-$role-metrics/metrics.sock" --server-uid "$(id -u "leelo-$role")" --role "$expected_role" --output "$state/$role.prom"
        snapshot_before=$(sha256sum "$state/$role.prom")
        if runuser -u leelo-collector -- /usr/local/bin/leelo-collector snapshot --socket "/run/leelo-$role-metrics/metrics.sock" --server-uid "$(id -u "leelo-$role")" --role "$wrong_role" --output "$state/$role.prom" >"$results/$role-wrong-role.stdout" 2>"$results/$role-wrong-role.stderr"; then
            echo 'snapshot accepted a role different from trusted configuration' >&2
            exit 1
        fi
        [[ $(sha256sum "$state/$role.prom") == "$snapshot_before" ]]
        install -m 0600 "$state/$role.prom" "$results/$role.prom"
    done
    echo 'PASS: trusted snapshot role matches each UID; both wrong-role requests rejected without replacing output'
    runuser -u leelo-collector -- python3 - <<'PY'
import socket
try:
    open('/var/lib/leelo-key/evaluation.key','rb')
except PermissionError:
    pass
else:
    raise SystemExit('collector could read evaluation key')
with socket.socket(socket.AF_UNIX) as stream:
    stream.settimeout(1)
    try:
        stream.connect('/run/leelo-key/evaluator.sock')
    except PermissionError:
        pass
    else:
        raise SystemExit('collector could reach evaluator socket')
print('PASS: collector cannot read evaluation key or connect to evaluator socket')
PY
    runuser -u leelo-http -G leelo-observe -- python3 - <<'PY'
import socket
with socket.socket(socket.AF_UNIX) as stream:
    stream.settimeout(1)
    stream.connect('/run/leelo-key-metrics/metrics.sock')
    try:
        received=stream.recv(1)
    except ConnectionResetError:
        received=b''
    assert not received, 'wrong UID received snapshot'
print('PASS: observation-group member with wrong kernel UID denied snapshot')
PY
    python3 - "$results" "$state" <<'PY'
import json,pathlib,subprocess,sys,time
results,state=map(pathlib.Path,sys.argv[1:])
properties=subprocess.check_output(['systemctl','show','leelo-key.service','-p','RestrictAddressFamilies','-p','IPAddressDeny','-p','NoNewPrivileges'],text=True)
assert 'RestrictAddressFamilies=AF_UNIX' in properties and 'AF_INET' not in properties
assert 'NoNewPrivileges=yes' in properties
assert any(line.startswith('IPAddressDeny=') and line != 'IPAddressDeny=' for line in properties.splitlines())
for role in ['key','http']:
    text=(results/f'{role}.prom').read_text()
    assert len(text.encode())<=65536 and 'leelo_inflight{' in text
    pid=int(subprocess.check_output(['systemctl','show',f'leelo-{role}.service','-p','MainPID','--value']))
    status=pathlib.Path(f'/proc/{pid}/status').read_text()
    assert 'Seccomp:\t2' in status and 'NoNewPrivs:\t1' in status
deadline=time.monotonic()+3
while time.monotonic()<deadline:
    records=[json.loads(line)['record'] for line in (state/'events.jsonl').read_bytes().split(b'\n')[:-1]]
    if all(any(r['component']==component and r['event']=='service_ready' for r in records) for component in ['worker','frontend']): break
    time.sleep(.1)
else: raise SystemExit('missing daemon readiness events')
print('PASS: snapshots collected; both startup events received; worker retains AF_UNIX/IP denial and seccomp')
PY
    ;;
client-test)
    [[ -s $base/enrollment.json && -s $base/admin.pub && -s $base/trust/providers.json ]]
    device=$(readlink -f /dev/disk/by-id/virtio-leelo-test-data)
    [[ -b $device && $(lsblk -dn -o SERIAL "$device" | xargs) == leelo-test-data && $(blockdev --getsize64 "$device") == 1073741824 ]]
    [[ -z $(find "/sys/class/block/$(basename "$device")/holders" -mindepth 1 -maxdepth 1 -print) ]]
    token=$(python3 -c 'import json,sys; x=json.load(open(sys.argv[1])); assert x["enrolled"] and 0<=x["token"]<32; print(x["token"])' "$base/enrollment.json")
    cryptsetup luksDump --dump-json-metadata "$device" | sha256sum >"$results/header-before.sha256"
    install -m 0755 "$repo/target/debug/leelo" /usr/local/bin/leelo
    install -m 0755 "$repo/target/debug/leelo-probe" /usr/local/bin/leelo-probe
    install_collector '--source client:0'
    events_before=$(wc -l <"$state/events.jsonl")
    sleep 1
    install -m 0600 "$state/events.prom" "$results/collector-before.prom"
    install -d -o root -g leelo-observe -m 0750 /etc/leelo-observe-probe
    install -o root -g leelo-observe -m 0640 "$base/trust/ca.pem" /etc/leelo-observe-probe/ca.pem
    python3 - "$base/trust/providers.json" <<'PY'
import json,pathlib,sys
config=json.load(open(sys.argv[1]))
for provider in config['providers']: provider['ca_file']='ca.pem'
pathlib.Path('/etc/leelo-observe-probe/providers.json').write_text(json.dumps(config))
PY
    chown root:leelo-observe /etc/leelo-observe-probe/providers.json
    chmod 0640 /etc/leelo-observe-probe/providers.json
    restorecon -RF /usr/local/bin/leelo /usr/local/bin/leelo-probe /etc/leelo-observe-probe
    runuser -u leelo-collector -- /usr/local/bin/leelo-probe --config /etc/leelo-observe-probe/providers.json --target 1 --textfile "$state/probe.prom" >"$results/probe.json"
    install -m 0600 "$state/probe.prom" "$results/probe.prom"
    python3 - "$results/probe.json" "$base/trust/providers.json" "$base/trust/ca.pem" <<'PY'
import datetime,json,ssl,socket,sys,urllib.parse
report=json.load(open(sys.argv[1])); provider=json.load(open(sys.argv[2]))['providers'][0]
assert report['success'] and report['collection_success'] and report['clock_valid']
url=urllib.parse.urlsplit(provider['url']); context=ssl.create_default_context(cafile=sys.argv[3]); context.minimum_version=ssl.TLSVersion.TLSv1_3
with socket.create_connection((url.hostname,url.port or 443),timeout=5) as tcp:
    with context.wrap_socket(tcp,server_hostname=url.hostname) as tls:
        observed=int(ssl.cert_time_to_seconds(tls.getpeercert()['notAfter']))
assert report['certificate_not_after_timestamp_seconds']==observed
print('PASS: unprivileged full proof probe and observed leaf certificate expiry verified')
PY
    LEELO_EVENTS_SOCKET="$socket" timeout 45s /usr/local/bin/leelo unlock --device "$device" --config "$base/trust/providers.json" --trust-key "$base/admin.pub" --token "$token" --tcti device:/dev/tpmrm0 --check-only >"$results/check.json"
    mapping=leelo-observability-test
    mountdir=/mnt/leelo-observability-test
    [[ ! -e /dev/mapper/$mapping ]]
    ! mountpoint -q "$mountdir"
    cleanup_mapping() {
        local status=$?
        trap - EXIT
        if mountpoint -q "$mountdir"; then umount "$mountdir"; fi
        if [[ -b /dev/mapper/$mapping ]]; then
            local backing
            backing=$(cryptsetup status "$mapping" | awk '$1=="device:" {print $2}')
            [[ $(readlink -f "$backing") == "$device" ]] && cryptsetup close "$mapping"
        fi
        exit "$status"
    }
    trap cleanup_mapping EXIT
    LEELO_EVENTS_SOCKET="$socket" timeout 45s /usr/local/bin/leelo unlock --device "$device" --config "$base/trust/providers.json" --trust-key "$base/admin.pub" --token "$token" --tcti device:/dev/tpmrm0 --mapping "$mapping" >"$results/activation.json"
    [[ -b /dev/mapper/$mapping ]]
    install -d -m 0700 "$mountdir"
    mount -o ro "/dev/mapper/$mapping" "$mountdir"
    cmp "$base/expected-marker" "$mountdir/marker"
    umount "$mountdir"
    cryptsetup close "$mapping"
    trap - EXIT
    python3 - "$state/events.jsonl" "$events_before" <<'PY'
import json,pathlib,sys,time
deadline=time.monotonic()+3
while time.monotonic()<deadline:
    records=[json.loads(line)['record'] for line in pathlib.Path(sys.argv[1]).read_bytes().split(b'\n')[:-1][int(sys.argv[2]):]]
    terminal=[r for r in records if r['event']=='operation_completed' and r['outcome']=='success']
    if any(r['operation']=='check' for r in terminal) and any(r['operation']=='activate' for r in terminal): break
    time.sleep(.1)
else: raise SystemExit('missing distinct check and activation terminal events')
providers=[r for r in records if r['event']=='provider_completed']
assert len(providers)>=2 and all(r['provider_index']==1 for r in providers), 'provider index must match one-based trusted configuration'
assert all(r['dropped_before']==0 for r in records), 'normal sequence lost events'
print('PASS: real TPM/LUKS credential check and actual mapping activation produced distinct success events')
print('PASS: provider observations use trusted configuration index 1; no emitted-event loss observed')
PY
    sleep 1
    install -m 0600 "$state/events.prom" "$results/collector-after.prom"
    python3 - "$results/collector-before.prom" "$results/collector-after.prom" <<'PY'
import pathlib,sys
def rejected(path):
    text=pathlib.Path(path).read_text()
    return next(int(line.rsplit(' ',1)[1]) for line in text.splitlines() if line.startswith('leelo_collector_events_total{outcome="rejected"}'))
assert rejected(sys.argv[1])==rejected(sys.argv[2]), 'normal sequence produced schema-rejected events'
print('PASS: collector schema-rejection counter unchanged during normal check/activation sequence')
PY
    systemctl stop leelo-observe-vm.service
    LEELO_EVENTS_SOCKET="$socket" timeout 45s /usr/local/bin/leelo unlock --device "$device" --config "$base/trust/providers.json" --trust-key "$base/admin.pub" --token "$token" --tcti device:/dev/tpmrm0 --check-only >"$results/check-collector-outage.json"
    cryptsetup luksDump --dump-json-metadata "$device" | sha256sum >"$results/header-after.sha256"
    cmp "$results/header-before.sha256" "$results/header-after.sha256"
    echo 'PASS: missing collector did not prevent credential check; existing LUKS metadata unchanged'
    ;;
capture) ;;
*) echo 'unknown phase' >&2; exit 1 ;;
esac
capture
echo "PASS: $phase"
