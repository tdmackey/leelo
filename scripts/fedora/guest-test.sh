#!/usr/bin/env bash
# This harness tests disposable Fedora VMs. Do not use it on a production guest.
# It formats only a 1 GiB secondary disk with the specified virtio serial.
set -euo pipefail
umask 077
[[ $(id -u) == 0 ]] || { echo 'run through sudo in the disposable guest' >&2; exit 1; }
source /etc/os-release
[[ ${ID:-} == fedora && ${VERSION_ID:-} == 44 ]] || { echo 'this fixture requires Fedora 44' >&2; exit 1; }
[[ -f /var/lib/leelo-disposable-vm && ! -L /var/lib/leelo-disposable-vm ]] || {
    echo 'missing disposable-guest marker; refusing to modify this machine' >&2; exit 1;
}
phase=${1:?usage: guest-test.sh PHASE}
case "$phase" in
    evaluator-setup|client-enroll|boot-unlock|boot-stop|reboot-check|network-off-check|negative-tests|capture) ;;
    *) echo "unknown phase: $phase" >&2; exit 1 ;;
esac
repo=${LEELO_TEST_REPO:-/home/leelo/leelo}
base=/var/lib/leelo-vm-test
results=$base/results
trust=$base/trust
device_link=/dev/disk/by-id/virtio-leelo-test-data
mapping=leelo-vm-test-data
mountpoint=/mnt/leelo-vm-test
leelo=/usr/local/bin/leelo
tcti=device:/dev/tpmrm0
mkdir -p "$results"
chmod 700 "$base" "$results"
exec > >(tee -a "$results/$phase.log") 2>&1

fail() { echo "FAIL: $*" >&2; exit 1; }
guard_disk() {
    [[ -L "$device_link" ]] || fail "missing dedicated virtio serial link"
    device=$(readlink -f -- "$device_link")
    [[ -b "$device" ]] || fail 'test target is not a block device'
    [[ $(lsblk -dn -o SERIAL "$device" | xargs) == leelo-test-data ]] || fail 'disk serial mismatch'
    [[ $(blockdev --getsize64 "$device") == 1073741824 ]] || fail 'disk must be exactly 1 GiB'
    [[ $(lsblk -dn -o TYPE "$device" | xargs) == disk ]] || fail 'target must be whole test disk'
    [[ $(lsblk -nr -o NAME "$device" | wc -l) == 1 ]] || fail 'test disk has children/holders'
    [[ -z $(lsblk -nr -o MOUNTPOINTS "$device" | tr -d '[:space:]') ]] || fail 'test disk is mounted'
    [[ -z $(find "/sys/class/block/$(basename "$device")/holders" -mindepth 1 -maxdepth 1 -print) ]] || fail 'test disk has holders'
    [[ $(blockdev --getro "$device") == 0 ]] || fail 'test disk is read-only'
}
load_enrollment() {
    [[ -f "$base/enrollment.json" ]] || fail 'missing enrollment state'
    read -r token slot < <(python3 - "$base/enrollment.json" <<'PY'
import json, pathlib, sys
x=json.loads(pathlib.Path(sys.argv[1]).read_text())
assert x['enrolled'] and x['old_slots_preserved'] and x['slot']==1
assert 0 <= x['token'] < 32
print(x['token'],x['slot'])
PY
)
    [[ -n ${token:-} && ${slot:-} == 1 ]] || fail 'invalid enrollment state'
}
unlock_check() {
    guard_disk
    "$leelo" unlock --device "$device" --config "$trust/providers.json" \
        --trust-key "$base/admin.pub" --token "$token" --tcti "$tcti" --check-only
}
recovery_check() {
    cryptsetup open --test-passphrase --key-slot 0 --key-file "$base/recovery.key" "$device_link"
}
close_own_mapping() {
    if mountpoint -q "$mountpoint"; then
        local source
        source=$(findmnt -n -o SOURCE --target "$mountpoint")
        [[ $(readlink -f -- "$source") == $(readlink -f -- "/dev/mapper/$mapping") ]] || fail 'unexpected mount source'
        umount -- "$mountpoint"
    fi
    if [[ -e /dev/mapper/$mapping ]]; then
        local active_device
        active_device=$(cryptsetup status "$mapping" | awk '$1=="device:" {print $2}')
        [[ $(readlink -f -- "$active_device") == $(readlink -f -- "$device_link") ]] || fail 'unexpected mapping device'
        cryptsetup close "$mapping"
    fi
}
open_mapping() {
    guard_disk
    load_enrollment
    [[ ! -e /dev/mapper/$mapping ]] || fail 'mapping name already exists'
    "$leelo" unlock --device "$device" --config "$trust/providers.json" \
        --trust-key "$base/admin.pub" --token "$token" --tcti "$tcti" --mapping "$mapping"
    [[ -b /dev/mapper/$mapping ]] || fail 'mapping was not created'
    local active_device
    active_device=$(cryptsetup status "$mapping" | awk '$1=="device:" {print $2}')
    [[ $(readlink -f -- "$active_device") == $(readlink -f -- "$device_link") ]] || fail 'mapping targets unexpected device'
}
capture() {
    {
        date --iso-8601=seconds
        cat /etc/os-release
        uname -a
        rpm -q cryptsetup cryptsetup-libs tpm2-tss tpm2-tools selinux-policy-targeted systemd
        getenforce
        lsblk -o NAME,SIZE,TYPE,SERIAL,FSTYPE,MOUNTPOINTS
        ps -eZ | grep -E 'leelo|LABEL' || true
        ls -lZ /usr/local/bin/leelo /usr/local/bin/leelod /dev/tpm* "$base" 2>/dev/null || true
        systemctl status leelo-vm-data.service leelo-key.service leelo-http.service --no-pager || true
    } >"$results/environment-$phase.txt" 2>&1
    ausearch -m AVC,USER_AVC -ts boot >"$results/selinux-$phase.txt" 2>&1 || true
    journalctl -b -u leelo-vm-data.service -u leelo-key.service -u leelo-http.service --no-pager >"$results/services-$phase.txt" 2>&1 || true
}
require_environment() {
    [[ $(getenforce) == Enforcing ]] || fail 'SELinux must remain enforcing'
    [[ -c /dev/tpmrm0 ]] || fail 'guest-visible TPM resource-manager device missing'
    [[ -s "$trust/providers.json" && -s "$trust/ca.pem" ]] || fail 'trusted evaluator handoff missing'
}
finish() {
    local status=$?
    trap - EXIT
    capture || true
    exit "$status"
}
trap finish EXIT

case "$phase" in
evaluator-setup)
    exec bash "$repo/scripts/fedora/evaluator-setup.sh"
    ;;
client-enroll)
    require_environment
    guard_disk
    [[ ! -e "$base/enrollment.json" && ! -e "$base/recovery.key" ]] || fail 'client enrollment already started'
    [[ -z $(wipefs --noheadings --output TYPE "$device") ]] || fail 'test disk is not blank'
    install -m 0755 "$repo/target/debug/leelo" "$leelo"
    install -d -m 0755 /usr/local/libexec
    install -m 0755 "$repo/scripts/fedora/guest-test.sh" /usr/local/libexec/leelo-vm-test
    "$leelo" keygen --private "$base/admin.key" --public "$base/admin.pub"
    openssl rand -out "$base/recovery.key" 32
    openssl rand -hex 32 >"$base/expected-marker"
    tpm2_pcrread -T "$tcti" sha256:7,11 >"$results/pcr-enrollment.txt"
    "$leelo" pcr-digest --tcti "$tcti" --pcr-mask 2176 >"$results/pcr-digest-enrollment.txt"
    # This low-cost PBKDF applies only to the random key in this disposable fixture.
    guard_disk
    cryptsetup luksFormat --type luks2 --batch-mode --key-file "$base/recovery.key" \
        --pbkdf pbkdf2 --pbkdf-force-iterations 1000 "$device"
    cryptsetup luksDump --dump-json-metadata "$device" >"$results/header-before.json"
    "$leelo" enroll --device "$device" --config "$trust/providers.json" \
        --existing-key-file "$base/recovery.key" --signing-key "$base/admin.key" \
        --journal "$base/enrollment.journal" --tcti "$tcti" --pcr-mask 2176 --threshold 1 \
        >"$base/enrollment.json"
    load_enrollment
    "$leelo" inspect --envelope "$base/enrollment.pending.leelo" --trust-key "$base/admin.pub" >"$results/envelope-inspect.json"
    unlock_check
    recovery_check
    cryptsetup luksDump --dump-json-metadata "$device" >"$results/header-enrolled.json"
    python3 - "$results" "$token" <<'PY'
import json,pathlib,sys
r=pathlib.Path(sys.argv[1]); before=json.loads((r/'header-before.json').read_text()); after=json.loads((r/'header-enrolled.json').read_text())
assert set(before['keyslots'])=={'0'} and not before['tokens']
assert set(after['keyslots'])=={'0','1'} and before['keyslots']['0']==after['keyslots']['0']
assert set(after['tokens'])=={sys.argv[2]} and after['tokens'][sys.argv[2]]['keyslots']==['1']
PY
    open_mapping
    mkfs.ext4 -q -F "/dev/mapper/$mapping"
    mkdir -p "$mountpoint"
    mount "/dev/mapper/$mapping" "$mountpoint"
    install -m 0600 "$base/expected-marker" "$mountpoint/marker"
    sync
    cmp "$base/expected-marker" "$mountpoint/marker"
    close_own_mapping
    open_mapping
    mount "/dev/mapper/$mapping" "$mountpoint"
    cmp "$base/expected-marker" "$mountpoint/marker"
    close_own_mapping
    cat >/etc/systemd/system/leelo-vm-data.service <<'UNIT'
[Unit]
Description=Leelo disposable data-volume late-boot test
Wants=network-online.target
After=network-online.target
ConditionPathExists=/var/lib/leelo-vm-test/enrollment.json

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/libexec/leelo-vm-test boot-unlock
ExecStop=/usr/local/libexec/leelo-vm-test boot-stop
TimeoutStartSec=90
UMask=0077
LimitCORE=0

[Install]
WantedBy=multi-user.target
UNIT
    restorecon -F /usr/local/bin/leelo /usr/local/libexec/leelo-vm-test /etc/systemd/system/leelo-vm-data.service
    systemctl daemon-reload
    systemctl enable leelo-vm-data.service
    cat /proc/sys/kernel/random/boot_id >"$base/enrollment-boot-id"
    "$leelo" --version >"$results/leelo-version.txt"
    capture
    echo 'PASS: guest TPM + remote TLS + dedicated LUKS2 disk + mapping/mount/read; recovery slot preserved'
    echo 'READY: reboot client, then run reboot-check'
    ;;
boot-unlock)
    require_environment
    open_mapping
    mkdir -p "$mountpoint"
    mount "/dev/mapper/$mapping" "$mountpoint"
    cmp "$base/expected-marker" "$mountpoint/marker"
    cat /proc/sys/kernel/random/boot_id >"$results/boot-unlock-id"
    tpm2_pcrread -T "$tcti" sha256:7,11 >"$results/pcr-lateboot.txt"
    echo 'PASS: systemd late-boot automatic data mapping and marker read'
    ;;
boot-stop)
    close_own_mapping
    ;;
reboot-check)
    require_environment
    [[ $(cat /proc/sys/kernel/random/boot_id) != $(cat "$base/enrollment-boot-id") ]] || fail 'client has not rebooted'
    # SSH can start before the boot job that depends on network-online.
    # Monitor the automatic job. Do not start or restart the job here.
    for _ in $(seq 1 100); do
        systemctl is-active --quiet leelo-vm-data.service && break
        systemctl is-failed --quiet leelo-vm-data.service && break
        sleep 1
    done
    systemctl is-active --quiet leelo-vm-data.service || fail 'late-boot service did not succeed'
    [[ $(cat "$results/boot-unlock-id") == $(cat /proc/sys/kernel/random/boot_id) ]] || fail 'boot service result is stale'
    mountpoint -q "$mountpoint" || fail 'data volume is not mounted'
    cmp "$base/expected-marker" "$mountpoint/marker"
    load_enrollment
    recovery_check
    capture
    systemctl stop leelo-vm-data.service
    guard_disk
    echo 'PASS: reboot retained TPM binding; automatic late-boot mapping and persistent marker verified'
    ;;
network-off-check)
    require_environment
    close_own_mapping
    guard_disk
    load_enrollment
    if unlock_check >"$results/network-off.stdout" 2>"$results/network-off.stderr"; then fail 'network outage permitted automatic unlock'; fi
    recovery_check
    cryptsetup luksDump --dump-json-metadata "$device" >"$results/header-network-off.json"
    cmp "$results/header-enrolled.json" "$results/header-network-off.json"
    capture
    echo 'PASS: network outage rejects automatic unlock; recovery and metadata preserved'
    ;;
negative-tests)
    require_environment
    close_own_mapping
    guard_disk
    load_enrollment
    unlock_check
    openssl rand -out "$base/wrong.pub" 32
    if "$leelo" unlock --device "$device" --config "$trust/providers.json" \
        --trust-key "$base/wrong.pub" --token "$token" --tcti "$tcti" --check-only \
        >"$results/wrong-trust.stdout" 2>"$results/wrong-trust.stderr"; then fail 'wrong signing trust key accepted'; fi
    recovery_check
    cryptsetup token export --token-id "$token" "$device" >"$base/original-token.json"
    python3 - "$base/original-token.json" "$base/tampered-token.json" <<'PY'
import base64,json,pathlib,sys
x=json.loads(pathlib.Path(sys.argv[1]).read_text()); s=x['envelope']; b=bytearray(base64.urlsafe_b64decode(s+'='*((-len(s))%4))); b[len(b)//2]^=1
x['envelope']=base64.urlsafe_b64encode(b).rstrip(b'=').decode(); pathlib.Path(sys.argv[2]).write_text(json.dumps(x))
PY
    restore_token() { cryptsetup token import --token-id "$token" --token-replace "$device" <"$base/original-token.json"; }
    trap 'status=$?; trap - EXIT; restore_token; capture || true; exit "$status"' EXIT
    guard_disk
    cryptsetup token import --token-id "$token" --token-replace "$device" <"$base/tampered-token.json"
    if unlock_check >"$results/tamper.stdout" 2>"$results/tamper.stderr"; then fail 'tampered signed token accepted'; fi
    recovery_check
    restore_token
    trap finish EXIT
    unlock_check
    cryptsetup luksDump --dump-json-metadata "$device" >"$results/header-restored.json"
    cmp "$results/header-enrolled.json" "$results/header-restored.json"
    tpm2_pcrread -T "$tcti" sha256:7,11 >"$results/pcr-before-negative.txt"
    # This is the guest's disposable vTPM. Do not extend a PCR on the host hardware TPM.
    tpm2_pcrextend -T "$tcti" 11:sha256=1111111111111111111111111111111111111111111111111111111111111111
    tpm2_pcrread -T "$tcti" sha256:7,11 >"$results/pcr-after-negative.txt"
    if unlock_check >"$results/pcr-negative.stdout" 2>"$results/pcr-negative.stderr"; then fail 'changed PCR permitted automatic unlock'; fi
    recovery_check
    cryptsetup luksDump --dump-json-metadata "$device" >"$results/header-after-negative.json"
    cmp "$results/header-enrolled.json" "$results/header-after-negative.json"
    capture
    echo 'PASS: wrong trust, signed-token tamper, and changed PCR reject; recovery and metadata preserved'
    ;;
capture) capture ;;
*) fail "unknown phase $phase" ;;
esac
