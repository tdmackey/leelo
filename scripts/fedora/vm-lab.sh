#!/usr/bin/env bash
# Run this host script as root. It starts disposable Fedora guests under QEMU/KVM.
# A private temporary directory contains guest credentials, disks, and TPM state.
set -euo pipefail
umask 077
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cache="$repo/.tools/fedora-vms"
mkdir -p "$cache"
chmod 755 "$cache"
image=Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2
checksum=Fedora-Cloud-44-1.7-x86_64-CHECKSUM
base_url=https://dl.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images
expected=28680fe5b371a5a82ebf43a31926e086a168e59949d03969c5093e7071f90b7f
lab_user=${LEELO_LAB_HOST_USER:-$(stat -c %U "$repo")}
[[ $EUID == 0 ]] || { echo 'Run this host driver as root (KVM access and dropping VM privileges).' >&2; exit 1; }
load_lab() {
    lab=$(cat "$cache/runtime-path")
    [[ "$lab" == /var/tmp/leelo-fedora44.* && -d "$lab" && ! -L "$lab" ]] || exit 1
}
port_for() { case "$1" in evaluator) echo 38221 ;; client) echo 38222 ;; *) return 1 ;; esac; }
ssh_for() {
    local role=$1; shift
    ssh -i "$lab/id_ed25519" -p "$(port_for "$role")" \
        -o BatchMode=yes -o ConnectTimeout=3 -o ServerAliveInterval=15 \
        -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$lab/known_hosts" \
        leelo@127.0.0.1 "$@"
}
case ${1:-help} in
run)
    bash "$0" up
    exec bash "$0" keepalive
    ;;
download)
    curl -fLsS --retry 3 "$base_url/$checksum" -o "$cache/$checksum"
    curl -fLsS --retry 3 https://fedoraproject.org/fedora.gpg -o "$cache/fedora.gpg"
    gpgv --keyring "$cache/fedora.gpg" --output - "$cache/$checksum" >"$cache/checksums.txt" 2>"$cache/signature.log"
    grep -F "SHA256 ($image) = $expected" "$cache/checksums.txt"
    if [[ ! -f "$cache/$image" ]]; then
        curl -fL --retry 3 --output "$cache/$image.partial" "https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/$image"
        printf '%s  %s\n' "$expected" "$cache/$image.partial" | sha256sum --check
        mv -- "$cache/$image.partial" "$cache/$image"
    fi
    printf '%s  %s\n' "$expected" "$cache/$image" | sha256sum --check
    chmod 644 "$cache/$image"
    cat "$cache/signature.log"
    ;;
up|start)
    [[ $(id -u "$lab_user") != 0 ]] || { echo 'Set LEELO_LAB_HOST_USER to an unprivileged host account.' >&2; exit 1; }
    if [[ "$1" == up ]]; then
    [[ ! -e "$cache/runtime-path" ]] || { echo 'Existing lab present; use status/down, do not overwrite it.' >&2; exit 1; }
    [[ -c /dev/kvm && -f "$cache/$image" ]] || { echo 'KVM and verified image required.' >&2; exit 1; }
    printf '%s  %s\n' "$expected" "$cache/$image" | sha256sum --check
    python3 - <<'PY'
import socket
for port in (38221,38222,38443):
    with socket.socket() as s: s.bind(('127.0.0.1',port))
PY
    lab=$(mktemp -d /var/tmp/leelo-fedora44.XXXXXXXX)
    printf '%s\n' "$lab" >"$cache/runtime-path"
    ssh-keygen -q -t ed25519 -N '' -f "$lab/id_ed25519"
    for role in evaluator client; do
        mkdir -p "$lab/$role/tpm"
        ssh-keygen -q -t ed25519 -N '' -f "$lab/$role/ssh_host_ed25519_key"
        python3 - "$lab" "$role" "$(port_for "$role")" <<'PY'
import json,pathlib,sys
lab=pathlib.Path(sys.argv[1]); role=sys.argv[2]; port=sys.argv[3]
d=lab/role
config={'hostname':'leelo-'+role,'manage_etc_hosts':True,'ssh_pwauth':False,
 'disable_root':True,'users':[{'name':'leelo','groups':['wheel'],'shell':'/bin/bash',
 'sudo':['ALL=(ALL) NOPASSWD:ALL'],'lock_passwd':True,
 'ssh_authorized_keys':[(lab/'id_ed25519.pub').read_text().strip()]}],
 'ssh_keys':{'ed25519_private':(d/'ssh_host_ed25519_key').read_text(),
 'ed25519_public':(d/'ssh_host_ed25519_key.pub').read_text()},
 'runcmd':[['touch','/var/lib/leelo-disposable-vm'],
 ['sh','-c','/usr/sbin/sshd -t 2>&1 | systemd-cat -t leelo-sshd-check; journalctl -b -u sshd --no-pager > /dev/ttyS0']]}
(d/'user-data').write_text('#cloud-config\n'+json.dumps(config))
(d/'meta-data').write_text('instance-id: '+lab.name+'-'+role+'\nlocal-hostname: leelo-'+role+'\n')
with (lab/'known_hosts').open('a') as f:
 f.write('[127.0.0.1]:'+port+' '+(d/'ssh_host_ed25519_key.pub').read_text())
PY
        cloud-localds "$lab/$role/seed.img" "$lab/$role/user-data" "$lab/$role/meta-data"
        qemu-img create -q -f qcow2 -F qcow2 -b "$cache/$image" "$lab/$role/system.qcow2" 40G
        cp /usr/share/OVMF/OVMF_VARS_4M.fd "$lab/$role/vars.fd"
    done
    qemu-img create -q -f qcow2 "$lab/client/data.qcow2" 1G
    chown -R "$lab_user:kvm" "$lab"
    else
        load_lab
        rm -f -- "$lab/stop-host-hold"
    fi
    for role in ${2:-evaluator client}; do
        port_for "$role" >/dev/null
        new_tpm=false
        if ! systemctl is-active --quiet "${lab##*/}-$role-tpm"; then
            systemd-run --unit="${lab##*/}-$role-tpm" --collect --uid="$lab_user" --gid=kvm \
                --property=Type=exec /usr/bin/swtpm socket --tpm2 \
                --tpmstate "dir=$lab/$role/tpm" --ctrl "type=unixio,path=$lab/$role/swtpm.sock" \
                --log "file=$lab/$role/swtpm.log" --pid "file=$lab/$role/swtpm.pid"
            new_tpm=true
        fi
        # Type=exec can report successful exec before swtpm listens.
        # Read the kernel table of listening sockets. Do not open another control connection.
        # A stale filesystem socket does not show that the service is ready.
        if "$new_tpm" && ! systemctl is-active --quiet "${lab##*/}-$role-qemu"; then
        python3 - "$lab/$role/swtpm.sock" "${lab##*/}-$role-tpm.service" <<'PY'
import pathlib, subprocess, sys, time
path, unit = sys.argv[1:]
deadline = time.monotonic() + 15
while time.monotonic() < deadline:
    if subprocess.run(["systemctl", "is-active", "--quiet", unit], timeout=2).returncode:
        raise SystemExit(f"{unit} exited before its control socket became ready")
    for line in pathlib.Path("/proc/net/unix").read_text().splitlines()[1:]:
        fields = line.split(maxsplit=7)
        # Linux uses flag 0x10000 for SO_ACCEPTCON. Type 0001 means SOCK_STREAM.
        if len(fields) == 8 and fields[7] == path and fields[4] == "0001" and int(fields[3], 16) & 0x10000:
            raise SystemExit(0)
    time.sleep(0.1)
raise SystemExit(f"timed out waiting for {unit} to listen on {path}")
PY
        fi
        if systemctl is-active --quiet "${lab##*/}-$role-qemu"; then continue; fi
        extra=(); net_extra=
        memory=3072; cpus=2
        if [[ "$role" == client ]]; then
            extra=(-drive "if=none,id=data,file=$lab/client/data.qcow2,format=qcow2" -device virtio-blk-pci,drive=data,serial=leelo-test-data)
            memory=8192; cpus=6
        else
            net_extra=,hostfwd=tcp:127.0.0.1:38443-:8443
        fi
        systemd-run --unit="${lab##*/}-$role-qemu" --collect --uid="$lab_user" --gid=kvm \
            --property=Type=exec --property="StandardOutput=append:$lab/$role/qemu.log" \
            --property="StandardError=append:$lab/$role/qemu.log" /usr/bin/qemu-system-x86_64 \
            -name "leelo-fedora44-$role" -machine q35,accel=kvm -cpu host -smp "$cpus" -m "$memory" \
            -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
            -drive "if=pflash,format=raw,file=$lab/$role/vars.fd" \
            -drive "if=none,id=os,file=$lab/$role/system.qcow2,format=qcow2" \
            -device virtio-blk-pci,drive=os,serial=leelo-system \
            -drive "if=virtio,format=raw,readonly=on,file=$lab/$role/seed.img" \
            "${extra[@]}" \
            -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$(port_for "$role")-:22$net_extra" \
            -device virtio-net-pci,netdev=net0 \
            -device virtio-serial-pci,id=virtio-serial0 \
            -chardev "socket,path=$lab/$role/guest-agent.sock,server=on,wait=off,id=qga0" \
            -device virtserialport,chardev=qga0,name=org.qemu.guest_agent.0 \
            -chardev "socket,id=chrtpm,path=$lab/$role/swtpm.sock" \
            -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0 \
            -object rng-random,id=rng0,filename=/dev/urandom -device virtio-rng-pci,rng=rng0 \
            -display none -serial "file:$lab/$role/serial.log" -monitor none \
            -qmp "unix:$lab/$role/qmp.sock,server=on,wait=off" \
            -pidfile "$lab/$role/qemu.pid" \
            -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny
        sleep 1
        [[ -f "$lab/$role/qemu.pid" ]] || { cat "$lab/$role/qemu.log"; exit 1; }
        kill -0 "$(cat "$lab/$role/qemu.pid")" || { cat "$lab/$role/qemu.log"; exit 1; }
    done
    echo "Fedora guests started; private lab: $lab"
    ;;
wait)
    load_lab
    for role in evaluator client; do
        ready=false
        for _ in $(seq 1 90); do
            if ssh_for "$role" 'test -f /var/lib/leelo-disposable-vm' 2>/dev/null; then ready=true; break; fi
            sleep 2
        done
        "$ready" || { tail -60 "$lab/$role/serial.log"; exit 1; }
        ssh_for "$role" 'cat /etc/fedora-release; uname -r; getenforce; ls -l /dev/tpmrm0; sudo cloud-init status'
    done
    ;;
ssh)
    load_lab; role=${2:?guest role}; shift 2; ssh_for "$role" "$@"
    ;;
stage)
    load_lab
    tar -czf "$cache/source.tar.gz" -C "$repo" Cargo.toml Cargo.lock rust-toolchain.toml crates scripts docs verification
    for role in ${2:-evaluator client}; do
        port_for "$role" >/dev/null
        ssh_for "$role" 'mkdir -p /home/leelo/leelo; tar -xzf - -C /home/leelo/leelo' <"$cache/source.tar.gz"
    done
    ;;
provision)
    load_lab
    pids=()
    for role in ${2:-evaluator client}; do
        port_for "$role" >/dev/null
        ssh_for "$role" 'sudo dnf install -y gcc pkgconf-pkg-config openssl-devel tpm2-tss-devel cryptsetup-devel cryptsetup swtpm swtpm-tools tpm2-tools openssl python3 rustup audit policycoreutils e2fsprogs util-linux curl tar gzip unzip' \
            >"$cache/provision-$role.log" 2>&1 &
        pids+=("$!")
    done
    failed=0
    for pid in "${pids[@]}"; do wait "$pid" || failed=1; done
    for role in ${2:-evaluator client}; do tail -15 "$cache/provision-$role.log"; done
    exit "$failed"
    ;;
build)
    load_lab
    ssh_for client 'bash /home/leelo/leelo/scripts/fedora/guest-build.sh' | tee "$cache/build.log"
    ;;
install-evaluator-binary)
    load_lab
    ssh_for client 'tar -cf - -C /home/leelo/leelo/target/debug leelod' | \
        ssh_for evaluator 'mkdir -p /home/leelo/leelo/target/debug; tar -xf - -C /home/leelo/leelo/target/debug'
    ;;
handoff)
    load_lab
    ssh_for evaluator 'sudo tar -cf - -C /var/lib/leelo-vm-test/public ca.pem providers.json' | \
        ssh_for client 'sudo install -d -m 0700 /var/lib/leelo-vm-test/trust; sudo tar -xf - -C /var/lib/leelo-vm-test/trust; sudo chown -R root:root /var/lib/leelo-vm-test/trust'
    ;;
collect)
    load_lab
    for role in evaluator client; do
        mkdir -p "$cache/results/$role"
        ssh_for "$role" 'sudo tar -czf - -C /var/lib/leelo-vm-test results' >"$cache/results/$role.tar.gz"
        tar -xzf "$cache/results/$role.tar.gz" -C "$cache/results/$role"
    done
    ;;
keepalive)
    load_lab
    echo 'Keeping the WSL host session active while the Fedora guests run.'
    while [[ ! -f "$lab/stop-host-hold" ]]; do sleep 30; done
    ;;
status)
    load_lab
    for role in evaluator client; do
        echo "$role"
        ps -p "$(cat "$lab/$role/qemu.pid")" -o pid,user,comm,etime
    done
    ;;
down)
    load_lab
    for role in evaluator client; do
        ssh_for "$role" 'sudo systemctl poweroff' || true
    done
    for _ in $(seq 1 30); do
        if ! systemctl is-active --quiet "${lab##*/}-evaluator-qemu" && \
           ! systemctl is-active --quiet "${lab##*/}-client-qemu"; then break; fi
        sleep 1
    done
    for role in evaluator client; do
        if systemctl is-active --quiet "${lab##*/}-$role-qemu"; then
            echo "$role still running; inspect before stopping the host session." >&2
            exit 1
        fi
        if systemctl is-active --quiet "${lab##*/}-$role-tpm"; then
            systemctl stop "${lab##*/}-$role-tpm"
        fi
    done
    touch "$lab/stop-host-hold"
    echo 'Guests stopped; images, private TPM state and logs retained for review.'
    ;;
*) echo 'Usage: vm-lab.sh download|run|up|start|keepalive|wait|stage|provision|build|install-evaluator-binary|handoff|collect|ssh ROLE COMMAND|status|down'; exit 2 ;;
esac
