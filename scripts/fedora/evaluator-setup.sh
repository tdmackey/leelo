#!/usr/bin/env bash
# Configure only the disposable Fedora 44 evaluator guest. The script does not disable SELinux.
set -Eeuo pipefail
umask 077
phase=${1:-setup}
[[ $# -le 1 && ( $phase == setup || $phase == verify-existing ) ]] || {
    echo "usage: evaluator-setup.sh [setup|verify-existing]" >&2; exit 1;
}
trap 'printf "FAIL: evaluator phase %s at line %s (status %s)\n" "$phase" "$LINENO" "$?" >&2' ERR

[[ $(id -u) == 0 ]] || { echo "run as root inside the disposable evaluator VM" >&2; exit 1; }
source /etc/os-release
[[ ${ID:-} == fedora && ${VERSION_ID:-} == 44 ]] || {
    echo "this fixture requires a disposable Fedora 44 guest" >&2; exit 1;
}
[[ -f /var/lib/leelo-disposable-vm && ! -L /var/lib/leelo-disposable-vm ]] || {
    echo "missing disposable-guest marker; refusing to modify this machine" >&2; exit 1;
}
for command in python3 openssl curl systemctl runuser getenforce restorecon install getent; do
    command -v "$command" >/dev/null || { echo "missing prerequisite: $command" >&2; exit 1; }
done
[[ $(getenforce) == Enforcing ]] || { echo "SELinux must already be Enforcing" >&2; exit 1; }

repo=${LEELO_TEST_REPO:-/home/leelo/leelo}
endpoint=${LEELO_TEST_ENDPOINT:-https://10.0.2.2:38443}
base=/var/lib/leelo-vm-test
results=$base/results/evaluator
public=$base/public
private=$base/evaluator-private
key=/var/lib/leelo-key/evaluation.key
started_at=$(date --iso-8601=seconds)

if [[ $phase == setup ]]; then
    [[ -x $repo/target/debug/leelod ]] || { echo "build $repo/target/debug/leelod first" >&2; exit 1; }
    [[ ! -e $key && ! -L $key ]] || {
        echo "existing evaluation key retained; use verify-existing to check installed services" >&2; exit 1;
    }
    install -d -m 0755 "$base" "$base/results" "$results" "$public"
    install -d -m 0700 "$private"
else
    for existing in /usr/local/bin/leelod "$key" "$public/server-public.json" "$public/providers.json" "$public/ca.pem"; do
        [[ -f $existing ]] || { echo "verify-existing requires $existing" >&2; exit 1; }
    done
    [[ -d $private && -d $results ]] || { echo "fixture directories are missing; refusing to reprovision" >&2; exit 1; }
    # Check the endpoint already supplied to the client. Do not change the endpoint.
    endpoint=$(python3 -c 'import json,sys; p=json.load(open(sys.argv[1]))["providers"]; assert len(p)==1; print(p[0]["url"])' "$public/providers.json")
fi

capture() {
    local status=$?
    trap - EXIT
    {
        printf 'phase=%s\nexit_status=%s\nstarted_at=%s\nfinished_at=%s\n' "$phase" "$status" "$started_at" "$(date --iso-8601=seconds)"
        printf 'selinux='; getenforce
        uname -a
        cat /etc/os-release
        /usr/local/bin/leelod --version 2>/dev/null || true
        openssl version
        curl --version
        systemctl --version
        rpm -q selinux-policy selinux-policy-targeted libselinux systemd openssl curl python3 || true
    } >"$results/environment.txt" 2>&1
    systemctl status --no-pager --full leelo-key.service leelo-http.service >"$results/systemd-status.txt" 2>&1 || true
    systemctl show leelo-key.service leelo-http.service -p User -p Group -p MainPID -p ActiveState -p SubState -p ExecMainStatus >"$results/systemd-properties.txt" 2>&1 || true
    journalctl --no-pager --since "$started_at" -u leelo-key.service -u leelo-http.service >"$results/service-journal.txt" 2>&1 || true
    {
        ls -ldZ /usr/local/bin/leelod /var/lib/leelo-key "$key" /run/leelo-key /run/leelo-key/evaluator.sock /etc/leelo-http /etc/leelo-http/server.key 2>&1 || true
        ps -eZ | grep -E 'leelod|LABEL' || true
    } >"$results/selinux-contexts.txt"
    if command -v ausearch >/dev/null; then
        ausearch -m AVC,USER_AVC -ts boot >"$results/selinux-avc.txt" 2>&1 || true
    else
        journalctl --no-pager -k --since "$started_at" | grep -Ei 'avc:|selinux' >"$results/selinux-avc.txt" || true
    fi
    chmod -R a+rX "$results"
    exit "$status"
}
trap capture EXIT

# Validate the trusted test endpoint before you use its hostname in an X.509 SAN.
python3 - "$endpoint" "$results/endpoint.json" <<'PY'
import ipaddress, json, re, sys, urllib.parse
url = sys.argv[1]
if any(ord(c) < 33 or ord(c) > 126 for c in url):
    raise SystemExit("endpoint must contain printable ASCII without spaces")
p = urllib.parse.urlsplit(url)
if p.scheme != "https" or not p.hostname or p.username is not None or p.password is not None or p.path not in ("", "/") or p.query or p.fragment:
    raise SystemExit("endpoint must be an HTTPS origin without userinfo/path/query/fragment")
host, port = p.hostname, p.port or 443
try:
    address = ipaddress.ip_address(host)
    san = "IP:" + str(address)
except ValueError:
    if len(host) > 253 or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", host):
        raise SystemExit("invalid endpoint hostname")
    san = "DNS:" + host
authority_host = "[" + host + "]" if ":" in host else host
with open(sys.argv[2], "w", encoding="utf-8") as f:
    json.dump({"endpoint":url.rstrip("/"), "san":san, "connect_to":f"{authority_host}:{port}:127.0.0.1:8443"}, f)
PY
san=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["san"])' "$results/endpoint.json")
connect_to=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["connect_to"])' "$results/endpoint.json")
endpoint=${endpoint%/}

if [[ $phase == setup ]]; then
    getent group leelo-ipc >/dev/null || groupadd --system leelo-ipc
fi
for account in leelo-key leelo-http leelo-ipc-probe; do
    if ! getent passwd "$account" >/dev/null; then
        if [[ $phase == setup ]]; then
            useradd --system --gid leelo-ipc --home-dir /nonexistent --shell /usr/sbin/nologin "$account"
        else
            echo "verify-existing requires account $account" >&2; exit 1;
        fi
    fi
    [[ $(id -u "$account") != 0 ]] || { echo "$account must be unprivileged" >&2; exit 1; }
    id -nG "$account" | tr ' ' '\n' | grep -Fx leelo-ipc >/dev/null || {
        echo "existing account $account must belong to leelo-ipc" >&2; exit 1;
    }
done
worker_uid=$(id -u leelo-key)
http_uid=$(id -u leelo-http)
probe_uid=$(id -u leelo-ipc-probe)
[[ $worker_uid != "$http_uid" && $worker_uid != "$probe_uid" && $http_uid != "$probe_uid" ]] || {
    echo "worker, frontend, and probe must have distinct UIDs" >&2; exit 1;
}
{
    id leelo-key; id leelo-http; id leelo-ipc-probe
} >"$results/accounts.txt"

if [[ $phase == setup ]]; then
install -m 0755 "$repo/target/debug/leelod" /usr/local/bin/leelod
install -d -o leelo-key -g leelo-ipc -m 0700 /var/lib/leelo-key
install -d -o root -g root -m 0700 /etc/leelo-key
install -d -o leelo-http -g leelo-ipc -m 0750 /etc/leelo-http
printf 'LEELO_HTTP_UID=%s\n' "$http_uid" >/etc/leelo-key/worker.env
chmod 0600 /etc/leelo-key/worker.env
runuser -u leelo-key -- /usr/local/bin/leelod keygen --key "$key" >"$public/server-public.json"
[[ $(stat -c '%a:%u' "$key") == "600:$worker_uid" ]]

# Keep the CA key in this root-only fixture directory. Do not send the key to the client.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 7 \
    -subj '/CN=Leelo disposable Fedora test CA' \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -keyout "$private/ca.key" -out "$public/ca.pem" >"$results/openssl-ca.txt" 2>&1
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -subj '/CN=Leelo disposable evaluator' \
    -keyout "$private/server.key" -out "$private/server.csr" >"$results/openssl-csr.txt" 2>&1
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' "$san" >"$private/server.ext"
openssl x509 -req -in "$private/server.csr" -CA "$public/ca.pem" -CAkey "$private/ca.key" \
    -CAcreateserial -days 7 -sha256 -extfile "$private/server.ext" -out "$private/server.crt" >"$results/openssl-leaf.txt" 2>&1
install -o leelo-http -g leelo-ipc -m 0600 "$private/server.key" /etc/leelo-http/server.key
install -o leelo-http -g leelo-ipc -m 0644 "$private/server.crt" /etc/leelo-http/server.crt

python3 - "$public/server-public.json" "$public/providers.json" "$endpoint" <<'PY'
import hashlib, json, sys
server = json.load(open(sys.argv[1], encoding="utf-8"))
key, public = bytes.fromhex(server["key_id"]), bytes.fromhex(server["public_key"])
if len(key) != 32 or len(public) != 49 or hashlib.sha384(public).digest()[:32] != key:
    raise SystemExit("invalid keygen public output")
provider = {"provider_id":hashlib.sha256(b"leelo/fedora44/disposable-evaluator/v1").hexdigest(),
            "key_id":key.hex(), "public_key":public.hex(), "url":sys.argv[3],
            "ca_file":"/var/lib/leelo-vm-test/trust/ca.pem"}
with open(sys.argv[2], "w", encoding="utf-8") as f:
    json.dump({"providers":[provider]}, f, indent=2)
    f.write("\n")
PY
chmod 0644 "$public/server-public.json" "$public/providers.json" "$public/ca.pem"

install -m 0644 "$repo/crates/leelod/systemd/leelo-key.service" /etc/systemd/system/leelo-key.service
install -m 0644 "$repo/crates/leelod/systemd/leelo-http.service" /etc/systemd/system/leelo-http.service
# Apply the existing default Fedora labels. Do not create or install a policy module.
restorecon -RFv /usr/local/bin/leelod /etc/leelo-key /etc/leelo-http /var/lib/leelo-key "$base" \
    /etc/systemd/system/leelo-key.service /etc/systemd/system/leelo-http.service >"$results/restorecon.txt" 2>&1
systemctl daemon-reload
systemctl start leelo-key.service leelo-http.service
fi

# Type=simple can become active before exec and UID setup finish.
# The owner of a /proc directory also depends on dumpability.
# The directory owner does not establish the process identity.
python3 - "$worker_uid" "$http_uid" "$results/process-identities.json" <<'PY'
import grp, json, os, pathlib, socket, stat, subprocess, sys, time
expected = [("leelo-key.service", int(sys.argv[1]), "worker"), ("leelo-http.service", int(sys.argv[2]), "serve")]
deadline = time.monotonic() + 20
last_error = "services have not been inspected"
while time.monotonic() < deadline:
    try:
        processes = []
        for unit, uid, command in expected:
            pid = int(subprocess.check_output(["systemctl", "show", "-p", "MainPID", "--value", unit], text=True, timeout=2).strip())
            if pid <= 0:
                raise RuntimeError(f"{unit} has no live MainPID")
            status = pathlib.Path(f"/proc/{pid}/status").read_text()
            uids = next([int(n) for n in line.split()[1:]] for line in status.splitlines() if line.startswith("Uid:"))
            if uids != [uid] * 4:
                raise RuntimeError(f"{unit} PID {pid} UID fields {uids}, expected {uid}")
            executable = os.readlink(f"/proc/{pid}/exe")
            arguments = pathlib.Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
            if executable != "/usr/local/bin/leelod" or len(arguments) < 2 or arguments[1] != command.encode():
                raise RuntimeError(f"{unit} has not executed expected leelod {command}")
            processes.append({"unit":unit, "pid":pid, "uids":uids, "executable":executable, "command":command})
        if processes[0]["pid"] == processes[1]["pid"]:
            raise RuntimeError("worker and frontend share a PID")
        endpoint = os.stat("/run/leelo-key/evaluator.sock")
        if not stat.S_ISSOCK(endpoint.st_mode) or stat.S_IMODE(endpoint.st_mode) != 0o660 or endpoint.st_uid != expected[0][1] or endpoint.st_gid != grp.getgrnam("leelo-ipc").gr_gid:
            raise RuntimeError("worker socket is not ready with expected owner/group/mode 0660")
        with socket.create_connection(("127.0.0.1", 8443), timeout=0.5):
            pass
        with open(sys.argv[3], "w", encoding="utf-8") as f:
            json.dump(processes, f, indent=2)
            f.write("\n")
        print("PASS: distinct live service UIDs, expected executables, Unix socket and TCP listener ready")
        break
    except (OSError, ValueError, StopIteration, RuntimeError, subprocess.SubprocessError) as error:
        last_error = str(error)
        time.sleep(0.2)
else:
    raise SystemExit("service readiness timeout: " + last_error)
PY
[[ $(stat -c '%a:%u' "$key") == "600:$worker_uid" ]] || {
    echo "evaluation key owner or mode differs from expected private worker file" >&2; exit 1;
}
worker_pid=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[0]["pid"])' "$results/process-identities.json")
http_pid=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[1]["pid"])' "$results/process-identities.json")
ps -o pid,euid,egid,args -p "$worker_pid,$http_pid" >"$results/processes.txt"

runuser -u leelo-http -- python3 - "$key" >"$results/frontend-key-read.txt" <<'PY'
import sys
try:
    with open(sys.argv[1], "rb") as f:
        f.read(1)
except PermissionError:
    print("PASS: frontend UID cannot read evaluation key")
else:
    raise SystemExit("FAIL: frontend UID read the evaluation key")
PY

# This account can traverse the directory and connect through leelo-ipc.
# The worker must reject its kernel UID before it parses or evaluates a request.
# If the connection fails, the test fails. Connection denial does not prove the worker's UID check.
runuser -u leelo-ipc-probe -- python3 - /run/leelo-key/evaluator.sock >"$results/ipc-wrong-uid.txt" <<'PY'
import socket, sys
with socket.socket(socket.AF_UNIX) as s:
    s.settimeout(3)
    s.connect(sys.argv[1])
    try:
        response = s.recv(1)
    except ConnectionResetError:
        response = b""
    if response:
        raise SystemExit("FAIL: worker responded to an unauthorized UID")
print("PASS: IPC-group account connected and worker refused its kernel UID")
PY

python3 - "$public/server-public.json" "$private/request.bin" <<'PY'
import json, sys
server = json.load(open(sys.argv[1], encoding="utf-8"))
# Any valid nonidentity group point is a permitted blinded evaluation input.
request = b"LEEL\x01\x01\x01\x00" + bytes.fromhex(server["key_id"]) + bytes.fromhex(server["public_key"])
assert len(request) == 89
open(sys.argv[2], "wb").write(request)
PY
code=''
for ((attempt=0; attempt<40; attempt++)); do
    if code=$(curl --silent --show-error --noproxy '*' --cacert "$public/ca.pem" \
        --connect-to "$connect_to" --connect-timeout 2 --max-time 5 --tlsv1.3 --tls-max 1.3 --proto '=https' \
        --request POST --header 'Content-Type: application/vnd.leelo.network-bound-v1' \
        --data-binary "@$private/request.bin" --output "$private/response.bin" --write-out '%{http_code}' \
        --url "$endpoint/v1/evaluate" 2>"$results/https-probe-stderr.txt") && [[ $code == 200 ]]; then
        break
    fi
    sleep 0.25
done
[[ $code == 200 ]] || { echo "TLS evaluation failed (HTTP $code); inspect results and AVCs" >&2; exit 1; }
python3 - "$private/response.bin" >"$results/https-probe.txt" <<'PY'
import sys
data = open(sys.argv[1], "rb").read(154)
if len(data) != 153 or data[:8] != b"LEEL\x01\x01\x01\x00":
    raise SystemExit("invalid evaluation response framing")
print("PASS: TLS 1.3, CA/hostname validation, and frontend-to-worker evaluation returned expected framing")
print("Proof verification is performed by the separate client enrollment/recovery phase.")
PY
[[ $(getenforce) == Enforcing ]]
printf 'PASS: evaluator %s; public handoff %s; results %s\n' "$phase" "$public" "$results"
