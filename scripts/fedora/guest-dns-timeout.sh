#!/usr/bin/env bash
# Test DNS cancellation in a private mount namespace inside the disposable guest.
# Keep the guest resolver, enrollment, and LUKS metadata unchanged.
set -euo pipefail
umask 077
[[ $EUID == 0 && -f /var/lib/leelo-disposable-vm && ! -L /var/lib/leelo-disposable-vm ]]
source /etc/os-release
[[ ${ID:-} == fedora && ${VERSION_ID:-} == 44 && $(getenforce) == Enforcing ]]
base=/var/lib/leelo-vm-test
results=$base/results
device=$(readlink -f /dev/disk/by-id/virtio-leelo-test-data)
[[ -b $device && $(lsblk -dn -o SERIAL "$device" | xargs) == leelo-test-data ]]
[[ $(blockdev --getsize64 "$device") == 1073741824 && $(lsblk -dn -o TYPE "$device" | xargs) == disk ]]
[[ $(lsblk -nr -o NAME "$device" | wc -l) == 1 ]]
[[ -z $(lsblk -nr -o MOUNTPOINTS "$device" | tr -d '[:space:]') ]]
[[ -z $(find "/sys/class/block/$(basename "$device")/holders" -mindepth 1 -maxdepth 1 -print) ]]
[[ ! -e /dev/mapper/leelo-vm-test-data && -d $results ]]
exec > >(tee "$results/dns-timeout.log") 2>&1
sha256sum /etc/resolv.conf >"$results/resolver-before-dns-test.sha256"
cryptsetup luksDump --dump-json-metadata "$device" >"$results/header-before-dns-timeout.json"
unshare --mount --propagation private python3 - "$device" "$base" "$results" <<'PY'
import json, os, pathlib, selectors, signal, socket, subprocess, sys, tempfile, time, uuid

device, base, result_dir = sys.argv[1:]
base, results = pathlib.Path(base), pathlib.Path(result_dir)
enrollment = json.loads((base / 'enrollment.json').read_text())
assert enrollment['enrolled'] and enrollment['slot'] == 1
with tempfile.TemporaryDirectory(prefix='dns-timeout-', dir=base) as temporary:
    directory = pathlib.Path(temporary)
    resolver = directory / 'resolv.conf'
    resolver.write_text('nameserver 127.0.0.2\noptions timeout:30 attempts:5\n')
    # This mount exists only in this process's private mount namespace.
    subprocess.run(['mount', '--bind', str(resolver), str(pathlib.Path('/etc/resolv.conf').resolve())], check=True)
    config = json.loads((base / 'trust/providers.json').read_text())
    assert len(config['providers']) == 1
    hostname = 'leelo-timeout-' + uuid.uuid4().hex + '.test'
    config['providers'][0]['url'] = 'https://' + hostname + ':38443'
    config_path = directory / 'providers.json'
    config_path.write_text(json.dumps(config))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sink, selectors.DefaultSelector() as selector:
        sink.bind(('127.0.0.2', 53))
        sink.setblocking(False)
        selector.register(sink, selectors.EVENT_READ)
        command = ['/usr/local/bin/leelo', 'unlock', '--device', device,
                   '--config', str(config_path), '--trust-key', str(base / 'admin.pub'),
                   '--token', str(enrollment['token']), '--tcti', 'device:/dev/tpmrm0', '--check-only']
        started = time.monotonic()
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        queries = 0
        forced = False
        try:
            while process.poll() is None:
                if time.monotonic() - started > 9:
                    forced = True
                    os.killpg(process.pid, signal.SIGKILL)
                    break
                for key, _ in selector.select(timeout=0.05):
                    key.fileobj.recvfrom(4096)
                    queries += 1
            stdout, stderr = process.communicate(timeout=2)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
        elapsed = time.monotonic() - started
        assert len(stdout) < 4096 and len(stderr) < 4096
        (results / 'dns-timeout.stdout').write_bytes(stdout)
        (results / 'dns-timeout.stderr').write_bytes(stderr)
        report = {'elapsed_seconds': elapsed, 'exit_code': process.returncode,
                  'discarded_dns_queries': queries, 'forced_termination': forced,
                  'resolver_timeout_seconds': 30, 'resolver_attempts': 5}
        (results / 'dns-timeout.json').write_text(json.dumps(report, indent=2) + '\n')
        assert queries > 0, 'the test did not observe a DNS query'
        assert not forced and elapsed < 7.5, report
        assert process.returncode != 0 and b'Timeout' in stderr, stderr.decode(errors='replace')
        assert hostname.encode() not in stderr and not stdout
        print('PASS: DNS requests were discarded; complete CLI process exited with bounded Timeout diagnostics')
        print(json.dumps(report))
PY
sha256sum --check "$results/resolver-before-dns-test.sha256"
cryptsetup luksDump --dump-json-metadata "$device" >"$results/header-after-dns-timeout.json"
cmp "$results/header-before-dns-timeout.json" "$results/header-after-dns-timeout.json"
echo 'PASS: guest resolver and LUKS metadata remain unchanged'
