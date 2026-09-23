# Leelo evaluator

This executable implements only network-bound mode. It is a prototype and has not had an audit. It does not verify attestation. The executable has three commands:

```text
leelod keygen --key /var/lib/leelo-key/evaluation.key
leelod worker --key /var/lib/leelo-key/evaluation.key --socket /run/leelo-key/evaluator.sock --allow-uid 991
leelod serve --listen 0.0.0.0:8443 --cert /etc/leelo-http/server.crt --tls-key /etc/leelo-http/server.key --worker-socket /run/leelo-key/evaluator.sock
```

The numeric UID above is an example. Replace it with the actual UID of the frontend account. Key generation prints only public JSON fields, `key_id` and `public_key`, as hexadecimal strings. The evaluation key contains exactly 48 secret bytes. The key ID contains the first 32 bytes of SHA-384 over its 49-byte compressed public key. Copy public key material through the trusted enrollment configuration. A remotely discovered advertisement cannot replace a trusted pin.

Run `keygen` as the worker account. The command creates the key exclusively with mode 0600. It never overwrites an existing file. It synchronizes the file before it prints public metadata. Investigate a failed or partial creation before you try another path. The worker rejects a key file with any of these properties:

- A symlink in the final path component.
- A file type other than a regular file.
- An owner different from the worker account.
- Permissions for the group or other users.
- A length other than 48 bytes.

The operator must control parent directories and configured paths. TLS private keys have the same ownership and permission requirements, with a maximum size of 64 KiB. The TLS key must belong to the frontend account.

## Process separation

Create separate `leelo-key` and `leelo-http` OS accounts. Create a shared `leelo-ipc` group. Give only `leelo-key` read access to the evaluation key directory and file. The TLS certificate and key belong to `leelo-http`. Create the socket directory with owner `leelo-key:leelo-ipc` and mode 0750. The worker creates its socket with mode 0660. The kernel supplies the UID of the connecting process. The worker checks that UID against `--allow-uid`. Group membership alone does not permit evaluation access. The group and other users must not have write access to socket directories.

The worker rejects existing socket paths. Use the service manager to manage the lifetime of the private runtime directory. Remove stale sockets only after the worker stops.

The same executable supplies both commands. Run the commands as separate processes under separate UIDs. One shared UID does not isolate the evaluation key. That UID can reopen its files and might inspect other processes. The frontend module does not load an evaluation key. It sends only a key ID and a blinded point to the configured socket. A compromised frontend can still request online evaluations while the worker is available. Process separation does not prevent denial of service or a privileged host compromise.

The example units in `systemd/` are templates. They are not installed. Prepare accounts, directories, files, the actual frontend UID, and firewall rules before you install the units. Adjust paths and resource budgets for the target distribution. Do not give the worker network access. Disable core dumps in the deployment configuration. Keep secrets out of swap. Use an external network policy to restrict client access to this network-bound evaluator.

## Protocol and limits

The frontend accepts only `POST /v1/evaluate` with content type `application/vnd.leelo.network-bound-v1`. HTTP/1.1 uses TLS 1.3. The client verifies the certificate and hostname. The protocol has no TLS 0-RTT, HTTP keep-alive, compressed bodies, alternative modes, or version negotiation. The frontend rejects an attested request. It never interprets that request as network-bound.

The binary header is `4c 45 45 4c 01 01 01 00`. Its fields are magic, version 1, suite 1, network-bound mode 1, and reserved zero. A request contains exactly 89 bytes: the header, a 32-byte key ID, and a 49-byte point. A successful response contains exactly 153 bytes: the header, a 49-byte point, and a 96-byte DLEQ proof.

The worker accepts exactly this request over Unix IPC, followed by a write-half-close. A successful IPC response contains byte zero, followed by the network response. A refusal contains byte one. Neither interface serializes secret key objects. The client uses `leelo-engine` to verify the proof against its enrollment pin before it derives a wrapping key.

The frontend permits 64 simultaneous connections, including incomplete TLS handshakes. The handshake and header deadline is two seconds. The total connection deadline is five seconds. The frontend permits at most 16 HTTP headers, an 8 KiB HTTP parser buffer, and an 89-byte body.

The worker permits eight simultaneous connections and uses a two-second IPC deadline. All curve operations have a fixed size. Timeout cancellation does not interrupt a synchronous curve operation. Fixed operation sizes and concurrency limits restrict that work. The frontend and worker refuse excess work. They do not keep unlimited queues. These resource limits do not provide a cumulative cryptographic-query budget or a rate limit for each client.

A change to an evaluation key invalidates old bindings. This prototype holds one evaluation key per worker and has no rotation registry. Keep old workers available at separately configured endpoints while you explicitly reenroll dependent volumes. TLS certificate renewal does not change the evaluation key.

## Tests

Run `cargo test -p leelod -p leelo-net` on Linux. Tests cover key-file permissions, symlinks, lengths, malformed IPC, and exact message framing. They also test actual child-process HTTPS-to-worker evaluation with proof verification.

The TLS test uses the `openssl` executable to create temporary certificates. The test runs services only on loopback. It removes temporary files and child processes. It checks wrong certificate trust, a wrong hostname, TLS 1.2, unsupported modes, and oversized bodies. All test processes use the same UID. These tests do not establish deployment isolation between OS users.
