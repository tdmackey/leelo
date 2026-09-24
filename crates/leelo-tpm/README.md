# leelo-tpm

This Linux adapter uses TPM2-TSS ESAPI for network-bound seed sealing.
The adapter recreates an ECC P-256 storage primary in the owner hierarchy.
It seals a 32-byte seed with an explicit SHA-256 PCR equality policy and
`PolicyCommandCode(Unseal)`. The signed envelope pins the primary Name and
the child Name. The sealed child has policy-only authorization, `fixedTPM`,
and `fixedParent`.

Seed creation uses an HMAC session salted to the storage primary.
The session encrypts TPM command parameters. Unsealing uses a salted policy
session with response encryption. The operation stops if session setup fails.
The adapter has no plaintext transport fallback. The adapter flushes only
transient handles that it owns.

The trusted caller supplies the TCTI configuration. Tokens cannot select the
configuration. The adapter does not read ambient TCTI variables.
This initial implementation requires empty owner-hierarchy authorization.
The adapter does not change that authorization or create persistent handles.
Enrollment must use a trusted TPM transport. The primary Name recorded during
enrollment supplies the trust reference for later use.

Attested mode returns `UnsupportedMode`. The adapter does not yet implement
signed PCR update policies, AK/EK onboarding, `PolicySigned`, or NV rollback.
A boot-image measurement contract also needs later integration.
The caller must select and approve PCR snapshots. The adapter does not infer
that a measured image is trustworthy.

Install `swtpm`, Python 3, TPM2-TSS development libraries, and Rust on Linux.
Run `bash scripts/test-tpm.sh`. The script creates a disposable TPM state
directory and a loopback transport. It tests actual Rust sealing, primary
recreation, engine unlock, and encrypted sessions. It also tests rejection of
password authorization, signed metadata mismatches, corrupted private blobs,
and PCR changes. Ordinary Cargo tests skip the simulator test.
The adapter uses no runtime TPM subprocesses.

This adapter is not formally verified. TPM2-TSS and firmware remain trusted.
Rust secret wrappers zeroize their buffers. FFI stack copies and the lifetimes
of internal TPM library allocations require a separate memory audit.
A successful simulator test does not qualify a real discrete TPM or fTPM.
