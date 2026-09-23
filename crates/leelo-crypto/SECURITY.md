# Cryptographic profile and review scope

This candidate implementation has not had an audit.
Successful test vectors do not prove the enclosing NBDE protocol or
constant-time machine code. They do not prove safe TPM and LUKS integration.
This crate forbids unsafe code in its own source. Dependencies require
separate review.

The only recovery suite is RFC 9497 VOPRF P384-SHA384, with one input per request.
Public points use 49-byte compressed SEC1 encoding. Proofs use 96-byte `c || s`
encoding. Client state permits one use. The caller must supply the trusted
server public key independently of the response. The random client input has
domain framing and remains local. This crate exposes no OPRF or POPRF modes,
negotiation, custom ECC, or deterministic-blind API.

HKDF-SHA384 uses `leelo/v1/hkdf-sha384` as its salt. Its info field concatenates
these values in this order:

1. `leelo/v1/key`.
2. A 4-byte big-endian purpose length.
3. The purpose.
4. A 4-byte big-endian context length.
5. The context.

VOPRF wrapping uses the purpose `voprf-leaf-wrap`. Other roles must use
separate purposes. Callers bind their canonical envelope context and AEAD
associated data. Key wrapping encrypts exactly 32 bytes with ChaCha20-Poly1305.
Each encryption uses a fresh 96-bit nonce from the OS.

Ed25519 signatures authenticate exactly the supplied bytes with strict
verification. The application must supply canonical messages with domain
separation. Stored VOPRF keys contain only the secret scalar. The import
operation derives the public key. It never trusts an independently supplied
public key in a stored key pair.

Secret wrappers do not implement Debug, Clone, or Serialize. Explicit exports
for storage return buffers that zeroize on drop. The caller must protect
exported bytes and prevent logs, swapping, dumps, and filesystem races.
Zeroization does not establish that all compiler temporaries, registers, or
dependency internals are erased.

Known qualification requirements and limits:

- RustCrypto p384 states that its arithmetic has not had an independent audit.
  Release requires an audit and a constant-time assessment of the target and compiler.
- voprf 0.5.0 rejects zero scalar encodings, including proof scalars.
  RFC 9497 permits zero proof scalars. The library can reject an extremely rare valid proof.
  This interoperability restriction fails closed. The implementation does not fully conform to RFC 9497.
- The upstream blind/evaluate API requires an infallible CryptoRng.
  OsRng panics if OS entropy fails during those calls. The operation stops with no weak fallback.
  Other randomness calls return an error.
- RFC 9497 documents static-DH query-oracle security limits. Server request
  budgets and lifecycle policy remain outside this primitive wrapper.

References: [RFC 9497](https://www.rfc-editor.org/rfc/rfc9497.html),
[voprf 0.5.0](https://docs.rs/voprf/0.5.0/voprf/),
[p384 security notice](https://docs.rs/p384/0.13.1/p384/).
