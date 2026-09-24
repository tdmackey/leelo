# Network-bound protocol vector

Every key, seed, share, coefficient, and credential in this directory is public test data.
Never use these values for a real enrollment.

`network-bound-v1.json` fixes one complete envelope and recovery transcript.
It includes canonical descriptor/envelope bytes, context hashes, leaf contexts, the network input, VOPRF request/response/output, all derived wrapping keys, Shamir shares, and the LUKS token.
It also names the expected rejection cases.
The TPM blob is a synthetic test object. It is not a TPM interchange format.

The Rust tests reconstruct the fixture and compare every field with the stored values.
They then recover the credential through the production engine with fresh blinds.
Signed modifications to generation, binding, input seed, provider pin, TPM object, and payload must fail at the expected boundary.

```sh
cargo test -p leelo-assurance --locked
python3 scripts/check-protocol-vector.py
```

The Python check uses the `cryptography` package and its independent primitive backends.
It separately implements canonical CBOR framing, the application key-derivation framing, and polynomial evaluation.
It checks public-key derivation, signatures, derived keys, AEAD, the token, and frame boundaries.
Its VOPRF output is an explicit fixture input. It does not provide independent VOPRF or TPM interoperability evidence.
The Rust VOPRF primitive has separate RFC 9497 vector tests.

To propose a deliberate protocol-vector change, run this command and review the complete output before replacing the stored file:

```sh
cargo run -p leelo-assurance --example generate_vector --locked
```

Deterministic randomness and fixed nonces exist only in the fixture package's test support.
The production crypto API does not expose them.
