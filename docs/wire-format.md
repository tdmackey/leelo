# Experimental version-1 encoding

This document specifies a local implementation profile. It is not a stable interoperability standard.

## Signed envelope

All arrays have definite lengths. Integers and lengths use the shortest CBOR representation.

The decoder consumes all input. It re-encodes the parsed values and rejects noncanonical bytes. The decoder rejects indefinite arrays, maps, tags, floats, and unknown versions or suites.

The raw envelope cannot exceed 64 KiB. Available LUKS2 token space is smaller. A token write can fail because of this limit.

The outer array is `[body_bytes, signature_bytes64]`. The signature covers `"leelo/v1/envelope\0" || body_bytes`.

The decoder verifies the signature with an externally configured Ed25519 key. This check occurs **before** the body directs any TPM or network action.

The body array is `[descriptor_bytes, tpm_blob, wrapped_leaves, wrapped_credential]`.

The descriptor contains 13 entries in this order:

| Entry | Value |
|---|---|
| 1 | version1 |
| 2 | suite1 |
| 3 | bindingID32 |
| 4 | UUID16 |
| 5 | slot0..31 |
| 6 | Positive generation |
| 7 | mode0(network-bound)/1(attested) |
| 8 | TPM node ID |
| 9 | Network tree |
| 10 | Network bindings |
| 11 | Nonzero PCR mask |
| 12 | SHA256 PCR digest32 |
| 13 | Literal purpose `luks2-slot` |

A network tree leaf is `[0, node_id, provider_id32]`. A threshold is `[1, node_id, required, children]`.

`leelo-policy` checks production policy limits and identity uniqueness. Network bindings follow tree traversal order. Each binding is `[node_id, provider_id32, key_id32, public_key49, input_seed32]`.

The key ID is the first 32 bytes of SHA-384 applied to the encoded public key. Envelope validation rejects a key ID that does not match that public key. The shared `leelo-protocol` crate owns this rule and the evaluator messages.

The decoder rejects repeated evaluation public keys and repeated key IDs.

The TPM blob is `[public_bytes, private_bytes, child_name, parent_name]`. Each blob contains 1..4096 bytes. Each Name contains 1..68 bytes.

The TPM adapter performs exact validation of the TPM data. The envelope signature covers the Names and blobs.

Each wrapped leaf is `[node_id, wrapped_key]`. The TPM leaf is first. Network leaves follow in tree traversal order.

A wrapped key is `[nonce12, ciphertext48]`. It holds exactly 32 plaintext bytes and a 16-byte tag.

The root wrapper holds a random LUKS slot credential. It never holds a direct disk volume key.

## Contexts and key derivation

The context is:

`context = SHA384("leelo/v1/context\0" || canonical_descriptor)`.

The leaf context is:

`leaf_context = "leelo/v1/leaf\0" || context48 || node_id_u8`.

The descriptor transitively fixes parent and coordinate relationships, provider identity, volume, epoch, and suite.

The descriptor excludes generated blobs and ciphertexts to prevent cycles. The final signature covers these excluded values.

The VOPRF input is:

`"leelo/v1/network-input\0" || bindingID32 || node_id_u8 || input_seed32`.

Each request uses a new RFC blind. Finalize verifies the proof against the pinned public key.

The HKDF-SHA384 salt is `leelo/v1/hkdf-sha384`.

The HKDF info is:

`"leelo/v1/key" || purpose_length_u32be || purpose || context_length_u32be || context`.

The purposes are `voprf-leaf-wrap`, `leelo/v1/tpm-wrap`, and `leelo/v1/luks-slot`. Each context is the applicable leaf or root context.

Derived keys contain 32 bytes. Each encryption uses a fresh random 96-bit nonce. Each new enrollment creates fresh root secrets, leaf secrets, and IDs.

## LUKS2 token

The outer JSON contains exactly these fields:

* `type: "leelo"`.
* A `keyslots` array with one decimal string.
* An `envelope` value in canonical unpadded base64url.

The decoder rejects duplicate known fields, unknown fields, extra keyslots, and noncanonical slot strings. The signed slot and UUID must match the selected target.

The evaluator uses separate fixed binary framing. `leelo-net` describes this framing. Neither endpoint accepts a general-purpose cryptographic object or algorithm negotiation.
