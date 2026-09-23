#!/usr/bin/env python3
"""Check public fixture composition with Python and OpenSSL-backed cryptography.

This is a test oracle. It is not a production implementation or a VOPRF oracle.
The VOPRF output is an explicit fixture input; Rust checks it against RFC-tested code.
"""
import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def head(kind, count):
    if count < 24:
        return bytes([(kind << 5) | count])
    for tag, width in [(24, 1), (25, 2), (26, 4), (27, 8)]:
        if count < 1 << (8 * width):
            return bytes([(kind << 5) | tag]) + count.to_bytes(width, "big")
    raise ValueError("integer too large")


def encode(value):
    if isinstance(value, int):
        return head(0, value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode()
        return head(3, len(raw)) + raw
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(map(encode, value))
    raise ValueError("unsupported fixture type")


def decode(raw):
    def item(position):
        initial = raw[position]
        position += 1
        kind, size = initial >> 5, initial & 31
        if size >= 24:
            width = {24: 1, 25: 2, 26: 4, 27: 8}[size]
            size = int.from_bytes(raw[position:position + width], "big")
            position += width
        if kind == 0:
            return size, position
        if kind in (2, 3):
            value = raw[position:position + size]
            assert len(value) == size
            return value if kind == 2 else value.decode(), position + size
        if kind == 4:
            result = []
            for _ in range(size):
                value, position = item(position)
                result.append(value)
            return result, position
        raise ValueError("unsupported fixture CBOR")
    value, consumed = item(0)
    assert consumed == len(raw)
    assert encode(value) == raw, "noncanonical fixture encoding"
    return value


def derive(ikm, context, purpose):
    info = (b"leelo/v1/key" + len(purpose).to_bytes(4, "big") + purpose
            + len(context).to_bytes(4, "big") + context)
    return HKDF(algorithm=hashes.SHA384(), length=32,
                salt=b"leelo/v1/hkdf-sha384", info=info).derive(ikm)


def mul(a, b):
    product = 0
    for _ in range(8):
        if b & 1:
            product ^= a
        b >>= 1
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
    return product


def main():
    fixture = Path(__file__).resolve().parent.parent / "test-vectors/network-bound-v1.json"
    vector = json.loads(fixture.read_text(encoding="utf-8-sig"))
    binary = lambda name: bytes.fromhex(vector[name])
    assert vector["schema_version"] == 1
    private = ec.derive_private_key(int.from_bytes(binary("evaluation_secret"), "big"), ec.SECP384R1())
    public = private.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    assert public == binary("evaluation_public")
    assert hashlib.sha384(public).digest()[:32] == binary("key_id")
    signer = ed25519.Ed25519PrivateKey.from_private_bytes(binary("signing_seed"))
    assert signer.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw) == binary("signing_public")
    outer = decode(binary("envelope"))
    signer.public_key().verify(outer[1], b"leelo/v1/envelope\0" + outer[0])
    body = decode(outer[0])
    assert body[0] == binary("descriptor")
    descriptor = decode(body[0])
    assert descriptor[:2] == [1, 1] and descriptor[4:8] == [3, 7, 0, 0]
    assert descriptor[8] == [0, 1, bytes([0x23]) * 32]
    binding = descriptor[9][0]
    assert binding == [1, bytes([0x23]) * 32, binary("key_id"), public, bytes([0x24]) * 32]
    context = hashlib.sha384(b"leelo/v1/context\0" + body[0]).digest()
    assert context == binary("context")
    tpm_context, network_context = [b"leelo/v1/leaf\0" + context + bytes([i]) for i in (0, 1)]
    assert tpm_context == binary("tpm_context") and network_context == binary("network_context")
    network_input = b"leelo/v1/network-input\0" + descriptor[2] + bytes([binding[0]]) + binding[4]
    assert network_input == binary("network_input")
    keys = [derive(binary("tpm_seed"), tpm_context, b"leelo/v1/tpm-wrap"),
            derive(binary("voprf_output"), network_context, b"voprf-leaf-wrap"),
            derive(binary("root_secret"), context, b"leelo/v1/luks-slot")]
    assert keys == [binary(name) for name in ("tpm_key", "network_key", "payload_key")]
    root = binary("root_secret")
    coefficient = binary("root_coefficient")
    shares = [bytes(s ^ mul(a, x) for s, a in zip(root, coefficient)) for x in (1, 2)]
    assert shares == [binary("tpm_share"), binary("network_share")]
    for index, (key, aad) in enumerate(zip(keys[:2], [tpm_context, network_context])):
        leaf, wrapped = body[2][index]
        assert leaf == index
        assert ChaCha20Poly1305(key).decrypt(wrapped[0], wrapped[1], aad) == shares[index]
    assert ChaCha20Poly1305(keys[2]).decrypt(body[3][0], body[3][1], context) == binary("credential")
    token = json.loads(vector["luks_token"])
    assert token["type"] == "leelo" and token["keyslots"] == ["3"]
    assert base64.urlsafe_b64decode(token["envelope"] + "===") == binary("envelope")
    assert binary("request")[:8] == binary("response")[:8] == b"LEEL\x01\x01\x01\x00"
    assert len(binary("request")) == 89 and len(binary("response")) == 153
    assert binary("request")[8:40] == binary("key_id")
    print("PASS: independent CBOR, key derivation, signature, sharing, AEAD, token and frame checks")
    print("VOPRF output and synthetic TPM blob are fixture inputs; this is not an independent TPM/VOPRF implementation.")


if __name__ == "__main__":
    main()
