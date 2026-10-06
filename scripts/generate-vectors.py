#!/usr/bin/env python3
"""Regenerate independent COSE fixtures using cryptography and cbor2, not csgn.

Install these tools in an isolated development environment if needed. This script
only rewrites the four named fixture constants in the Rust vector/ring tests.
"""
from pathlib import Path
import hashlib
import re

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

NOW = 1_790_000_000
MAX_VALIDITY = 30 * 86_400
SEED_1 = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")


def vector(seed, issuer, kind, payload, validity):
    key = Ed25519PrivateKey.from_private_bytes(seed)
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    kid = hashlib.sha256(cbor2.dumps({1: 1, -1: 6, -2: public}, canonical=True)).digest()
    protected = cbor2.dumps({1: -19, 2: [15, -65537], 4: kid,
                            15: {1: issuer, 4: NOW + validity, 6: NOW}, -65537: kind})
    signature = key.sign(cbor2.dumps(["Signature1", protected, b"", payload]))
    message = cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload, signature]))
    ring = cbor2.dumps({1: 2, 2: issuer, 3: [{1: 1, 2: kid, 3: -19, 4: [2],
                       -1: 6, -2: public, -65537: NOW}], 4: MAX_VALIDITY})
    return message, ring


one = vector(SEED_1, "cmty", "credential", b"csgn test vector", 86_400)
two = vector(bytes([1] * 32), "cgbl", "snapshot/revocation-list", bytes.fromhex("a1636e657701"), 3_600)
fixtures = dict(zip(["COSE_1", "RING_1", "COSE_2", "RING_2"], [*one, *two]))
root = Path(__file__).resolve().parent.parent
for name in ["vectors.rs", "ring.rs"]:
    path = root / "tests" / name
    text = path.read_text()
    for label, value in fixtures.items():
        encoded = value.hex()
        lines = "\n".join(f'    "{encoded[i:i + 80]}",' for i in range(0, len(encoded), 80))
        text = re.sub(rf'const {label}: &str = concat!\(.*?\);',
                      f'const {label}: &str = concat!(\n{lines}\n);', text, flags=re.S)
    path.write_text(text)
