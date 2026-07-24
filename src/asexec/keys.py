"""ed25519 key management. Self-managed, pseudonymous, no CA.

A key is an ordinary local file. Key hygiene (backup, passphrase, HSM,
rotation) is the evaluator's standard signing-key responsibility and is out
of scope for v1. The public ``keyid`` is the SHA-256 of the raw public key,
which every identity-binding scheme references.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Tuple

import nacl.signing

from .errors import AsexecError

KEY_ALG = "ed25519"


def keyid_for(public_key: bytes) -> str:
    """Stable key identifier: ``sha-256:<hex of sha256(pubkey)>``."""
    return "sha-256:" + hashlib.sha256(public_key).hexdigest()


def generate() -> Tuple[bytes, bytes]:
    """Return (private_key_32b, public_key_32b)."""
    sk = nacl.signing.SigningKey.generate()
    return bytes(sk), bytes(sk.verify_key)


def save(private_key: bytes, path: str) -> str:
    """Write the secret key file (0600) and a sibling ``<path>.pub``.

    Returns the keyid.
    """
    pub = bytes(nacl.signing.SigningKey(private_key).verify_key)
    kid = keyid_for(pub)
    secret = {
        "version": 1,
        "alg": KEY_ALG,
        "keyid": kid,
        "private_key": private_key.hex(),
        "public_key": pub.hex(),
    }
    # create with restrictive permissions from the start
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(secret, f, indent=2)
    with open(path + ".pub", "w") as f:
        json.dump({"version": 1, "alg": KEY_ALG, "keyid": kid, "public_key": pub.hex()}, f, indent=2)
    return kid


def load_signing_key(path: str) -> Tuple[bytes, bytes]:
    """Load a secret key file, returning (private_key, public_key)."""
    with open(path) as f:
        data = json.load(f)
    if data.get("alg") != KEY_ALG:
        raise AsexecError(f"unsupported key alg {data.get('alg')!r}")
    priv = bytes.fromhex(data["private_key"])
    pub = bytes(nacl.signing.SigningKey(priv).verify_key)
    if "public_key" in data and bytes.fromhex(data["public_key"]) != pub:
        raise AsexecError("key file public_key does not match private_key")
    return priv, pub


def sign(private_key: bytes, message: bytes) -> bytes:
    return nacl.signing.SigningKey(private_key).sign(message).signature


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        nacl.signing.VerifyKey(public_key).verify(message, signature)
        return True
    except Exception:
        return False
