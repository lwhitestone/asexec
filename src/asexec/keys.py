"""ed25519 key management. Self-managed, pseudonymous, no CA.

A key is an ordinary local file. Key hygiene (backup, passphrase, HSM,
rotation) is the evaluator's standard signing-key responsibility and is out
of scope for v1. The public ``keyid`` is the SHA-256 of the raw public key,
which every identity-binding scheme references.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os

import nacl.signing

from .constants import FORMATS, MANIFEST_PAYLOAD_TYPE
from .errors import AsexecError
from .parsing import MAX_NESTING_DEPTH, parse_json

# The algorithm of the format signing writes: a key file names it, and only such a key signs.
_ALG = FORMATS[MANIFEST_PAYLOAD_TYPE]["signing_key_alg"]


def derive_keyid(public_key: bytes, payload_type: str = MANIFEST_PAYLOAD_TYPE) -> str:
    """Stable key identifier: ``sha-256:<hex of sha256(pubkey)>``, with the prefix of format
    ``payload_type`` (by default the one signing writes)."""
    return FORMATS[payload_type]["digest_ref_prefix"] + hashlib.sha256(public_key).hexdigest()


def generate() -> tuple[bytes, bytes]:
    """Return (private_key_32b, public_key_32b)."""
    sk = nacl.signing.SigningKey.generate()
    return bytes(sk), bytes(sk.verify_key)


def save(private_key: bytes, path: str, *, force: bool = False) -> str:
    """Write the secret key file (0600 on Unix) and a sibling ``<path>.pub``.

    Refuses to overwrite either file (``FileExistsError``) unless ``force``.
    Returns the keyid.
    """
    pub = bytes(nacl.signing.SigningKey(private_key).verify_key)
    kid = derive_keyid(pub)
    secret = {
        "version": 1,
        "alg": _ALG,
        "keyid": kid,
        "private_key": private_key.hex(),
        "public_key": pub.hex(),
    }

    # O_EXCL makes "does not exist" and "create" one atomic step. Check the .pub
    # first so a refusal never leaves a half-written pair.
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if force else os.O_EXCL)
    if not force and os.path.lexists(path + ".pub"):
        raise FileExistsError(errno.EEXIST, os.strerror(errno.EEXIST), path + ".pub")
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(secret, f, indent=2)

    # Unix permission bits are not meaningful on Windows.
    if os.name != "nt":
        os.chmod(path, 0o600)

    with open(path + ".pub", "w") as f:
        json.dump(
            {
                "version": 1,
                "alg": _ALG,
                "keyid": kid,
                "public_key": pub.hex(),
            },
            f,
            indent=2,
        )

    return kid


def load_signing_key(path: str) -> tuple[bytes, bytes]:
    """Load a secret key file, returning (private_key, public_key).

    Raises ``OSError`` if the file cannot be read, else ``AsexecError`` if it is not
    a valid key file."""
    with open(path) as f:
        try:  # a manifest file's JSON rules: no repeated key, and at most 64 deep, so no
            # parser reaches its recursion limit (which differs between Python versions)
            data = parse_json(f.read(), MAX_NESTING_DEPTH)
        except (ValueError, AsexecError) as e:  # not UTF-8 or JSON, or a rule broken
            raise AsexecError(f"key file {path!r} is not valid JSON: {e}") from None
    if not isinstance(data, dict):
        raise AsexecError(f"key file {path!r} is not a JSON object")
    if data.get("alg") != _ALG:
        raise AsexecError(f"unsupported key alg {data.get('alg')!r}")
    try:
        priv = bytes.fromhex(data["private_key"])
        pub = bytes(nacl.signing.SigningKey(priv).verify_key)
        stored = bytes.fromhex(data["public_key"]) if "public_key" in data else pub
    except (KeyError, TypeError, ValueError) as e:  # nacl's errors subclass these
        raise AsexecError(f"{path!r} is not a valid key file: {e}") from e
    if stored != pub:
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
