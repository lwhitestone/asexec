"""Raw manifest data for the verify tests, independent of the production builder.

``verify`` judges files it did not write, so its tests start from plain dicts rather than
``manifest.build_*``. A schema change edits the bodies here and the builder's own tests;
``tests/verify/test_verify_builder_guard.py`` fails until the builder agrees.

A file is a wrapper around a DSSE envelope: ``{"dsse": {"payloadType", "payload", "signatures":
[{"keyid", "sig"}]}, "pubkey"}``, where ``dsse.payload`` is the base64 of the body bytes and
``sig`` the base64 of the signature, as DSSE has them, and ``pubkey`` is hex. Signing
serializes a body as the writer does (``canonical_bytes``) and reuses the library's
``signing_input``, so the signed bytes are the real ones, and writes the ``payloadType``
signing writes (pinned in ``tests/test_constants.py``), so a release commit that changes it
changes these files with it. Any bytes can be signed (``sign_bytes``), and nothing else of the
writer is used, so nothing gates what can be signed.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
from typing import Any

import nacl.signing

from asexec import keys
from asexec.canonical import canonical_bytes, pae, signing_input
from asexec.constants import FORMATS, MANIFEST_PAYLOAD_TYPE

# The files a verify scenario writes under --artifacts, and their sha-256 digests
# ("harness/" is the directory hash of hashing.py's v1 scheme).
ARTIFACTS = {
    "harness/eval.py": "def run():\n    return 42\n",
    **{f"transcript{i}.txt": f"run {i}: score=0.{i}\n" for i in range(3)},
}
DIGESTS = {
    "harness/": "2edb1fb893693308cab35ab8fa26f2be6a8a459b02f6f3fcd2100c712115ce09",
    "transcript0.txt": "95df040e723a615372bc3d293ffef85be5b530e678fcb26e18f7177a41524691",
    "transcript1.txt": "0d576426c32f17c207749e124f2aa222dd863f92d7a810dcf8097f078398239b",
    "transcript2.txt": "9e692c724057f5d7662349313efb4420cc2b3d1124dda2d61d068eccaa074d4e",
}

TARGET = {"kind": "api", "provider": "anthropic", "model_id": "m", "endpoint": ""}
DUE = "2099-01-01T00:00:00Z"

# Real quicknet round 1000 (fetched once; verification is offline).
FLOOR = {
    "floor_type": "drand",
    "chain_hash": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
    "round": 1000,
    "signature": (
        "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125"
        "e342b73a8dd2bacbe47e4b6b63ed5e39"
    ),
    "randomness": "fe290beca10872ef2fb164d2aa4442de4566183ec51c56ff3cd603d930e54fdd",
}

_SEED = bytes(range(32))
TEST_KEY = (_SEED, bytes(nacl.signing.SigningKey(_SEED).verify_key))


def subject_entry(name: str) -> dict[str, Any]:
    return {"name": name, "digest": {"sha-256": DIGESTS[name]}}


def body_bytes(body: dict[str, Any]) -> bytes:
    """The bytes signing stores for ``body``: its canonical serialization."""
    return canonical_bytes(body)


def ref(body: dict[str, Any] | bytes) -> str:
    """``sha-256:`` + the hex sha-256 of the body bytes (``body``'s, if it is a dict)."""
    raw = body if isinstance(body, bytes) else body_bytes(body)
    return "sha-256:" + hashlib.sha256(raw).hexdigest()


# A valid prereg, and a valid postreg fulfilling it: a chain of one.
PREREG = {
    "predicateType": "https://asexec.org/manifest/v1",
    "phase": "prereg",
    "target": TARGET,
    "due": DUE,
    "declaration": "all runs in full",
    "subject": [subject_entry("harness/")],
    "hash_alg": "sha-256",
    "notes": "prereg",
}
POSTREG = {
    **PREREG,
    "phase": "postreg",
    "subject": [subject_entry("transcript0.txt"), subject_entry("harness/")],
    "fulfills": ref(PREREG),
    "notes": "postreg0",
}


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


# A well-formed signature (strict base64 of 64 bytes) that verifies under no key.
ZERO_SIG = b64(bytes(64))


def sign_bytes(raw: bytes, key: tuple[bytes, bytes] = TEST_KEY) -> dict[str, Any]:
    """A file around the body bytes ``raw``, signed by ``key`` whatever they hold."""
    priv, pub = key
    return {
        "dsse": {
            "payloadType": MANIFEST_PAYLOAD_TYPE,
            "payload": base64.b64encode(raw).decode("ascii"),
            "signatures": [
                {"keyid": keys.keyid_for(pub), "sig": b64(keys.sign(priv, signing_input(raw)))}
            ],
        },
        "pubkey": pub.hex(),
    }


def sign(body: dict[str, Any], key: tuple[bytes, bytes] = TEST_KEY) -> dict[str, Any]:
    """A file around ``body``, signed by ``key`` whatever the body holds."""
    return sign_bytes(body_bytes(body), key)


def sign_labelled(
    body: dict[str, Any], payload_type: str, key: tuple[bytes, bytes] = TEST_KEY
) -> dict[str, Any]:
    """A file labelled ``payload_type`` whose signature is valid under this release's PAE
    version with that type in it: what verify would accept if it fell back to its own
    rules for a format it does not read."""
    priv, _pub = key
    envelope = sign(body, key)
    version = FORMATS[MANIFEST_PAYLOAD_TYPE]["signing_pae_version"]
    signed = pae(version, payload_type.encode(), body_bytes(body))
    envelope["dsse"]["payloadType"] = payload_type
    envelope["dsse"]["signatures"][0]["sig"] = b64(keys.sign(priv, signed))
    return envelope


def decoded(envelope: dict[str, Any]) -> bytes:
    """The body bytes ``envelope["dsse"]["payload"]`` holds."""
    return base64.b64decode(envelope["dsse"]["payload"], validate=True)


def body_of(envelope: dict[str, Any]) -> dict[str, Any]:
    """The body ``envelope`` holds, decoded."""
    return json.loads(decoded(envelope))


def store(envelope: dict[str, Any], raw: bytes) -> None:
    """In place: make ``raw`` the body bytes ``envelope`` holds. Its signature is kept."""
    envelope["dsse"]["payload"] = base64.b64encode(raw).decode("ascii")


def _segments(path: str) -> list[str | int]:
    """``a.b[0].c`` or ``a.b.0.c`` -> ``["a", "b", 0, "c"]``."""
    return [int(k) if k.isdigit() else k for k in re.sub(r"\[(\d+)\]", r".\1", path).split(".")]


def set_path(obj: Any, path: str, value: Any) -> None:
    """In place: set the dotted ``path`` (``[N]`` or a numeric segment indexes an array),
    creating missing objects on the way."""
    *parents, last = _segments(path)
    for key in parents:
        obj = obj[key] if isinstance(key, int) else obj.setdefault(key, {})
    obj[last] = value


def del_path(obj: Any, path: str) -> None:
    """In place: remove the dotted ``path`` if it is there."""
    *parents, last = _segments(path)
    for key in parents:
        obj = obj[key]
    if isinstance(last, int):
        del obj[last]
    else:
        obj.pop(last, None)


def with_field(data: dict[str, Any], path: str, value: Any) -> dict[str, Any]:
    out = copy.deepcopy(data)
    set_path(out, path, value)
    return out


def without_field(data: dict[str, Any], path: str) -> dict[str, Any]:
    out = copy.deepcopy(data)
    del_path(out, path)
    return out


def malformed(body: dict[str, Any]) -> dict[str, Any]:
    """A file around ``body``, signed, that is malformed all the same: its
    ``dsse.signatures`` is not an array (format #1), so no test reads the body."""
    envelope = sign(body)
    envelope["dsse"]["signatures"] = envelope["dsse"]["signatures"][0]
    return envelope
