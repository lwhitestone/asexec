"""Raw manifest data for the verify tests, independent of the production builder.

``verify`` judges files it did not write, so its tests start from plain dicts rather
than ``manifest.build_*``. A schema change edits the bodies here and the builder's own
tests; ``tests/verify/test_verify_builder_guard.py`` fails until the builder agrees.

Signing reuses the library's ``signing_input``, so the signed bytes are the real ones.
Nothing else of the writer is used, so nothing gates what can be signed.
"""

from __future__ import annotations

import copy
import hashlib
from typing import Any

import nacl.signing

from asexec import keys
from asexec.canonical import canonical_bytes, signing_input

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


def ref(body: dict[str, Any]) -> str:
    """``sha-256:`` + the hex sha-256 of the body's canonical bytes."""
    return "sha-256:" + hashlib.sha256(canonical_bytes(body)).hexdigest()


# A valid prereg, and a valid postreg fulfilling it: a chain of one.
PREREG = {
    "schema_id": "asexec",
    "predicateType": "https://asexec.dev/manifest",
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


def sign(body: dict[str, Any], key: tuple[bytes, bytes] = TEST_KEY) -> dict[str, Any]:
    """An envelope around ``body``, signed by ``key`` whatever the body holds."""
    priv, pub = key
    return {
        "payloadType": "application/vnd.asexec+json",
        "payload": copy.deepcopy(body),
        "signature": {
            "alg": "ed25519",
            "keyid": keys.keyid_for(pub),
            "pubkey": pub.hex(),
            "sig": keys.sign(priv, signing_input(body)).hex(),
        },
    }


def resign(envelope: dict[str, Any], key: tuple[bytes, bytes] = TEST_KEY) -> dict[str, Any]:
    """A copy of ``envelope`` whose payload is signed again, by ``key``."""
    return {**copy.deepcopy(envelope), "signature": sign(envelope["payload"], key)["signature"]}


def set_path(obj: Any, path: str, value: Any) -> None:
    """In place: set the dotted ``path`` (a numeric segment indexes an array), creating
    missing objects on the way."""
    *parents, last = [int(k) if k.isdigit() else k for k in path.split(".")]
    for key in parents:
        obj = obj[key] if isinstance(key, int) else obj.setdefault(key, {})
    obj[last] = value


def del_path(obj: Any, path: str) -> None:
    """In place: remove the dotted ``path`` if it is there."""
    *parents, last = [int(k) if k.isdigit() else k for k in path.split(".")]
    for key in parents:
        obj = obj[key]
    obj.pop(last, None)


def with_field(data: dict[str, Any], path: str, value: Any) -> dict[str, Any]:
    out = copy.deepcopy(data)
    set_path(out, path, value)
    return out


def without_field(data: dict[str, Any], path: str) -> dict[str, Any]:
    out = copy.deepcopy(data)
    del_path(out, path)
    return out


def tamper_body(envelope: dict[str, Any], path: str, value: Any) -> dict[str, Any]:
    """A copy of ``envelope`` with ``payload.<path>`` changed and the old signature kept."""
    return with_field(envelope, f"payload.{path}", value)
