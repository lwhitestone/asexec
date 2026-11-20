"""Canonical serialization and the PAE signing input.

We sign the PAE (Pre-Authentication Encoding, borrowed from DSSE) of a fixed,
documented canonical byte serialization of the payload.
"""

from __future__ import annotations

import json
from typing import Any

from .constants import FORMATS, MANIFEST_PAYLOAD_TYPE


def canonical_bytes(payload: Any) -> bytes:
    """Deterministically serialize a JSON-compatible object to bytes.

    Rules (documented so any implementation can reproduce them):
      - UTF-8
      - object keys sorted (lexicographic, by Unicode code point)
      - no insignificant whitespace (compact separators)
      - non-ASCII preserved (ensure_ascii=False)

    The payload passed here must NOT contain the outer signature block; only
    the manifest body is signed.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def pae(version: bytes, payload_type: bytes, body: bytes) -> bytes:
    """Pre-Authentication Encoding.

    PAE(t, b) = VERSION SP LEN(t) SP t SP LEN(b) SP b

    where VERSION is the format's ``signing_pae_version``, SP is a single ASCII space
    and LEN is ASCII decimal of the byte length. Signing/verifying always happens over
    this string, never over raw JSON.
    """
    return b" ".join(
        [
            version,
            str(len(payload_type)).encode("ascii"),
            payload_type,
            str(len(body)).encode("ascii"),
            body,
        ]
    )


def signing_input(payload: Any, payload_type: str = MANIFEST_PAYLOAD_TYPE) -> bytes:
    """The exact bytes to sign/verify for a manifest payload of format ``payload_type`` (a
    key of ``FORMATS``; by default the one signing writes), under that format's rules."""
    version = FORMATS[payload_type]["signing_pae_version"]
    return pae(version, payload_type.encode("ascii"), canonical_bytes(payload))
