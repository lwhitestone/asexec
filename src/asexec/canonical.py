"""Canonical serialization and the PAE signing input.

We sign the PAE (Pre-Authentication Encoding, borrowed from DSSE) of a fixed,
documented canonical byte serialization of the payload.
"""

from __future__ import annotations

import json
from typing import Any

from .constants import PAE_PREFIX, PAYLOAD_TYPE


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


def pae(payload_type: bytes, body: bytes) -> bytes:
    """Pre-Authentication Encoding.

    PAE(t, b) = PREFIX SP LEN(t) SP t SP LEN(b) SP b

    where SP is a single ASCII space and LEN is ASCII decimal of the byte
    length. Signing/verifying always happens over this string, never over raw
    JSON.
    """
    return b" ".join(
        [
            PAE_PREFIX,
            str(len(payload_type)).encode("ascii"),
            payload_type,
            str(len(body)).encode("ascii"),
            body,
        ]
    )


def signing_input(payload: Any) -> bytes:
    """The exact bytes to sign/verify for a manifest payload."""
    return pae(PAYLOAD_TYPE.encode("ascii"), canonical_bytes(payload))
