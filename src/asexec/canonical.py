"""The body bytes signing writes, their canonical base64 spelling, and the PAE signing input.

A manifest stores its body as bytes: ``dsse.payload`` is their base64, and signer and
verifier both sign and check those bytes exactly as stored, through DSSE's PAE. Nothing is
re-serialized to verify. Signing still has to produce the bytes once, so it writes a
documented canonical serialization; a body another writer spelled differently verifies just
the same.
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any

from .constants import FORMATS, MANIFEST_PAYLOAD_TYPE
from .errors import ManifestError


def canonical_bytes(payload: Any) -> bytes:
    """Deterministically serialize a JSON-compatible object to the body bytes signing stores.

    Rules (documented so any implementation can reproduce them):
      - UTF-8
      - object keys sorted (lexicographic, by Unicode code point)
      - no insignificant whitespace (compact separators)
      - non-ASCII preserved (ensure_ascii=False)

    Raises ``ManifestError`` for a string with no UTF-8 form (one holding a lone surrogate).
    Verify never calls this: it reads the bytes a file stores.
    """
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    try:
        return text.encode("utf-8")
    except UnicodeEncodeError as e:
        raise ManifestError(f"the body has a string with no UTF-8 form: {e.reason}") from e


def encode_base64(data: bytes) -> str:
    """``data`` in standard, padded base64: the one spelling ``decode_base64`` accepts."""
    return base64.b64encode(data).decode("ascii")


# Why a string is not the base64 of any bytes (format #2), the same on every Python version.
NOT_STRICT_BASE64 = (
    "not strict base64 (the standard alphabet, padded, no whitespace, one spelling per byte string)"
)


def decode_base64(text: str) -> bytes:
    """The bytes ``text`` is the strict base64 of: the standard alphabet, padding required,
    no whitespace, and exactly the spelling ``encode_base64`` gives them (so no unused bit is
    set). Anything else raises ``ValueError``, so each byte string has one spelling."""
    try:
        data = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):  # ValueError: a str that is not ASCII
        raise ValueError(NOT_STRICT_BASE64) from None
    if encode_base64(data) != text:
        raise ValueError(NOT_STRICT_BASE64)
    return data


def pae(version: bytes, payload_type: bytes, body: bytes) -> bytes:
    """Pre-Authentication Encoding (DSSE).

    PAE(t, b) = VERSION SP LEN(t) SP t SP LEN(b) SP b

    where VERSION is the format's ``signing_pae_version`` (``DSSEv1``), SP is a single
    ASCII space and LEN is ASCII decimal of the byte length. Signing/verifying always
    happens over this string, never over raw JSON.
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


def signing_input(body: bytes, payload_type: str = MANIFEST_PAYLOAD_TYPE) -> bytes:
    """The exact bytes to sign/verify for the body bytes ``body`` of format ``payload_type``
    (a key of ``FORMATS``; by default the one signing writes), under that format's rules."""
    version = FORMATS[payload_type]["signing_pae_version"]
    return pae(version, payload_type.encode("ascii"), body)
