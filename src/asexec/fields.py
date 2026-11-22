"""Constrained field types shared by the writer and input models (``models.py``).

Each type writes one *structural* requirement of ``docs/VERIFICATION.md`` once, so the
models that produce a manifest and the models that read one cannot drift apart.
"""

from __future__ import annotations

import re
from typing import Annotated, Any

from pydantic import AfterValidator, PlainValidator, Strict

from . import canonical, chains


def _fromhex_ok(value: str) -> str:
    bytes.fromhex(value)  # a ValueError here becomes a ValidationError
    return value


def _check_base64(value: str) -> str:
    canonical.decode_base64(value)  # a ValueError here becomes a ValidationError
    return value


# The length of an ed25519 signature, the one algorithm v1 signs with.
_ED25519_SIGNATURE_LENGTH = 64


def _check_signature(value: str) -> str:
    if len(canonical.decode_base64(value)) != _ED25519_SIGNATURE_LENGTH:  # a ValueError: not base64
        raise ValueError(f"not {_ED25519_SIGNATURE_LENGTH} bytes, an ed25519 signature's length")
    return value


_LOWER_HEX = re.compile(r"(?:[0-9a-f]{2})*")


def _lower_hex(value: str) -> str:
    if not _LOWER_HEX.fullmatch(value):
        raise ValueError("not lowercase hex")
    return value


def _pinned_chain(value: str) -> str:
    if value not in chains.CHAINS:
        raise ValueError("not a drand chain the verifier pins")
    return value


def is_normal_name(name: str) -> bool:
    """Whether ``name`` is a relative path in normal form (content #3): ``/``-separated
    segments, none of them empty, ``.`` or ``..``, and no backslash. So an absolute name,
    ``./a``, ``a//b``, ``a/``, ``a/../b`` and ``a\\b`` are not, and one file has one name."""
    return (
        bool(name)
        and "\\" not in name
        and all(seg not in ("", ".", "..") for seg in name.split("/"))
    )


def _check_normal_name(value: str) -> str:
    if not is_normal_name(value):
        raise ValueError("not a normalized relative path")
    return value


# A link that is present but not a string can never equal a ref, so it is read as this
# marker: it links to nothing (a gap), and it is never mistaken for an absent link (a root).
DANGLING = "(malformed link)"


def _link(value: Any) -> str | None:
    return value if value is None or isinstance(value, str) else DANGLING


# An integer, never a coerced "1000", 1000.7 or True (floor #3).
StrictInt = Annotated[int, Strict()]

# Hex as ``bytes.fromhex`` accepts it (VERIFICATION.md, Conventions, Hex). Kept as the
# string as written: comparisons against a computed digest stay exact.
Hex = Annotated[str, AfterValidator(_fromhex_ok)]

# Hex as this tool writes it: lowercase, no whitespace. The writer models use it, so the
# tool never writes a spelling that an exact comparison with a digest would reject.
LowerHex = Annotated[str, AfterValidator(_lower_hex)]

# Strict base64 (format #2): the standard alphabet, padded, no whitespace, and the one
# spelling of its bytes. Kept as the string as written; ``canonical.decode_base64`` gives the bytes.
# The writer models use it too: the only spelling the tool writes is the one verify reads.
Base64 = Annotated[str, AfterValidator(_check_base64)]

# A DSSE ``sig`` (selfsig #2): strict base64, as DSSE has it, of an ed25519 signature's 64
# bytes. Used by the writer too, so the tool writes only what verify reads.
SignatureBase64 = Annotated[str, AfterValidator(_check_signature)]

# A subject, plan or evidence ``name`` as this tool writes it (content #3).
NormalName = Annotated[str, AfterValidator(_check_normal_name)]

# A drand chain hash the verifier pins (floor #2). ``chains.CHAINS`` is fixed at import.
PinnedChain = Annotated[str, AfterValidator(_pinned_chain)]

# ``body.phase`` / ``fulfills`` / ``prev_hash``: compared by string equality, never
# parsed (chain #2). ``None`` when absent; any other non-string value is ``DANGLING``.
Link = Annotated[str | None, PlainValidator(_link)]
