"""Constrained field types shared by the writer and input models (``models.py``).

Each type writes one *structural* requirement of ``docs/VERIFICATION.md`` once, so the
models that produce a manifest and the models that read one cannot drift apart.
"""

from __future__ import annotations

import re
from typing import Annotated, Any

from pydantic import AfterValidator, PlainValidator, Strict

from . import drand


def _fromhex_ok(value: str) -> str:
    bytes.fromhex(value)  # a ValueError here becomes a ValidationError
    return value


_LOWER_HEX = re.compile(r"(?:[0-9a-f]{2})*")


def _lower_hex(value: str) -> str:
    if not _LOWER_HEX.fullmatch(value):
        raise ValueError("not lowercase hex")
    return value


def _pinned_chain(value: str) -> str:
    if value not in drand.CHAINS:
        raise ValueError("not a drand chain the verifier pins")
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

# A drand chain hash the verifier pins (floor #2). ``drand.CHAINS`` is fixed at import.
PinnedChain = Annotated[str, AfterValidator(_pinned_chain)]

# ``payload.phase`` / ``fulfills`` / ``prev_hash``: compared by string equality, never
# parsed (chain #2). ``None`` when absent; any other non-string value is ``DANGLING``.
Link = Annotated[str | None, PlainValidator(_link)]
