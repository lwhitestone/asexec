"""The JSON rules every input is held to: manifest files and bodies, key files, identity
documents and the CLI's JSON values.

It imports only ``errors``, so any module can use it.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .errors import ManifestError


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """``object_pairs_hook``: a repeated key is ambiguous (parsers disagree on
    which wins), so a file that contains one is malformed."""
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ManifestError(f"duplicate JSON key {key!r}")
        out[key] = value
    return out


# The deepest a manifest file, or the body it holds, may nest arrays and objects (the
# outermost object is 1). Each is counted on its own: the file holds the body as a string, so
# a body's depth is the same in any file. Manifests nest about 5 deep. A deeper one is
# rejected before it is parsed, so no parser, model or encoder ever reaches its recursion
# limit: those limits differ between Python versions and machines, and would make the same
# file verify differently.
MAX_NESTING_DEPTH = 64

# A JSON string (skipped, so brackets inside one don't count) or a bracket. The quantifiers are
# possessive and the closing quote optional, so the scan is linear: an unterminated string runs
# to the end of the text, which json.loads then rejects, and is never rescanned.
_STRING_OR_BRACKET = re.compile(r'"[^"\\]*+(?:\\.[^"\\]*+)*+"?|[\[\]{}]', re.DOTALL)


def _check_within_max_nesting_depth(text: str, max_depth: int) -> None:
    depth = 0
    for match in _STRING_OR_BRACKET.finditer(text):
        token = match.group()
        if token in ("[", "{"):
            depth += 1
            if depth > max_depth:
                raise ManifestError(f"nested more than {max_depth} deep")
        elif token in ("]", "}"):
            depth -= 1


def parse_json(text: str, max_depth: int) -> Any:
    """A JSON value held to the JSON rules of a manifest file: unique keys, nested at most
    ``max_depth`` deep (``MAX_NESTING_DEPTH``, or less for a value to sit inside a body). Raises
    ``ManifestError`` for either rule, else a ``ValueError`` if ``text`` is not JSON
    (``json.JSONDecodeError``, or an integer of more digits than Python reads). The CLI holds
    every JSON value it is given to these rules."""
    _check_within_max_nesting_depth(text, max_depth)
    return json.loads(text, object_pairs_hook=_reject_duplicate_keys)
