"""Content hashing and the ``subject`` builder.

SHA-256 is the default and always available (stdlib). The algorithm is named
in every manifest (`hash_alg`, a mandatory field) so it is algorithm-agile:
other algorithms (e.g. BLAKE3, if the optional dependency is installed) can be
selected without a format change.

Directory hashing (v1): a *sorted manifest of file hashes*. We walk every
regular file under the directory, take each file's hash, and hash the sorted
list of ``"<hexhash>  <relpath>\\n"`` lines (bytewise-sorted by relpath).
Deterministic and auditable with common tools.

Documented v1 limitation: this captures file *contents* and *relative paths*
only — not the executable bit, symlink targets, or empty directories. A
future NAR-style serialization would capture those; see 04-plan.md.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any, Callable, Dict, List

from .errors import HashAlgError

DEFAULT_ALG = "sha-256"

# name -> zero-arg factory returning a fresh hashlib-like object with
# .update(bytes) and .hexdigest().
_ALGORITHMS: Dict[str, Callable[[], Any]] = {
    "sha-256": hashlib.sha256,
}

try:  # optional: register BLAKE3 if available
    import blake3 as _blake3  # type: ignore

    _ALGORITHMS["blake3"] = _blake3.blake3  # pragma: no cover
except Exception:  # pragma: no cover
    pass


def available_algorithms() -> List[str]:
    return sorted(_ALGORITHMS)


def _new(alg: str):
    try:
        return _ALGORITHMS[alg]()
    except KeyError:
        raise HashAlgError(
            f"unknown or unavailable hash algorithm {alg!r}; "
            f"available: {', '.join(available_algorithms())}"
        )


def hash_bytes(data: bytes, alg: str = DEFAULT_ALG) -> str:
    h = _new(alg)
    h.update(data)
    return h.hexdigest()


def hash_file(path: str, alg: str = DEFAULT_ALG, chunk: int = 1 << 20) -> str:
    h = _new(alg)
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def _iter_files(root: str):
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            full = os.path.join(dirpath, name)
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            rel = os.path.relpath(full, root)
            yield rel.replace(os.sep, "/"), full


def hash_dir(path: str, alg: str = DEFAULT_ALG) -> str:
    """Hash a directory tree via a sorted manifest of file hashes."""
    lines = []
    for rel, full in _iter_files(path):
        lines.append(f"{hash_file(full, alg)}  {rel}")
    manifest = ("\n".join(sorted(lines)) + "\n").encode("utf-8")
    return hash_bytes(manifest, alg)


def digest_path(path: str, alg: str = DEFAULT_ALG) -> str:
    """Hash a file or directory, returning a hex digest."""
    if os.path.isdir(path):
        return hash_dir(path, alg)
    return hash_file(path, alg)


def build_subject(paths: List[str], alg: str = DEFAULT_ALG) -> List[Dict[str, Any]]:
    """Build the manifest ``subject`` array from a list of paths.

    Each entry: ``{"name": <display>, "digest": {alg: hexhash}}``. Directory
    names are suffixed with "/".
    """
    subject = []
    for p in paths:
        name = os.path.basename(os.path.normpath(p))
        if os.path.isdir(p):
            name += "/"
        subject.append({"name": name, "digest": {alg: digest_path(p, alg)}})
    return subject
