"""Content hashing and the ``subject`` builder.

SHA-256 is the default and always available (stdlib). Each subject entry names its own
algorithm (``hash_alg``) beside its digest, so it can be substituted; other algorithms (e.g.
BLAKE3, if the optional dependency is installed) can be selected without a format change.

A subject is an explicit list of files, each hashed exactly as listed. There is no directory
hash: to commit to a tree, list its files, or pack it (a tar, for example) and list the
archive. An entry's ``name`` is the file's path as given, relative to the current directory,
normalized and ``/``-separated (``./a//b.txt`` is ``a/b.txt``), so two files with the same
basename stay distinct. Signing refuses what ``content`` fails in any manifest: a directory or
anything else that is not a regular file, an absolute path, a ``..`` component, a backslash,
and two paths with the same name. A symlink is hashed through to its target, under its own
name. Signing does not check where a symlink points, so one that resolves outside the
directory verify is given as ``--artifacts`` is signed, and fails ``content`` (#5) there.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from typing import Any

from .errors import HashAlgError, ManifestError
from .fields import is_normal_name

# name -> zero-arg factory returning a fresh hashlib-like object with
# .update(bytes) and .hexdigest().
_ALGORITHMS: dict[str, Callable[[], Any]] = {
    "sha-256": hashlib.sha256,
}

try:  # optional: register BLAKE3 if available
    import blake3 as _blake3  # type: ignore

    _ALGORITHMS["blake3"] = _blake3.blake3  # pragma: no cover
except Exception:  # pragma: no cover
    pass


def available_algorithms() -> list[str]:
    return sorted(_ALGORITHMS)


def _new(alg: str):
    try:
        return _ALGORITHMS[alg]()
    except KeyError:
        raise HashAlgError(
            f"unknown or unavailable hash algorithm {alg!r}; "
            f"available: {', '.join(available_algorithms())}"
        ) from None


def hash_file(path: str, alg: str, chunk: int = 1 << 20) -> str:
    h = _new(alg)
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def name_problem(text: str) -> str | None:
    """Why ``text`` names no file a manifest can hold, or None: it has a NUL character (no
    path has one), or a character with no UTF-8 form (a lone surrogate, or a byte that is not
    UTF-8 as the OS decodes it), which no body can hold."""
    if "\x00" in text:
        return "a NUL character"
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return "a character with no UTF-8 form"
    return None


def _check_holdable(path: str) -> None:
    why = name_problem(path)
    if why:
        raise ManifestError(f"{path!r} names no file a manifest can hold: it has {why}")


def entry_name(path: str) -> str:
    """The ``name`` of the file at ``path`` (as given, relative to the current directory):
    normalized and ``/``-separated. Raises ``ManifestError`` for a path that no normalized
    relative name can stand for: absolute, with a ``..`` component, or (where ``\\`` is not
    a separator) with a backslash, which another system would read as a separator, or one a
    manifest cannot hold (``name_problem``)."""
    _check_holdable(path)
    if os.path.isabs(path) or os.path.splitdrive(path)[0]:
        raise ManifestError(
            f"{path!r} is an absolute path; name a file by its path relative to the current "
            "directory (verify looks it up under --artifacts)"
        )
    text = path.replace(os.sep, "/")
    if os.altsep:
        text = text.replace(os.altsep, "/")
    if "\\" in text:
        raise ManifestError(f"{path!r} has a backslash, which some systems read as a separator")
    segments = [seg for seg in text.split("/") if seg not in ("", ".")]
    if ".." in segments:
        raise ManifestError(f"{path!r} has a '..' component; name the file without it")
    name = "/".join(segments)
    if not is_normal_name(name):  # e.g. "" or "."; a directory, refused by the caller first
        raise ManifestError(f"{path!r} does not name a file")
    return name


def build_entry(path: str, alg: str) -> dict[str, Any]:
    """``{"name", "hash_alg", "digest": {alg: hex}}`` for the one file at ``path``.

    Refuses (``ManifestError``) a directory, anything else that exists but is not a regular
    file, and a path ``entry_name`` refuses. A symlink is hashed through to its target. A
    missing file raises ``FileNotFoundError``."""
    _check_holdable(path)  # before the filesystem is asked, which can't take such a path
    if os.path.isdir(path):
        raise ManifestError(
            f"{path!r} is a directory; list its files, or pack it (a tar, say) and list that"
        )
    if os.path.exists(path) and not os.path.isfile(path):
        raise ManifestError(f"{path!r} is not a regular file")
    name = entry_name(path)
    return {"name": name, "hash_alg": alg, "digest": {alg: hash_file(path, alg)}}


def build_entries(paths: list[str], alg: str) -> list[dict[str, Any]]:
    """One entry per path (``build_entry``), refusing two paths with the same name."""
    entries: list[dict[str, Any]] = []
    seen: dict[str, str] = {}
    for p in paths:
        entry = build_entry(p, alg)
        if entry["name"] in seen:
            raise ManifestError(
                f"{seen[entry['name']]!r} and {p!r} both name {entry['name']!r}: "
                "a file is listed twice"
            )
        seen[entry["name"]] = p
        entries.append(entry)
    return entries


def build_subject(paths: list[str], alg: str) -> list[dict[str, Any]]:
    """Build the manifest ``subject`` array from a list of file paths (``build_entries``)."""
    return build_entries(paths, alg)
