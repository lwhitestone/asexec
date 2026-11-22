"""Manifest construction, signing, and referencing.

A manifest file is an asexec wrapper around a standard DSSE envelope::

    {
      "dsse": {
        "payloadType": "application/vnd.asexec.v1+json",
        "payload": "<base64 of the body bytes>",
        "signatures": [{"keyid": "sha-256:...", "sig": "<base64 of the signature>"}]
      },
      "pubkey": "<hex>",
      "untrusted": {"asexec_version": "..."},  (unsigned, read by no test)
      "ceiling": { ... }                       (optional, unsigned)
    }

The body is the JSON object the body bytes hold. Only the body bytes are signed, over
DSSE's PAE (``canonical.py``), and ``ref`` is their digest: both are of the bytes exactly
as stored, never re-serialized. Signing writes the bytes once, from the body's canonical
serialization. The body borrows in-toto field names (``subject``, ``predicateType``).

Typed construction/validation lives in ``models.py`` (Pydantic); the crypto here stays
dict-based so the signed bytes are exactly the canonical bytes of a plain dict.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Any

from . import keys
from .canonical import build_signing_input, decode_base64, encode_base64, serialize_canonical
from .constants import FORMATS, MANIFEST_PAYLOAD_TYPE
from .errors import ManifestError
from .models import Anchor, Dsse, Manifest, ManifestBody, Signature
from .parsing import MAX_NESTING_DEPTH, parse_json

# The signing gate: what signing refuses to go without. It is the writer's rule, not a
# verify test. format and selfsig check every file's frame and signature, never body
# fields, and signing meets both by construction. This gate adds what makes a body
# mean something to the tests that read it:
#
#   phase          : how verify matches a manifest (commitments, chain, keyconsist,
#                    timely, complete, order).
#   fulfills       : a postreg's link to its prereg's ref; without it, the postreg is
#                    notarization-only. Required of a postreg only (see _check_signable).
#   target         : what was committed to. No test reads it; it is the claim itself.
#   predicateType  : names the body for in-toto consumers. verify selects the format by
#                    dsse.payloadType and never reads it.
#
# Everything else in the body is optional, due included: a commitment with no due never
# elapses (no-due until a postreg counts). Each subject, plan and evidence entry carries
# its own hash_alg: a digest means nothing without its algorithm, and no default
# supplies one.
_REQUIRED_TO_SIGN = ("predicateType", "phase", "target")


def _build(
    phase: str,
    target,
    *,
    due=None,
    declaration=None,
    subject=None,
    fulfills=None,
    prev_hash=None,
    floor=None,
    provenance=None,
    repro_recipe=None,
    notes=None,
    plan=None,
    items=None,
    item_id=None,
    status=None,
    evidence=None,
) -> dict[str, Any]:
    """Construct + validate a body via the model, return the plain signed dict."""
    # The fields that may hold objects or arrays, before the model recurses into them.
    values = [target, declaration, subject, floor, repro_recipe, notes, plan, items, evidence]
    for value in values:
        _check_value_within_max_nesting_depth(
            value, MAX_NESTING_DEPTH - 1
        )  # each sits one level into the body
    anchor = Anchor(floor=floor) if floor is not None else None
    body = ManifestBody(
        phase=phase,
        target=target,
        due=due,
        declaration=declaration,
        subject=subject,
        fulfills=fulfills,
        prev_hash=prev_hash,
        anchor=anchor,
        provenance=provenance,
        repro_recipe=repro_recipe,
        notes=notes,
        plan=plan,
        items=items,
        item_id=item_id,
        status=status,
        evidence=evidence,
    )
    return body.dump_body()


def build_prereg(target, **fields) -> dict[str, Any]:
    return _build("prereg", target, **fields)


def build_postreg(target, *, fulfills, **fields) -> dict[str, Any]:
    return _build("postreg", target, fulfills=fulfills, **fields)


def derive_ref(body_bytes: bytes, payload_type: str = MANIFEST_PAYLOAD_TYPE) -> str:
    """Stable content reference to a manifest body: ``sha-256:<hex>`` of its body bytes as
    stored, with the prefix of format ``payload_type`` (by default the one signing writes).

    Independent of the signature, so ``fulfills`` and ``prev_hash`` links are stable
    regardless of who signed. Never re-serialized: two spellings of one JSON value are two
    bodies.
    """
    prefix = FORMATS[payload_type]["digest_ref_prefix"]
    return prefix + hashlib.sha256(body_bytes).hexdigest()


def sign(body: dict[str, Any], private_key: bytes, public_key: bytes) -> dict[str, Any]:
    """Serialize ``body`` to its body bytes and sign them: the file, as a dict, with the
    unsigned ``untrusted.asexec_version`` of this release beside them."""
    # Refuse what verify would reject as too deep (format #2), before encoding recurses into it.
    _check_value_within_max_nesting_depth(body, MAX_NESTING_DEPTH)
    _check_signable(body)
    body_bytes = serialize_canonical(body)
    sig = keys.sign(private_key, build_signing_input(body_bytes))
    dsse = Dsse(
        payload=encode_base64(body_bytes),
        signatures=[Signature(keyid=keys.derive_keyid(public_key), sig=encode_base64(sig))],
    )
    return Manifest(dsse=dsse, pubkey=public_key.hex()).model_dump(mode="json")


def _check_value_within_max_nesting_depth(value: Any, max_depth: int) -> None:
    """Refuse a value to be signed that nests more than ``max_depth`` deep, or holds itself.

    It doesn't recurse: deep enough, the model and the encoder overflow the C stack, which can
    kill the process rather than raise. It walks level by level, each container once per
    level, so shared values can't multiply the work.
    """
    level = [value]
    depth = 0
    while containers := {id(v): v for v in level if isinstance(v, dict | list | tuple)}:
        depth += 1
        if depth > max_depth:
            raise ManifestError(f"the body would be nested more than {MAX_NESTING_DEPTH} deep")
        level = [
            child
            for container in containers.values()
            for child in (container.values() if isinstance(container, dict) else container)
        ]


def _check_signable(body: dict[str, Any]) -> None:
    """The signing gate, checked on the dict.

    Kept alongside the model so a body assembled by hand (not via ``build_*``)
    still cannot be signed if it is missing a field the gate requires - the model would
    silently re-supply the structural defaults, so presence must be checked on
    the dict as given.
    """
    missing = [f for f in _REQUIRED_TO_SIGN if f not in body or body[f] in (None, "", [], {})]
    if missing:
        raise ManifestError(f"manifest body missing mandatory field(s): {', '.join(missing)}")
    _check_entries(body.get("subject"), "subject")
    _check_entries(body.get("evidence"), "evidence")
    if isinstance(body.get("plan"), dict):
        _check_entries([body["plan"]], "plan")
    if body["phase"] == "postreg":
        fulfills = body.get("fulfills")
        if not isinstance(fulfills, str) or not fulfills:
            raise ManifestError(
                "postreg manifest missing mandatory 'fulfills' (a non-empty string)"
            )


def _check_entries(entries: Any, field: str) -> None:
    """Each entry of a hand-built ``subject``, ``evidence`` or ``plan`` carries its own
    ``hash_alg``, and no two of one list share a ``name`` (what ``content`` would fail)."""
    if not isinstance(entries, list):
        return
    names = []
    for entry in entries:
        if isinstance(entry, dict) and not entry.get("hash_alg"):
            raise ManifestError(f"a {field} entry has no 'hash_alg'")
        names.append(entry.get("name") if isinstance(entry, dict) else None)
    counts = Counter(n for n in names if isinstance(n, str))
    repeated = sorted(n for n, k in counts.items() if k > 1)
    if repeated:
        raise ManifestError(f"{field} lists {', '.join(map(repr, repeated))} twice")


def read_body(manifest: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    """The body bytes a manifest file stores, and the body they hold.

    Raises ``ManifestError`` unless ``dsse.payload`` is strict base64 of bytes that
    ``parse_body`` accepts (format #2). It checks nothing else of the file.
    """
    dsse = manifest.get("dsse")
    payload = dsse.get("payload") if isinstance(dsse, dict) else None
    if not isinstance(payload, str):
        raise ManifestError("not an asexec manifest (no dsse.payload string)")
    try:
        body_bytes = decode_base64(payload)
    except ValueError as e:
        raise ManifestError(f"dsse.payload is {e}") from None
    return body_bytes, parse_body(body_bytes)


def derive_witness_nonce(manifest: dict[str, Any]) -> str:
    """The nonce a ceiling witnesses for a signed file: ``sha-256:`` and the sha-256 of its
    ``pubkey``'s bytes, its signature's bytes and the signing input that signature covers
    (VERIFICATION.md, ceiling #2). So a ceiling shows this key had signed these bytes by its
    time, and can't be moved to the same body signed by another key. Raises ``KeyError``,
    ``IndexError``, ``TypeError`` or ``ValueError`` for a file with no such signature."""
    dsse = manifest["dsse"]
    payload_type = dsse["payloadType"]
    signed = build_signing_input(decode_base64(dsse["payload"]), payload_type)
    sig = decode_base64(dsse["signatures"][0]["sig"])
    witnessed = bytes.fromhex(manifest["pubkey"]) + sig + signed
    return FORMATS[payload_type]["digest_ref_prefix"] + hashlib.sha256(witnessed).hexdigest()


def attach_ceiling(manifest: dict[str, Any], ceiling: dict[str, Any]) -> dict[str, Any]:
    """Attach a ceiling witness in the wrapper, beside ``dsse`` and ``pubkey``.

    The ceiling can only be fetched after signing: its nonce covers the signature
    (``derive_witness_nonce``). It is self-authenticated by the witness signature, and the
    verifier checks the nonce. Attaching a ceiling changes neither ``ref`` nor the signature,
    so ``fulfills``/``prev_hash`` links stay stable.
    """
    manifest["ceiling"] = ceiling
    return manifest


def get_ceiling(manifest: dict[str, Any]) -> dict[str, Any] | None:
    return manifest.get("ceiling")


def save(manifest: dict[str, Any], path: str) -> None:
    with open(path, "w") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")


def _parse_object(text: str, what: str) -> dict[str, Any]:
    """The JSON rules a file and a body are both held to (``parse_json``), and a JSON object.
    Raises ``ManifestError`` or ``json.JSONDecodeError`` (a ``ValueError``)."""
    data = parse_json(text, MAX_NESTING_DEPTH)
    if not isinstance(data, dict):
        raise ManifestError(f"{what} must be a JSON object")
    return data


def load(path: str) -> dict[str, Any]:
    """Load a manifest file.

    Raises ``ManifestError`` for anything that is not a JSON object with unique
    keys, nested at most ``MAX_NESTING_DEPTH`` deep; ``OSError`` /
    ``UnicodeDecodeError`` / ``json.JSONDecodeError`` may also propagate (callers
    that must not crash catch them).
    """
    with open(path, encoding="utf-8") as f:
        text = f.read()
    return _parse_object(text, "manifest")


def parse_body(body_bytes: bytes) -> dict[str, Any]:
    """The body that body bytes hold, held to the file's JSON rules on its own.

    The bytes must be UTF-8 JSON text (RFC 8259; no byte order mark, so not UTF-16 or
    UTF-32) of an object with unique keys, nested at most ``MAX_NESTING_DEPTH`` deep,
    counted from the body's own outermost object. Raises ``ManifestError`` otherwise. A
    lone surrogate escape (``"\\ud800"``) is valid JSON text, and is read as the string it
    spells.
    """
    try:
        text = body_bytes.decode("utf-8")
        return _parse_object(text, "the body")
    except ManifestError:
        raise
    except ValueError as e:  # not UTF-8 (UnicodeDecodeError), or not JSON (JSONDecodeError)
        raise ManifestError(str(e)) from None
