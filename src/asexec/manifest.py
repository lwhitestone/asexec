"""Manifest construction, signing, and referencing.

A manifest file is an asexec wrapper around a standard DSSE envelope::

    {
      "dsse": {
        "payloadType": "application/vnd.asexec.v1+json",
        "payload": "<base64 of the body bytes>",
        "signatures": [{"keyid": "sha-256:...", "sig": "<hex>"}]
      },
      "pubkey": "<hex>",
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
import re
from typing import Any

from . import keys
from .canonical import b64decode, b64encode, canonical_bytes, signing_input
from .constants import FORMATS, MANIFEST_PAYLOAD_TYPE, SUBJECT_DEFAULT_HASH_ALG
from .errors import ManifestError
from .models import Anchor, Dsse, Manifest, ManifestBody, Signature

# Bedrock = the mandatory minimum whose absence breaks verifiability of the
# central commitment -> fulfillment / gap claim. Two disjoint reasons a field is
# bedrock:
#
#   structural : body-frame invariants - a body without these is not an
#                asexec manifest at all (they scope every other check).
#   semantic   : the claim the tool actually adjudicates - what was committed to
#                (``target``). The deadline (``due``) is *optional*: a commitment
#                with no deadline simply stays ``open`` forever, so it is not
#                bedrock.
#
# Everything else - the drand floor, the Roughtime ceiling witness, subject/hash_alg,
# declaration, free-text - is individually optional. `subject`/`hash_alg` are
# *conditionally* required together: a content claim is meaningless without its
# algorithm, so `hash_alg` is required iff `subject` is present.
_BEDROCK_STRUCTURAL = ("predicateType", "phase")
_BEDROCK_SEMANTIC = ("target",)


def _build(
    phase: str,
    target,
    *,
    due=None,
    declaration=None,
    subject=None,
    hash_alg=None,
    fulfills=None,
    prev_hash=None,
    floor=None,
    identity=None,
    provenance=None,
    repro_recipe=None,
    notes=None,
) -> dict[str, Any]:
    """Construct + validate a body via the model, return the plain signed dict."""
    if subject:
        hash_alg = hash_alg or SUBJECT_DEFAULT_HASH_ALG
    else:
        hash_alg = None  # never a dangling algorithm without a subject
    anchor = Anchor(floor=floor) if floor is not None else None
    body = ManifestBody(
        phase=phase,
        target=target,
        due=due,
        declaration=declaration,
        subject=subject,
        hash_alg=hash_alg,
        fulfills=fulfills,
        prev_hash=prev_hash,
        anchor=anchor,
        identity=identity,
        provenance=provenance,
        repro_recipe=repro_recipe,
        notes=notes,
    )
    return body.to_body()


def build_prereg(
    target, *, due=None, declaration=None, subject=None, hash_alg=None, **optional
) -> dict[str, Any]:
    return _build(
        "prereg",
        target,
        due=due,
        declaration=declaration,
        subject=subject,
        hash_alg=hash_alg,
        **optional,
    )


def build_postreg(
    target,
    *,
    fulfills,
    due=None,
    declaration=None,
    subject=None,
    prev_hash=None,
    hash_alg=None,
    **optional,
) -> dict[str, Any]:
    return _build(
        "postreg",
        target,
        due=due,
        declaration=declaration,
        subject=subject,
        hash_alg=hash_alg,
        fulfills=fulfills,
        prev_hash=prev_hash,
        **optional,
    )


def ref(body_bytes: bytes, payload_type: str = MANIFEST_PAYLOAD_TYPE) -> str:
    """Stable content reference to a manifest body: ``sha-256:<hex>`` of its body bytes as
    stored, with the prefix of format ``payload_type`` (by default the one signing writes).

    Independent of the signature, so ``fulfills`` and ``prev_hash`` links are stable
    regardless of who signed. Never re-serialized: two spellings of one JSON value are two
    bodies.
    """
    prefix = FORMATS[payload_type]["digest_ref_prefix"]
    return prefix + hashlib.sha256(body_bytes).hexdigest()


def sign(body: dict[str, Any], private_key: bytes, public_key: bytes) -> dict[str, Any]:
    """Serialize ``body`` to its body bytes and sign them: the file, as a dict."""
    _check_bedrock(body)
    body_bytes = canonical_bytes(body)
    sig = keys.sign(private_key, signing_input(body_bytes))
    dsse = Dsse(
        payload=b64encode(body_bytes),
        signatures=[Signature(keyid=keys.keyid_for(public_key), sig=sig.hex())],
    )
    return Manifest(dsse=dsse, pubkey=public_key.hex()).model_dump(mode="json")


def _check_bedrock(body: dict[str, Any]) -> None:
    """Dict-level signing gate.

    Kept alongside the model so a body assembled by hand (not via ``build_*``)
    still cannot be signed if it is missing a bedrock field - the model would
    silently re-supply the structural defaults, so presence must be checked on
    the dict as given.
    """
    missing = [
        f
        for f in (_BEDROCK_STRUCTURAL + _BEDROCK_SEMANTIC)
        if f not in body or body[f] in (None, "", [], {})
    ]
    if missing:
        raise ManifestError(f"manifest body missing mandatory field(s): {', '.join(missing)}")
    if body.get("subject") and not body.get("hash_alg"):
        raise ManifestError("manifest body has a 'subject' but no 'hash_alg'")
    if body["phase"] == "postreg" and "fulfills" not in body:
        raise ManifestError("postreg manifest missing mandatory 'fulfills'")


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
        body_bytes = b64decode(payload)
    except ValueError as e:
        raise ManifestError(f"dsse.payload is {e}") from None
    return body_bytes, parse_body(body_bytes)


def attach_ceiling(manifest: dict[str, Any], ceiling: dict[str, Any]) -> dict[str, Any]:
    """Attach a ceiling witness in the wrapper, beside ``dsse`` and ``pubkey``.

    The ceiling cannot live inside the signed body: its nonce is the body's ``ref`` (a hash
    of the body bytes), so embedding it would be circular. It is self-authenticated by the
    witness signature and binds to this manifest via ``nonce == ref`` (checked by the
    verifier). Attaching a ceiling does not perturb ``ref``, so ``fulfills``/``prev_hash``
    links stay stable and a ceiling can be attached after signing.
    """
    manifest["ceiling"] = ceiling
    return manifest


def get_ceiling(manifest: dict[str, Any]) -> dict[str, Any] | None:
    return manifest.get("ceiling")


def save(manifest: dict[str, Any], path: str) -> None:
    with open(path, "w") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")


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

# A JSON string (skipped, so brackets inside one don't count) or a bracket.
_STRING_OR_BRACKET = re.compile(r'"(?:[^"\\]|\\.)*"|[\[\]{}]', re.DOTALL)


def _check_nesting(text: str) -> None:
    depth = 0
    for match in _STRING_OR_BRACKET.finditer(text):
        token = match.group()
        if token in ("[", "{"):
            depth += 1
            if depth > MAX_NESTING_DEPTH:
                raise ManifestError(f"nested more than {MAX_NESTING_DEPTH} deep")
        elif token in ("]", "}"):
            depth -= 1


def _parse_object(text: str, what: str) -> dict[str, Any]:
    """The JSON rules a file and a body are both held to: a JSON object with unique keys,
    nested at most ``MAX_NESTING_DEPTH`` deep. Raises ``ManifestError`` or
    ``json.JSONDecodeError`` (a ``ValueError``)."""
    _check_nesting(text)
    data = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
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
