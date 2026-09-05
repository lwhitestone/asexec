"""Manifest construction, signing, and referencing.

A manifest is a small envelope::

    {
      "payloadType": "application/vnd.asexec+json",
      "payload":  { ...the signed body... },
      "signature": {"alg":"ed25519","keyid":..., "pubkey":..., "sig":...}
    }

Only the ``payload`` (body) is signed, over the PAE construction in
``canonical.py``. Bespoke JSON, borrowing in-toto field names (`subject`,
`predicateType`) without the DSSE/in-toto tooling.

Typed construction/validation lives in ``models.py`` (Pydantic); the crypto
here stays dict-based so the signed bytes are exactly the canonical bytes of a
plain dict — see ``canonical.py``.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Optional

from .canonical import canonical_bytes, signing_input
from .errors import ManifestError
from .models import Anchor, Manifest, ManifestBody, Signature
from . import keys

# Bedrock = the mandatory minimum whose absence breaks verifiability of the
# central commitment -> fulfillment / gap claim. Two disjoint reasons a field is
# bedrock:
#
#   structural : format-frame invariants — a body without these is not an
#                asexec manifest at all (they scope every other check).
#   semantic   : the claim the tool actually adjudicates — WHAT was committed to
#                (``target``). The deadline (``due``) is *optional*: a commitment
#                with no deadline simply stays ``open`` forever, so it is not
#                bedrock.
#
# Everything else — the drand floor, the ceiling witness, subject/hash_alg,
# declaration, free-text — is individually optional. `subject`/`hash_alg` are
# *conditionally* required together: a content claim is meaningless without its
# algorithm, so `hash_alg` is required iff `subject` is present.
_BEDROCK_STRUCTURAL = ("schema_version", "predicateType", "phase")
_BEDROCK_SEMANTIC = ("target",)

_DEFAULT_HASH_ALG = "sha-256"


def _build(phase: str, target, *, due=None, declaration=None,
           subject=None, hash_alg=None, fulfills=None, prev_hash=None,
           floor=None, identity=None, provenance=None,
           repro_recipe=None, notes=None) -> Dict[str, Any]:
    """Construct + validate a body via the model, return the plain signed dict."""
    if subject:
        hash_alg = hash_alg or _DEFAULT_HASH_ALG
    else:
        hash_alg = None  # never a dangling algorithm without a subject
    anchor = Anchor(floor=floor) if floor is not None else None
    body = ManifestBody(
        phase=phase, target=target, due=due, declaration=declaration,
        subject=subject, hash_alg=hash_alg, fulfills=fulfills, prev_hash=prev_hash,
        anchor=anchor, identity=identity, provenance=provenance,
        repro_recipe=repro_recipe, notes=notes,
    )
    return body.to_body()


def build_prereg(target, *, due=None, declaration=None,
                 subject=None, hash_alg=None, **optional) -> Dict[str, Any]:
    return _build("prereg", target, due=due, declaration=declaration,
                  subject=subject, hash_alg=hash_alg, **optional)


def build_postreg(target, *, fulfills, due=None, declaration=None,
                  subject=None, prev_hash=None, hash_alg=None, **optional) -> Dict[str, Any]:
    return _build("postreg", target, due=due, declaration=declaration,
                  subject=subject, hash_alg=hash_alg, fulfills=fulfills,
                  prev_hash=prev_hash, **optional)


def ref(body: Dict[str, Any]) -> str:
    """Stable content reference to a manifest body: ``sha-256:<hex>``.

    Computed over the canonical bytes of the body (signature-independent), so
    ``fulfills`` and ``prev_hash`` links are stable regardless of who signed.
    """
    return "sha-256:" + hashlib.sha256(canonical_bytes(body)).hexdigest()


def sign(body: Dict[str, Any], private_key: bytes, public_key: bytes) -> Dict[str, Any]:
    _check_bedrock(body)
    sig = keys.sign(private_key, signing_input(body))
    signature = Signature(
        keyid=keys.keyid_for(public_key), pubkey=public_key.hex(), sig=sig.hex(),
    )
    return Manifest(payload=body, signature=signature).model_dump(mode="json")


def _check_bedrock(body: Dict[str, Any]) -> None:
    """Dict-level signing gate.

    Kept alongside the model so a body assembled by hand (not via ``build_*``)
    still cannot be signed if it is missing a bedrock field — the model would
    silently re-supply the structural defaults, so presence must be checked on
    the dict as given.
    """
    missing = [f for f in (_BEDROCK_STRUCTURAL + _BEDROCK_SEMANTIC)
               if f not in body or body[f] in (None, "", [], {})]
    if missing:
        raise ManifestError(f"manifest body missing mandatory field(s): {', '.join(missing)}")
    if body.get("subject") and not body.get("hash_alg"):
        raise ManifestError("manifest body has a 'subject' but no 'hash_alg'")
    if body["phase"] == "postreg" and "fulfills" not in body:
        raise ManifestError("postreg manifest missing mandatory 'fulfills'")


def get_body(manifest: Dict[str, Any]) -> Dict[str, Any]:
    if "payload" not in manifest or "signature" not in manifest:
        raise ManifestError("not an asexec manifest (missing payload/signature)")
    return manifest["payload"]


def attach_ceiling(manifest: Dict[str, Any], ceiling: Dict[str, Any]) -> Dict[str, Any]:
    """Attach a ceiling witness at the ENVELOPE level (beside payload/signature).

    The ceiling cannot live inside the signed ``payload``: its nonce is
    ``ref(payload)`` (a hash of the body), so embedding it would be circular.
    It is self-authenticated by the witness signature and binds to this
    manifest via ``nonce == ref(payload)`` (checked by the verifier). Attaching
    a ceiling does not perturb ``ref``, so ``fulfills``/``prev_hash`` links stay
    stable and a ceiling can be attached after signing.
    """
    manifest["ceiling"] = ceiling
    return manifest


def get_ceiling(manifest: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    return manifest.get("ceiling")


def save(manifest: Dict[str, Any], path: str) -> None:
    with open(path, "w") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")


def load(path: str) -> Dict[str, Any]:
    with open(path) as f:
        return json.load(f)
