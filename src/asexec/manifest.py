"""Manifest construction, signing, and referencing.

A manifest is a small envelope::

    {
      "payloadType": "application/vnd.asexec+json",
      "payload":  { ...the signed body... },
      "signature": {"alg":"ed25519","keyid":..., "pubkey":..., "sig":...}
    }

Only the ``payload`` (body) is signed, over the PAE construction in
``canonical.py``. Bespoke JSON, borrowing in-toto field names (`subject`,
`predicateType`, `predicate`-style `notes`) without the DSSE/in-toto tooling.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional

from . import PREDICATE_TYPE, SCHEMA_VERSION
from .canonical import canonical_bytes, signing_input
from .errors import ManifestError
from . import keys

# Bedrock = the mandatory minimum whose absence breaks verifiability of the
# central commitment -> fulfillment / gap claim (the governing rule from the
# interview). 0.2.0 splits it into two disjoint reasons a field is bedrock:
#
#   structural : format-frame invariants — a body without these is not an
#                asexec manifest at all (they scope every other check).
#   semantic   : the two claims the tool actually adjudicates — WHAT was
#                committed to (target_identity) and BY WHEN it must be
#                disclosed (disclosure_window). Without these there is no
#                commitment to verify against.
#
# Everything else — the drand floor, the ceiling witness, subject/hash_alg,
# free-text — is individually optional (roadmap #1). `subject`/`hash_alg` are
# *conditionally* required: a content claim is meaningless without its
# algorithm, so `hash_alg` is required iff `subject` is present.
_BEDROCK_STRUCTURAL = ("schema_version", "predicateType", "phase")
_BEDROCK_SEMANTIC = ("target_identity", "disclosure_window")


def _base_body(phase: str, target_identity: dict, disclosure_window: dict, *,
               subject: Optional[List[dict]] = None,
               hash_alg: Optional[str] = None) -> Dict[str, Any]:
    body: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "predicateType": PREDICATE_TYPE,
        "phase": phase,
        "target_identity": target_identity,
        "disclosure_window": disclosure_window,
    }
    # subject (and its algorithm) are now optional: a pre-registration may
    # commit to a target + window before any harness exists to hash.
    if subject:
        body["subject"] = subject
        body["hash_alg"] = hash_alg or "sha-256"
    return body


def _attach_optional(body: Dict[str, Any], *, floor=None, identity=None,
                     provenance=None, repro_recipe=None, notes=None) -> Dict[str, Any]:
    if floor is not None:
        # anchor.floor is the signed, sign-time freshness beacon (drand). The
        # ceiling witness lives at the ENVELOPE level, not here, because its
        # nonce is ref(body) and so cannot be inside the signed body.
        body["anchor"] = {"floor": floor}
    if identity is not None:
        body["identity"] = identity
    if provenance is not None:
        body["provenance"] = provenance
    if repro_recipe is not None:
        body["repro_recipe"] = repro_recipe
    if notes is not None:
        body["notes"] = notes
    return body


def build_preregistration(target_identity, disclosure_window, *,
                          subject=None, hash_alg=None, **optional) -> Dict[str, Any]:
    body = _base_body("preregistration", target_identity, disclosure_window,
                      subject=subject, hash_alg=hash_alg)
    return _attach_optional(body, **optional)


def build_receipt(target_identity, disclosure_window, *, fulfills,
                  subject=None, prev_hash=None, hash_alg=None, **optional) -> Dict[str, Any]:
    body = _base_body("receipt", target_identity, disclosure_window,
                      subject=subject, hash_alg=hash_alg)
    body["fulfills"] = fulfills
    body["prev_hash"] = prev_hash
    return _attach_optional(body, **optional)


def ref(body: Dict[str, Any]) -> str:
    """Stable content reference to a manifest body: ``sha-256:<hex>``.

    Computed over the canonical bytes of the body (signature-independent), so
    ``fulfills`` and ``prev_hash`` links are stable regardless of who signed.
    """
    return "sha-256:" + hashlib.sha256(canonical_bytes(body)).hexdigest()


def sign(body: Dict[str, Any], private_key: bytes, public_key: bytes) -> Dict[str, Any]:
    _check_bedrock(body)
    sig = keys.sign(private_key, signing_input(body))
    return {
        "payloadType": "application/vnd.asexec+json",
        "payload": body,
        "signature": {
            "alg": "ed25519",
            "keyid": keys.keyid_for(public_key),
            "pubkey": public_key.hex(),
            "sig": sig.hex(),
        },
    }


def _check_bedrock(body: Dict[str, Any]) -> None:
    missing = [f for f in (_BEDROCK_STRUCTURAL + _BEDROCK_SEMANTIC)
               if f not in body or body[f] in (None, "", [], {})]
    if missing:
        raise ManifestError(f"manifest body missing mandatory field(s): {', '.join(missing)}")
    # conditional: a subject (content claim) is meaningless without its algorithm.
    if body.get("subject") and not body.get("hash_alg"):
        raise ManifestError("manifest body has a 'subject' but no 'hash_alg'")
    if body["phase"] == "receipt" and "fulfills" not in body:
        raise ManifestError("receipt manifest missing mandatory 'fulfills'")


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
