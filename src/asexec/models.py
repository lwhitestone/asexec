"""Pydantic models for asexec manifest bodies and envelopes.

These give typed *construction and validation* of manifests. They deliberately
do NOT participate in the cryptography: signing is always over the canonical
bytes of a plain ``dict`` (see ``canonical.py``). A model is built, validated,
then dumped to a dict via :meth:`ManifestBody.to_body` (``mode="json"``,
``exclude_none=True``) before it is signed / referenced / serialized.

The verifier reads raw dicts, never these models, so an unknown or future field
in a published manifest can never break offline verification — the models only
gate what *this* tool writes.

Schema note (v3 term/type refactor): ``phase`` is ``prereg`` | ``postreg``;
the commitment is expressed as a free-form ``target`` (what) plus an optional
``due`` deadline (by when) and an optional ``declaration`` (plain-language or
structured description). Semantic bedrock is ``target`` alone — ``due`` is
optional (a commitment with no deadline simply stays ``open`` forever).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from . import PREDICATE_TYPE, SCHEMA_VERSION

# A field the caller may express either as a plain string or as structured JSON.
# "take what is provided and compile it" — more disclosure buys more trust, but
# nothing beyond ``target`` is required.
Freeform = Union[str, Dict[str, Any]]

PHASES = ("prereg", "postreg")


class SubjectItem(BaseModel):
    """One hashed artifact: ``{"name": ..., "digest": {alg: hexhash}}``."""

    model_config = ConfigDict(extra="forbid")

    name: str
    digest: Dict[str, str]


class Floor(BaseModel):
    """A drand freshness floor (``anchor.floor``). ``extra="allow"`` keeps any
    future beacon fields verbatim through a round-trip."""

    model_config = ConfigDict(extra="allow")

    floor_type: str
    chain_hash: Optional[str] = None
    round: Optional[int] = None
    signature: Optional[str] = None
    randomness: Optional[str] = None


class Anchor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    floor: Optional[Floor] = None


class ManifestBody(BaseModel):
    """The signed body of a manifest (the ``payload``).

    ``extra="forbid"`` because construction is fully typed here — a stray field
    is a bug in the caller, not something to sign silently.
    """

    model_config = ConfigDict(extra="forbid")

    # structural bedrock — the format frame
    schema_version: str = SCHEMA_VERSION
    predicateType: str = PREDICATE_TYPE
    phase: str

    # semantic bedrock — WHAT was committed to (the only mandatory claim)
    target: Freeform

    # the commitment's optional shape
    due: Optional[str] = None
    declaration: Optional[Freeform] = None

    # optional content claim (subject requires its algorithm)
    subject: Optional[List[SubjectItem]] = None
    hash_alg: Optional[str] = None

    # postreg linkage
    fulfills: Optional[str] = None
    prev_hash: Optional[str] = None

    # optional context
    anchor: Optional[Anchor] = None
    identity: Optional[List[Any]] = None
    provenance: Optional[str] = None
    repro_recipe: Optional[Dict[str, Any]] = None
    notes: Optional[Freeform] = None

    @field_validator("phase")
    @classmethod
    def _phase_known(cls, v: str) -> str:
        if v not in PHASES:
            raise ValueError(f"phase must be one of {PHASES}, got {v!r}")
        return v

    @model_validator(mode="after")
    def _bedrock(self) -> "ManifestBody":
        # semantic bedrock: target is the only mandatory claim (due is optional).
        if self.target in (None, "", {}, []):
            raise ValueError("manifest body missing mandatory 'target'")
        # conditional: a content claim is meaningless without its algorithm.
        if self.subject and not self.hash_alg:
            raise ValueError("manifest body has a 'subject' but no 'hash_alg'")
        # a postreg without a link cannot be checked against any commitment.
        if self.phase == "postreg" and not self.fulfills:
            raise ValueError("postreg manifest missing mandatory 'fulfills'")
        return self

    def to_body(self) -> Dict[str, Any]:
        """Return the plain dict that gets canonicalized and signed."""
        return self.model_dump(mode="json", exclude_none=True)


class Signature(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alg: str = "ed25519"
    keyid: str
    pubkey: str
    sig: str


class Manifest(BaseModel):
    """The envelope. ``extra="allow"`` so a ceiling witness can be attached at
    the envelope level after signing without tripping validation."""

    model_config = ConfigDict(extra="allow")

    payloadType: str = "application/vnd.asexec+json"
    payload: Dict[str, Any]
    signature: Signature
