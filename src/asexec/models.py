"""Pydantic models for asexec manifest bodies and envelopes, in two families.

**Writer models** (``ManifestBody``, ``Floor``, ``Ceiling``, ...) gate what this tool
writes: ``strict`` (no coercion) and ``extra="forbid"`` (a stray field is a caller bug).
They do not participate in the cryptography: signing is always over the canonical bytes
of a plain ``dict`` (see ``canonical.py``). A model is built, validated, then dumped to a
dict via :meth:`ManifestBody.to_body` (``mode="json"``, ``exclude_none=True``) before it
is signed/referenced/serialized.

**Input models** (``*Input``) parse what the verifier reads, one slice at a time. They
are ``strict`` and ``extra="allow"``, so an unknown or future field in a published
manifest can never break offline verification. Each field encodes one *structural*
requirement of ``docs/VERIFICATION.md`` (noted beside it); every other requirement, and
every verdict, stays in ``verifier.py`` and the modules it calls. A ``null`` value is read
as absent, the same as a missing key (VERIFICATION.md, Run rules).

Where both families describe one slice, the writer model subclasses the input model and
only forbids extra fields, so a shape is written once.

Schema note (v3 term/type refactor): ``phase`` is ``prereg`` | ``postreg``;
the commitment is expressed as a free-form ``target`` (what) plus an optional
``due`` deadline (by when) and an optional ``declaration`` (plain-language or
structured description). Semantic bedrock is ``target`` alone. ``due`` is
optional (a commitment with no deadline simply stays ``open`` forever).
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    Strict,
    TypeAdapter,
    ValidationInfo,
    field_validator,
    model_validator,
)

from . import PREDICATE_TYPE, SCHEMA_VERSION, drand
from .types import Hex, Link, PinnedChain, StrictInt

# A field the caller may express either as a plain string or as structured JSON.
# "take what is provided and compile it" - more disclosure buys more trust, but
# nothing beyond ``target`` is required.
Freeform = str | dict[str, Any]

PHASES = ("prereg", "postreg")


# --------------------------------------------------------------------------- #
# input models (what the verifier reads)
# --------------------------------------------------------------------------- #
class InputModel(BaseModel):
    """Base of the input models: strict, open to unknown fields, ``null`` read as absent."""

    model_config = ConfigDict(strict=True, extra="allow")

    @model_validator(mode="before")
    @classmethod
    def _null_is_absent(cls, data: Any) -> Any:
        if isinstance(data, dict):
            return {k: v for k, v in data.items() if v is not None}
        return data


class SignatureInput(InputModel):
    """``signature`` (VERIFICATION.md ### BDR)."""

    pubkey: Hex  # BDR #2
    sig: Hex  # BDR #2
    keyid: Any = None  # BDR #3 compares it to the derived keyid; any other value fails there


class EnvelopeInput(InputModel):
    """The file's top level (BDR #1). ``payload`` stays a dict: its slices are parsed on
    demand, so a junk floor fails only ``floor``."""

    payload: dict[str, Any]
    signature: SignatureInput


class FloorInput(InputModel):
    """``payload.anchor.floor`` (VERIFICATION.md ### floor)."""

    floor_type: Literal["drand"]  # floor #1
    chain_hash: PinnedChain = drand.DEFAULT_CHAIN  # floor #2
    round: StrictInt  # floor #3
    signature: Hex  # floor #3
    randomness: Hex | None = None  # floor #4 (shape; the equality is code)


class CeilingInput(InputModel):
    """``ceiling`` (VERIFICATION.md ### ceiling)."""

    ceiling_type: Literal["roughtime"]  # ceiling #1
    nonce: str  # ceiling #2 (shape; the binding to ref(payload) is code)
    witness_id: str  # ceiling #3 (shape; the pin lookup is code)
    pubkey: Hex | None = None  # ceiling #4 (shape; the equality is code)
    response: Hex  # ceiling #5 (shape; the response check is code)


class SubjectEntryInput(InputModel):
    """One ``payload.subject[]`` entry (content #1). Validated with
    ``context={"hash_alg": ...}``: ``digest[hash_alg]`` must be a string."""

    name: str  # content #1
    digest: dict[str, Any]  # content #1

    @model_validator(mode="after")
    def _digest_for_alg(self, info: ValidationInfo) -> SubjectEntryInput:
        if info.context is None or "hash_alg" not in info.context:
            return self  # the writer validates its digests by type instead
        alg = info.context["hash_alg"]
        if not isinstance(alg, str) or not isinstance(self.digest.get(alg), str):
            raise ValueError("digest[hash_alg] is not a string")
        return self


# ``payload.subject`` (content #1): a non-empty array; each entry is a ``SubjectEntryInput``.
SubjectInput = TypeAdapter(Annotated[list[Any], Strict(), Field(min_length=1)])


class LinkInput(InputModel):
    """``payload.phase`` / ``fulfills`` / ``prev_hash``: a link is a string or absent
    (chain #2). Never fails: a non-string link is ``types.DANGLING``."""

    phase: Link = None
    fulfills: Link = None
    prev_hash: Link = None


class DueInput(InputModel):
    """``payload.due``: a string or absent (Commitment states, ``invalid-due``). The
    ISO-8601 parse stays in the verifier."""

    due: str | None = None


# --------------------------------------------------------------------------- #
# writer models (what this tool writes)
# --------------------------------------------------------------------------- #
class SubjectItem(SubjectEntryInput):
    """One hashed artifact: ``{"name": ..., "digest": {alg: hexhash}}``."""

    model_config = ConfigDict(extra="forbid")

    digest: dict[str, str]


class Floor(FloorInput):
    """A drand freshness floor (``anchor.floor``), as ``drand.floor_record`` writes it."""

    model_config = ConfigDict(extra="forbid")


class Ceiling(CeilingInput):
    """A Roughtime ceiling witness (envelope ``ceiling``), as ``roughtime.fetch_ceiling``
    writes it."""

    model_config = ConfigDict(extra="forbid")

    pubkey: Hex
    midpoint: float
    radius: float


class Anchor(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    floor: Floor | None = None


class ManifestBody(BaseModel):
    """The signed body of a manifest (the ``payload``).

    ``extra="forbid"`` because construction is fully typed here - a stray field
    is a bug in the caller, not something to sign silently.
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    # structural bedrock - the format frame
    schema_version: str = SCHEMA_VERSION
    predicateType: str = PREDICATE_TYPE
    phase: str

    # semantic bedrock - WHAT was committed to (the only mandatory claim)
    target: Freeform

    # the commitment's optional shape
    due: str | None = None
    declaration: Freeform | None = None

    # optional content claim (subject requires its algorithm)
    subject: list[SubjectItem] | None = None
    hash_alg: str | None = None

    # postreg linkage
    fulfills: str | None = None
    prev_hash: str | None = None

    # optional context
    anchor: Anchor | None = None
    identity: list[Any] | None = None
    provenance: str | None = None
    repro_recipe: dict[str, Any] | None = None
    notes: Freeform | None = None

    @field_validator("phase")
    @classmethod
    def _phase_known(cls, v: str) -> str:
        if v not in PHASES:
            raise ValueError(f"phase must be one of {PHASES}, got {v!r}")
        return v

    @model_validator(mode="after")
    def _bedrock(self) -> ManifestBody:
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

    def to_body(self) -> dict[str, Any]:
        """Return the plain dict that gets canonicalized and signed."""
        return self.model_dump(mode="json", exclude_none=True)


class Signature(SignatureInput):
    model_config = ConfigDict(extra="forbid")

    alg: str = "ed25519"
    keyid: str


class Manifest(EnvelopeInput):
    """The envelope. ``extra="allow"`` so a ceiling witness can be attached at
    the envelope level after signing without tripping validation."""

    payloadType: str = "application/vnd.asexec+json"
    signature: Signature
