"""Pydantic models for asexec manifest bodies and the files around them, in two families.

A file is a wrapper around a DSSE envelope: ``{"dsse": {"payloadType", "payload",
"signatures": [{"keyid", "sig"}]}, "pubkey", "ceiling"}``, where ``dsse.payload`` is the
base64 of the body bytes, and the body is the JSON object they hold.

**Writer models** (``ManifestBody``, ``Floor``, ``Ceiling``, ``Manifest``, ...) gate what
this tool writes: ``strict`` (no coercion) and ``extra="forbid"`` (a stray field is a caller
bug). They do not participate in the cryptography: signing serializes a plain ``dict`` to
the body bytes once (see ``canonical.py``), and signs those bytes. A body model is built,
validated, then dumped to a dict via :meth:`ManifestBody.to_body` (``mode="json"``,
``exclude_none=True``) before it is serialized and signed.

**Input models** (``*Input``) parse what the verifier reads, one slice at a time. They
are ``strict`` and ``extra="allow"``, so an unknown or future field in a published
manifest can never break offline verification. Each field encodes one *structural*
requirement of ``docs/VERIFICATION.md`` (noted beside it); every other requirement, and
every verdict, stays in ``verifier.py`` and the modules it calls. A ``null`` value is read
as absent, the same as a missing key (VERIFICATION.md, Run rules).

Where both families describe one slice, the writer model subclasses the input model,
forbids extra fields and rejects ``None`` (``null_is_absent = False``), so a shape is
written once.

Schema note (v3 term/type refactor): ``phase`` is ``prereg`` | ``postreg``;
the commitment is expressed as a free-form ``target`` (what) plus an optional
``due`` deadline (by when) and an optional ``declaration`` (plain-language or
structured description). Semantic bedrock is ``target`` alone. ``due`` is
optional (a commitment with no deadline simply stays ``open`` forever).
"""

from __future__ import annotations

from typing import Annotated, Any, ClassVar, Literal

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

from . import drand
from .constants import MANIFEST_PAYLOAD_TYPE, MANIFEST_PREDICATE_TYPE
from .fields import Base64, Hex, Link, LowerHex, PinnedChain, SignatureBase64, StrictInt

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

    # The writer subclasses turn this off: for them an explicit None is a caller bug,
    # never a default.
    null_is_absent: ClassVar[bool] = True

    @model_validator(mode="before")
    @classmethod
    def _null_is_absent(cls, data: Any) -> Any:
        if cls.null_is_absent and isinstance(data, dict):
            return {k: v for k, v in data.items() if v is not None}
        return data


class DsseInput(InputModel):
    """``dsse``, the DSSE envelope (VERIFICATION.md ### format). ``signatures`` stays a list
    of anything: how many entries it has, and what they hold, is ``selfsig``'s to judge."""

    payloadType: str  # format #1 (shape; #3, that it names a FORMATS entry, is code)
    payload: Base64  # format #2 (strict base64; that the bytes are a JSON object is code)
    signatures: list[Any]  # format #1


class EnvelopeInput(InputModel):
    """The file's top level (format #1). The body is not a field: it is ``dsse.payload``'s
    bytes, decoded and parsed by the verifier, and its slices are parsed on demand, so a
    junk floor fails only ``floor``."""

    dsse: DsseInput


class SignatureInput(InputModel):
    """``dsse.signatures[0]``, the one signature (VERIFICATION.md ### selfsig). Read only
    when ``dsse.signatures`` holds exactly one entry, an object (selfsig #1)."""

    keyid: Any = None  # selfsig #4 compares it to the derived keyid; any other value fails there
    sig: SignatureBase64  # selfsig #2 (strict base64 of 64 bytes, as DSSE has it)


class KeyInput(InputModel):
    """The file's ``pubkey``, in the wrapper outside ``dsse``, as hex (VERIFICATION.md
    ### selfsig)."""

    pubkey: Hex  # selfsig #2


class FloorInput(InputModel):
    """``body.anchor.floor`` (VERIFICATION.md ### floor)."""

    floor_type: Literal["drand"]  # floor #1
    chain_hash: PinnedChain = drand.DEFAULT_CHAIN  # floor #2
    round: StrictInt  # floor #3
    signature: Hex  # floor #3
    randomness: Hex | None = None  # floor #4 (shape; the equality is code)


class CeilingInput(InputModel):
    """``ceiling`` (VERIFICATION.md ### ceiling)."""

    ceiling_type: Literal["roughtime"]  # ceiling #1
    nonce: str  # ceiling #2 (shape; the binding to ref is code)
    witness_id: str  # ceiling #3 (shape; the pin lookup is code)
    pubkey: Hex | None = None  # ceiling #4 (shape; the equality is code)
    response: Hex  # ceiling #5 (shape; the response check is code)


class SubjectEntryInput(InputModel):
    """One ``body.subject[]`` entry (content #1). Must be validated with
    ``context={"hash_alg": ...}``: ``digest[hash_alg]`` must be hex."""

    name: str  # content #1
    digest: dict[str, Any]  # content #1

    # The writer subclass turns this off: it types every digest as a string, and
    # ManifestBody pairs the subject with its hash_alg.
    digest_needs_hash_alg: ClassVar[bool] = True

    @model_validator(mode="after")
    def _digest_for_alg(self, info: ValidationInfo) -> SubjectEntryInput:
        if not self.digest_needs_hash_alg:
            return self
        if info.context is None or "hash_alg" not in info.context:
            # A caller bug, not a malformed entry: TypeError is not turned into a
            # ValidationError, so it can never pass silently as a FAIL or a PASS.
            raise TypeError('SubjectEntryInput needs context={"hash_alg": ...}')
        alg = info.context["hash_alg"]
        if not isinstance(alg, str) or not isinstance(self.digest.get(alg), str):
            raise ValueError("digest[hash_alg] is not a string")
        bytes.fromhex(self.digest[alg])  # a ValueError here: digest[hash_alg] is not hex
        return self


# ``body.subject`` (content #1): a non-empty array; each entry is a ``SubjectEntryInput``.
SubjectInput = TypeAdapter(Annotated[list[Any], Strict(), Field(min_length=1)])


class LinkInput(InputModel):
    """``body.phase`` / ``fulfills`` / ``prev_hash``: a link is a string or absent
    (chain #2). Never fails: a non-string link is ``fields.DANGLING``."""

    phase: Link = None
    fulfills: Link = None
    prev_hash: Link = None


class DueInput(InputModel):
    """``body.due``: a string or absent (Commitment states, ``invalid-due``). The
    ISO-8601 parse stays in the verifier."""

    due: str | None = None


# --------------------------------------------------------------------------- #
# writer models (what this tool writes)
# --------------------------------------------------------------------------- #
class SubjectItem(SubjectEntryInput):
    """One hashed artifact: ``{"name": ..., "digest": {alg: hexhash}}``."""

    model_config = ConfigDict(extra="forbid")
    null_is_absent = False
    digest_needs_hash_alg = False

    digest: dict[str, str]


class Floor(FloorInput):
    """A drand freshness floor (``anchor.floor``), as ``drand.floor_record`` writes it."""

    model_config = ConfigDict(extra="forbid")
    null_is_absent = False

    signature: LowerHex
    randomness: LowerHex | None = None


class Ceiling(CeilingInput):
    """A Roughtime ceiling witness (the file's ``ceiling``), as ``roughtime.fetch_ceiling``
    writes it."""

    model_config = ConfigDict(extra="forbid")
    null_is_absent = False

    nonce: LowerHex
    pubkey: LowerHex
    response: LowerHex
    midpoint: float
    radius: float


class Anchor(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    floor: Floor | None = None


class ManifestBody(BaseModel):
    """The signed body of a manifest (what ``dsse.payload`` holds).

    ``extra="forbid"`` because construction is fully typed here - a stray field
    is a bug in the caller, not something to sign silently.
    """

    model_config = ConfigDict(strict=True, extra="forbid")

    # structural bedrock - the body frame
    predicateType: str = MANIFEST_PREDICATE_TYPE
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
        """Return the plain dict that gets serialized to the body bytes and signed."""
        return self.model_dump(mode="json", exclude_none=True)


class Signature(SignatureInput):
    """One ``dsse.signatures[]`` entry, as DSSE has it: a ``keyid`` and a ``sig`` (the
    signature's base64). It names no algorithm: that is the format's (``signing_key_alg``)."""

    model_config = ConfigDict(extra="forbid")
    null_is_absent = False

    keyid: str


class Dsse(DsseInput):
    """The DSSE envelope signing writes: the format's type, the body bytes' base64, and
    exactly one signature."""

    model_config = ConfigDict(extra="forbid")
    null_is_absent = False

    payloadType: str = MANIFEST_PAYLOAD_TYPE
    signatures: Annotated[list[Signature], Field(min_length=1, max_length=1)]


class Manifest(EnvelopeInput):
    """The file: the envelope and the key that signed it. ``extra="allow"`` so a ceiling
    witness can be attached beside them after signing without tripping validation."""

    null_is_absent = False

    dsse: Dsse
    pubkey: LowerHex
