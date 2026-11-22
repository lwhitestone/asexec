"""Pydantic models for asexec manifest bodies and the files around them, in two families.

The layout of a file is in ``manifest.py``.

**Writer models** (``ManifestBody``, ``Floor``, ``Ceiling``, ``Manifest``, ...) gate what
this tool writes: ``strict`` (no coercion) and ``extra="forbid"`` (a stray field is a caller
bug). They do not participate in the cryptography: signing serializes a plain ``dict`` to
the body bytes once (see ``canonical.py``), and signs those bytes. A body model is built,
validated, then dumped to a dict via :meth:`ManifestBody.dump_body` (``mode="json"``,
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
structured description). Signing requires ``predicateType``, ``phase`` and ``target``,
and ``fulfills`` in a postreg (the signing gate, in ``manifest.py``). ``due`` is optional
(a commitment with no deadline never elapses: ``no-due`` until a postreg counts).
"""

from __future__ import annotations

import types
from collections import Counter
from typing import Annotated, Any, ClassVar, Literal, Union, get_args, get_origin

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    Strict,
    TypeAdapter,
    field_validator,
    model_validator,
)

from . import __version__
from .constants import MANIFEST_PAYLOAD_TYPE, MANIFEST_PREDICATE_TYPE
from .fields import (
    Base64,
    Hex,
    Link,
    LowerHex,
    NormalName,
    PinnedChain,
    SignatureBase64,
    StrictInt,
)

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
    chain_hash: PinnedChain  # floor #2: required; verify never picks a chain for a manifest
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
    """One ``body.subject[]`` entry (content #1): a string ``name``, the entry's own string
    ``hash_alg``, and ``digest[hash_alg]`` hex. There is no default ``hash_alg``. That the
    name is in normal form (#3) and unique (#4) is code."""

    name: str  # content #1
    hash_alg: str  # content #1 (that it is available, #2, is code)
    digest: dict[str, Any]  # content #1

    @model_validator(mode="after")
    def _check_digest_for_alg(self) -> SubjectEntryInput:
        if not isinstance(self.digest.get(self.hash_alg), str):
            raise ValueError("digest[hash_alg] is not a string")
        bytes.fromhex(self.digest[self.hash_alg])  # a ValueError here: not hex
        return self


# ``body.subject`` and ``body.evidence`` (content #1): a non-empty array; each entry is a
# ``SubjectEntryInput``. ``body.plan`` is one such entry.
SubjectInput = TypeAdapter(Annotated[list[Any], Strict(), Field(min_length=1)])


class ItemInput(InputModel):
    """One ``body.items[]`` entry of a prereg: a string ``id`` (complete #1). Its ``kind`` is
    declared and never tested, so it is not a field."""

    id: str


# ``body.items`` (complete #1): an array; each entry is an ``ItemInput``.
ItemsInput = TypeAdapter(Annotated[list[Any], Strict()])


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
    """One hashed file: ``{"name": <normalized relative path>, "hash_alg": alg,
    "digest": {alg: hexhash}}``."""

    model_config = ConfigDict(extra="forbid")
    null_is_absent = False

    name: NormalName
    digest: dict[str, str]


class Plan(SubjectEntryInput):
    """``body.plan``: the plan document, by digest, as a subject entry is, with its declared
    (never tested) ``media_type`` and ``label``. asexec never parses the plan."""

    model_config = ConfigDict(extra="forbid")
    null_is_absent = False

    name: NormalName
    digest: dict[str, str]
    media_type: str | None = None
    label: str | None = None


class EvidenceItem(SubjectEntryInput):
    """One ``body.evidence[]`` entry: a file that backs a postreg, by digest, as a subject
    entry is, with its declared (never tested) ``media_type`` and ``uri``."""

    model_config = ConfigDict(extra="forbid")
    null_is_absent = False

    name: NormalName
    digest: dict[str, str]
    media_type: str | None = None
    uri: str | None = None


class Item(ItemInput):
    """One committed item: an ``id`` a postreg's ``item_id`` names, and a declared ``kind``
    (a run, an ablation, a search)."""

    model_config = ConfigDict(extra="forbid")
    null_is_absent = False

    kind: str | None = None


# What happened to an item (ROADMAP, New properties): the values a postreg's status may take.
STATUSES = ("reported", "excluded", "blocked")
Status = Literal["reported", "excluded", "blocked"]


class Floor(FloorInput):
    """A drand freshness floor (``anchor.floor``), as ``drand.build_floor_record`` writes it."""

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

    # required to sign: phase drives matching; predicateType names the body for in-toto
    predicateType: str = MANIFEST_PREDICATE_TYPE
    phase: str

    # required to sign: WHAT was committed to
    target: Freeform

    # the commitment's optional shape
    due: str | None = None
    declaration: Freeform | None = None

    # optional content claim: files, each with its own algorithm
    subject: Annotated[list[SubjectItem], Field(min_length=1)] | None = None

    # postreg linkage
    fulfills: str | None = None
    prev_hash: str | None = None

    # the claim record: a prereg's plan and items, a postreg's item_id, status and evidence
    plan: Plan | None = None
    items: list[Item] | None = None
    item_id: str | None = None
    status: Status | None = None
    evidence: Annotated[list[EvidenceItem], Field(min_length=1)] | None = None

    # optional context
    anchor: Anchor | None = None
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
    def _check_required_and_unique(self) -> ManifestBody:
        # the signing gate's target (due is optional).
        if self.target in (None, "", {}, []):
            raise ValueError("manifest body missing mandatory 'target'")
        # content #4: one file, one entry, in each list.
        for field, entries in (("subject", self.subject), ("evidence", self.evidence)):
            counts = Counter(entry.name for entry in entries or [])
            repeated = sorted(name for name, n in counts.items() if n > 1)
            if repeated:
                raise ValueError(f"{field} lists {', '.join(map(repr, repeated))} twice")
        # one id, one item: a prereg whose item ids repeat fails complete.
        counts = Counter(item.id for item in self.items or [])
        repeated = sorted(i for i, n in counts.items() if n > 1)
        if repeated:
            raise ValueError(f"items list the id {', '.join(map(repr, repeated))} twice")
        # a postreg without a link cannot be checked against any commitment.
        if self.phase == "postreg" and not self.fulfills:
            raise ValueError("postreg manifest missing mandatory 'fulfills'")
        return self

    def dump_body(self) -> dict[str, Any]:
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


class Untrusted(BaseModel):
    """The file's ``untrusted``: metadata nothing checks, in the wrapper, so neither signed nor
    part of ``ref``. Signing writes the release that wrote the file, for diagnostics only. No
    input model reads it: no test does (VERIFICATION.md, Untrusted)."""

    model_config = ConfigDict(strict=True, extra="forbid")

    asexec_version: str = __version__


class Manifest(EnvelopeInput):
    """The file: the envelope, the key that signed it, and the untrusted section.
    ``extra="allow"`` so a ceiling witness can be attached beside them after signing without
    tripping validation."""

    null_is_absent = False

    dsse: Dsse
    pubkey: LowerHex
    untrusted: Untrusted = Field(default_factory=Untrusted)


# --------------------------------------------------------------------------- #
# the fields this format defines (VERIFICATION.md, Untrusted)
# --------------------------------------------------------------------------- #
# A field's shape, as the report reads it to list what this format does not define: ``None``
# for a value (free-form, like ``target`` or a ``digest``, or a scalar), or ``("object",
# fields)`` / ``("array", fields)`` for an object, or an array of objects, whose fields the
# format defines.
Fields = dict[str, Any]


def _derive_shape(annotation: Any) -> tuple[str, Fields] | None:
    origin = get_origin(annotation)
    if origin is Annotated:
        return _derive_shape(get_args(annotation)[0])
    if origin in (Union, types.UnionType):
        return next(filter(None, map(_derive_shape, get_args(annotation))), None)
    if origin is list:
        inner = _derive_shape(get_args(annotation)[0])
        return ("array", inner[1]) if inner and inner[0] == "object" else None
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return ("object", derive_known_fields(annotation))
    return None


def derive_known_fields(model: type[BaseModel]) -> Fields:
    """The fields a writer model can write, each with its shape (see ``Fields``)."""
    return {name: _derive_shape(info.annotation) for name, info in model.model_fields.items()}


# What a body may hold that this format defines: every field the writer can write. Anything
# else, at the top of the body or in an object the format defines, is an unknown field. These
# two sets say what the format defines, so the report can show what it does not.
BODY_FIELDS: Fields = derive_known_fields(ManifestBody)
# The same outside the body, in the file around it: the envelope, the key, the ceiling a
# witness attaches, and ``untrusted``, which is shown whole (nothing in it is the format's).
WRAPPER_FIELDS: Fields = {
    **derive_known_fields(Manifest),
    "untrusted": None,
    "ceiling": ("object", derive_known_fields(Ceiling)),
}
