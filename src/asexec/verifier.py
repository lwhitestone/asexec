"""The verifier. A canonical verify code. Trust comes from reproducibility.

Everything the verifier does verifies offline against pinned constants; nothing
here touches the network.

Output: a canonical plaintext code
-------------------------------------------------------------
``verify`` runs a caller-chosen set of tests and emits one code per run::

    asexec-verify/1 floor=PASS format=PASS selfsig=PASS

Grammar (spec'd here so any implementation reproduces it byte-for-byte):

  - Literal prefix ``asexec-verify/1`` (this versions the code GRAMMAR itself,
    independent of the signed-byte format), then a single ASCII space.
  - One ``name=RESULT`` token per requested test, ``RESULT`` in ``{PASS, FAIL}``.
  - Tokens are sorted alphabetically by name and single-space delimited.

The same result set is byte-identical everywhere. Because the code *names* which
tests ran, adding a test in a later version can never change the meaning of an
older code: a code means exactly one thing, permanently.

The verify code is a summary of a computation, not a credential. Real verification
= run this tool against the manifests (+artifacts) and get this code.

Tests (the catalog - only verifiable claims, no self-declarations)
--------------------------------------------------------------------
  - ``ceiling``    : a ceiling witness (Roughtime) signature verifies against a
                     pinned key AND its nonce == ref (of the body bytes). Applies
                     to manifests that carry a ceiling.
  - ``chain``      : prev_hash chain integrity (one root, no gaps, no forks: a
                     single linear chain). Applies to
                     commitments that have counted postregs.
  - ``content``    : subject digests recomputed from --artifacts match. Subject
                     names must resolve inside --artifacts (an escape is a
                     mismatch). Applies where artifacts are provided and a
                     subject is present.
  - ``floor``      : the drand freshness floor BLS-verifies. Applies to
                     manifests that carry an anchor.floor.
  - ``format``     : the file can be read: a JSON object (unique keys, nested at
                     most 64 deep) with an object dsse holding a string
                     payloadType and an array of signatures, and a payload that
                     is strict base64 of a JSON object held to the same rules on
                     its own; and its dsse.payloadType names a format this
                     release reads (a ``FORMATS`` key). Applies to every manifest
                     file. **Required in every run.**
  - ``keyconsist`` : each validly signed postreg that names a commitment's ref
                     has the key of a commitment with that ref. Applies to the
                     commitments ``verify_paths`` marks ``key_checked``.
  - ``selfsig``    : the file is unchanged since its own key signed it: exactly
                     one signature, its sig base64 of 64 bytes and the file's
                     pubkey hex, the
                     signature over the PAE of the body bytes verifies by pubkey,
                     and its keyid derives from pubkey. Applies to every manifest
                     that passes ``format``. **Required in every run.**

Only a file that passes ``format`` is examined by any other test, and every test reads it
under the rules of the format its dsse.payloadType names (``FORMATS``), never another's. The
body bytes are read exactly as stored: nothing is re-serialized, so ``ref`` and the
signature are of the bytes the file holds.

A requested test is ``PASS`` iff it holds everywhere it applies AND it applies
somewhere; a requested test that applies **nowhere** is ``FAIL``
(requested-but-absent), never a silent omission or a pass with nothing examined.

States (per commitment = a validly signed prereg + the postregs that fulfil it)
------------------------------------------------------------------------------
A commitment is a prereg that passes ``format`` and meets the ``selfsig`` conditions. One
that passes ``format`` but fails them is a rejected pre-registration: no commitment, no
state, and its keyid (which nothing authenticated) is matched against no postreg. A postreg
naming it is rejected under it.

Rendered in the human report above the code; the verifier RENDERS these, it
never adjudicates intent or whether a commitment was "good enough":
  - fulfilled          : >=1 postreg references this prereg AND is validly
                         signed by the prereg's own key. Postregs that reference
                         it but fail either condition are listed separately
                         (``rejected_postregs``) and never count; those
                         that count are ``counted_postregs``.
  - open               : 0 counted postregs and the ``due`` deadline has not
                         elapsed (or no ``due`` was declared - an open-ended
                         commitment)
  - elapsed-no-postreg : 0 counted postregs and the ``due`` deadline has elapsed
  - invalid-due        : 0 counted postregs and ``due`` is present but is not a
                         parseable ISO-8601 timestamp (never silently rendered
                         ``open``)

A postreg whose ``fulfills`` matches no provided prereg is notarization-only: it
belongs to no commitment, so it has no state, and is reported in its own list.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import time
from typing import Any

from pydantic import ValidationError

from . import drand, hashing, keys, manifest
from .canonical import b64decode, signing_input
from .constants import FORMATS, VERIFY_CODE_VERSION
from .errors import ManifestError, VerificationError
from .models import (
    CeilingInput,
    DueInput,
    EnvelopeInput,
    FloorInput,
    KeyInput,
    LinkInput,
    SignatureInput,
    SubjectEntryInput,
    SubjectInput,
)

# The test catalog, alphabetical (the order names appear in a code).
TEST_CATALOG: tuple[str, ...] = (
    "ceiling",
    "chain",
    "content",
    "floor",
    "format",
    "keyconsist",
    "selfsig",
)

# The mandatory minimum: a run that does not check both is not a meaningful asexec
# verification, so `verify` requires each explicitly. `format` says whether a file can be
# read at all, and `selfsig` whether a readable one is unchanged since its key signed it.
REQUIRED_TESTS: frozenset[str] = frozenset({"format", "selfsig"})


def _quoted(names) -> str:
    return ", ".join(f"'{name}'" for name in sorted(names))


def parse_tests(spec: str) -> list[str]:
    """Parse a ``--tests`` string into a validated, de-duplicated list.

    Raises ``VerificationError`` on an unknown test or if a required test is absent
    (no implicit default; the caller must declare its appetite explicitly).
    """
    required = " and ".join(_quoted([name]) for name in sorted(REQUIRED_TESTS))
    names = [t.strip() for t in spec.split(",") if t.strip()]
    if not names:
        raise VerificationError(f"no tests requested; --tests must list at least {required}")
    unknown = [t for t in names if t not in TEST_CATALOG]
    if unknown:
        raise VerificationError(
            f"unknown test(s): {', '.join(unknown)}; available: {', '.join(TEST_CATALOG)}"
        )
    missing = REQUIRED_TESTS - set(names)
    if missing:
        raise VerificationError(
            f"missing required test(s) {_quoted(missing)}; every run must include {required}"
        )
    # preserve catalog order, de-dup.
    return [t for t in TEST_CATALOG if t in names]


def _parse_due(raw: Any) -> tuple[bool, float | None, bool]:
    """Parse a ``due`` value to ``(present, epoch_seconds, naive)``.

    A timezone-less value is read as UTC so the result never depends on the
    verifier's local timezone; ``naive`` flags it. ``epoch_seconds`` is None if
    ``due`` is absent (missing or null) or not a parseable ISO-8601 string.
    """
    try:
        due = DueInput.model_validate({"due": raw}).due
    except ValidationError:
        return True, None, False
    if due is None:
        return False, None, False
    try:
        dt = datetime.datetime.fromisoformat(due.replace("Z", "+00:00"))
    except ValueError:
        return True, None, False
    naive = dt.tzinfo is None
    if naive:
        dt = dt.replace(tzinfo=datetime.UTC)
    return True, dt.timestamp(), naive


def _lookup(obj: Any, *path: str) -> tuple[bool, Any]:
    """``(present, value)`` of the property at ``path`` under ``obj`` (Run rules).

    A property is absent iff its key is missing or its value is null. Any other
    value is present, and so examined. A non-object on the way makes the property
    present, as that non-object, so it fails its input model.
    """
    for key in path:
        if not isinstance(obj, dict):
            return True, obj
        obj = obj.get(key)
        if obj is None:
            return False, None
    return True, obj


# Why a file's string payloadType names no format this release reads (format #3), as the
# report shows it (docs/VERIFICATION.md). Such a file is never read under another entry.
REASON_FORMAT_NEWER = (
    "payloadType names a format newer than this release: upgrade asexec to read it"
)
REASON_FORMAT_BETA = "payloadType names an asexec beta format, and betas are not supported"
REASON_FORMAT_PRE_V1 = (
    "payloadType names the format of asexec before 0.4.0, which is not supported:"
    " re-sign with this release"
)

# Recognized only to say why they fail: what asexec 0.2.0 to 0.3.x wrote, and a beta's
# type (``X.Y.ZbN``). Any other payloadType that is not a FORMATS key reads as newer. Those
# releases wrote it at the top level, with no dsse: a file laid out that way under that
# type gets its reason too.
_PRE_V1_PAYLOAD_TYPE = "application/vnd.asexec+json"
_BETA_PAYLOAD_TYPE = re.compile(r"application/vnd\.asexec\.[0-9]+\.[0-9]+\.[0-9]+b[0-9]+\+json")


def _unknown_format_reason(payload_type: str) -> str:
    if payload_type == _PRE_V1_PAYLOAD_TYPE:
        return REASON_FORMAT_PRE_V1
    if _BETA_PAYLOAD_TYPE.fullmatch(payload_type):
        return REASON_FORMAT_BETA
    return REASON_FORMAT_NEWER


def _claimed_keyid(mani: dict[str, Any]) -> Any:
    """``dsse.signatures[0].keyid``, the keyid a file claims as its signer, or None. Nothing
    has authenticated it until the file meets the selfsig conditions."""
    signatures = mani["dsse"]["signatures"]
    first = signatures[0] if signatures else None
    return first.get("keyid") if isinstance(first, dict) else None


def verify_format(mani: dict[str, Any]) -> dict[str, Any]:
    """``format`` for a file ``manifest.load`` has read as a JSON object (which checks the
    rest of format #1: readable, unique keys, nesting): the format its dsse.payloadType
    names (#3), then that format's frame (#1) and body (#2). A file that passes also gets
    the ``payload_type``, ``ref`` and ``keyid`` it is known by, and the ``body_bytes`` and
    ``body`` the other tests read.

    #3 comes first: a file of a format this release does not read is not held to this
    format's frame, which a newer format may lay out differently. Never raises."""
    dsse = mani.get("dsse")
    payload_type = dsse.get("payloadType") if isinstance(dsse, dict) else None
    if dsse is None and mani.get("payloadType") == _PRE_V1_PAYLOAD_TYPE:  # 0.3.x's layout
        return {"ok": False, "errors": [REASON_FORMAT_PRE_V1]}
    if isinstance(payload_type, str) and payload_type not in FORMATS:  # format #3
        return {"ok": False, "errors": [_unknown_format_reason(payload_type)]}
    try:
        envelope = EnvelopeInput.model_validate(mani)  # format #1 (frame), #2 (base64)
    except ValidationError as e:
        return {"ok": False, "errors": [f"malformed: {_describe(e)}"]}
    body_bytes = b64decode(envelope.dsse.payload)  # format #2: the model checked it decodes
    try:
        body = manifest.parse_body(body_bytes)  # format #2: the body's own JSON rules
    except ManifestError as e:
        return {"ok": False, "errors": [f"malformed: body: {e}"]}
    return {
        "ok": True,
        "errors": [],
        "payload_type": payload_type,
        "ref": manifest.ref(body_bytes, payload_type),
        "keyid": _claimed_keyid(mani),
        "body_bytes": body_bytes,
        "body": body,
    }


def verify_selfsig(mani: dict[str, Any], body_bytes: bytes, payload_type: str) -> dict[str, Any]:
    """``selfsig`` for a file that passed ``format``, with the ``body_bytes`` it stores: one
    signature (#1), a hex ``pubkey`` and a ``sig`` of strict base64 of 64 bytes (#2), a
    signature over the PAE of the body bytes by ``pubkey`` (#3), and a ``keyid`` that
    derives from ``pubkey`` (#4), under the rules of the file's own format. ``signature_ok``
    is #1-#3 and ``keyid_ok`` #4. Never raises."""
    signatures = mani["dsse"]["signatures"]
    if len(signatures) != 1 or not isinstance(signatures[0], dict):  # selfsig #1
        return {**_SELFSIG_FAILED}
    try:
        entry = SignatureInput.model_validate(signatures[0])  # selfsig #2: sig
        key = KeyInput.model_validate(mani)  # selfsig #2: pubkey
    except ValidationError:
        return {**_SELFSIG_FAILED}
    pub = bytes.fromhex(key.pubkey)
    sig = b64decode(entry.sig)
    return {
        "examined": True,
        "signature_ok": keys.verify(pub, signing_input(body_bytes, payload_type), sig),  # #3
        "keyid_ok": keys.keyid_for(pub, payload_type) == entry.keyid,  # selfsig #4
    }


# A file that fails ``format``: ``selfsig`` does not examine it.
_SELFSIG_NOT_EXAMINED = {"examined": False, "signature_ok": False, "keyid_ok": False}
# A file that passes ``format`` and fails selfsig #1 or #2: nothing to check a signature with.
_SELFSIG_FAILED = {"examined": True, "signature_ok": False, "keyid_ok": False}


def _selfsig_ok(record: dict[str, Any]) -> bool:
    """Whether a manifest meets the ``selfsig`` conditions (it passed ``format`` too)."""
    return bool(record["selfsig"]["signature_ok"] and record["selfsig"]["keyid_ok"])


def _describe(error: ValidationError) -> str:
    """A one-line summary of a ``ValidationError``: each failing path and its message."""
    return "; ".join(
        f"{'.'.join(str(p) for p in e['loc']) or '(value)'}: {e['msg']}" for e in error.errors()
    )


def _invalid(error: ValidationError, type_field: str) -> dict[str, Any]:
    """The record for a slice that failed its input model. A wrong ``<x>_type`` is
    ``unsupported`` (an unknown kind of witness), anything else ``invalid``."""
    unsupported = any(e["loc"] == (type_field,) for e in error.errors())
    return {"status": "unsupported" if unsupported else "invalid", "error": _describe(error)}


def verify_floor(body: dict[str, Any]) -> dict[str, Any]:
    """Verify the drand freshness floor at ``body.anchor.floor`` (if present)."""
    present, floor = _lookup(body, "anchor", "floor")
    if not present:
        return {"status": "absent"}
    try:
        parsed = FloorInput.model_validate(floor)  # floor #1-#4 (shape)
    except ValidationError as e:
        return _invalid(e, "floor_type")
    return drand.verify_floor(parsed)  # floor #4 equality, #5 BLS; never raises


def verify_ceiling(
    mani: dict[str, Any], ref: str, servers: dict[str, dict[str, object]] | None = None
) -> dict[str, Any]:
    """Verify the ceiling witness in the file's wrapper (if present).

    Two conditions: (1) the witness signature verifies against a pinned key,
    and (2) the witness's nonce binds to THIS manifest (nonce == ``ref``, the digest of
    its body bytes). Called only for a manifest that passed ``format``. Delegates the
    binding, the pin lookup in ``servers`` (default: the pinned
    ``roughtime.SERVERS``) and the witness cryptography to the ``roughtime`` module.
    """
    present, ceiling = _lookup(mani, "ceiling")
    if not present:
        return {"status": "absent"}
    try:
        parsed = CeilingInput.model_validate(ceiling)  # ceiling #1, #3-#5 (shape)
    except ValidationError as e:
        return _invalid(e, "ceiling_type")
    from . import roughtime

    try:  # ceiling #2 binding, #3 pin lookup, #4 equality, #5 response
        return roughtime.verify_ceiling(parsed, ref, servers)
    except Exception as e:  # an unsigned, attacker-shaped wrapper field must not crash verify
        return {"status": "invalid", "error": str(e)}


# A subject name that no path on this system can have (it holds a NUL, or a lone surrogate
# the filesystem encoding can't encode): it names no artifact (content #4).
_NO_SUCH_PATH = object()


def _resolve_inside(artifacts_dir: str, name: str) -> Any:
    """Resolve a subject ``name`` under ``artifacts_dir``; None if it escapes
    (``..``, an absolute name, or a symlink pointing outside), ``_NO_SUCH_PATH`` if no path
    can have it."""
    root = os.path.realpath(artifacts_dir)
    try:
        path = os.path.realpath(os.path.join(root, name.rstrip("/")))
    except ValueError:  # embedded NUL, or UnicodeEncodeError
        return _NO_SUCH_PATH
    if path != root and not path.startswith(root + os.sep):
        return None
    return path


def _verify_subject_item(item: Any, alg: Any, artifacts_dir: str) -> dict[str, Any]:
    label = str(item.get("name") if isinstance(item, dict) else item)[:80]
    if not isinstance(alg, str):  # content #2: no install has a non-string algorithm
        return {"name": label, "ok": False, "reason": f"algorithm unavailable: {alg!r}"}
    try:
        entry = SubjectEntryInput.model_validate(item, context={"hash_alg": alg})  # content #1
    except ValidationError:
        return {"name": label, "ok": False, "reason": "malformed subject entry"}
    name, expected = entry.name, entry.digest[alg]
    if alg not in hashing.available_algorithms():
        return {"name": name, "ok": False, "reason": f"algorithm unavailable: {alg!r}"}
    path = _resolve_inside(artifacts_dir, name)
    if path is None:
        return {"name": name, "ok": False, "reason": "path resolves outside --artifacts"}
    if path is _NO_SUCH_PATH or not os.path.exists(path):
        return {"name": name, "ok": False, "reason": "artifact not found"}
    try:
        actual = hashing.digest_path(path, alg)
    except OSError as e:
        return {"name": name, "ok": False, "reason": f"artifact unreadable: {e.strerror or e}"}
    ok = bytes.fromhex(actual) == bytes.fromhex(expected)  # content #6: any hex spelling
    return {"name": name, "ok": ok, **({} if ok else {"expected": expected, "actual": actual})}


def verify_content(
    body: dict[str, Any], artifacts_dir: str | None, payload_type: str
) -> dict[str, Any]:
    """``content`` for a manifest that passed ``format``, of format ``payload_type``: a
    subject with no ``hash_alg`` is read with that format's default."""
    if not artifacts_dir:
        return {"status": "skipped", "reason": "no artifacts provided"}
    present, subject = _lookup(body, "subject")
    if not present:
        return {"status": "skipped", "reason": "manifest has no subject"}
    try:
        SubjectInput.validate_python(subject)  # content #1 (an array of entries)
    except ValidationError:
        return {
            "status": "mismatch",
            "entries": [{"name": "(subject)", "ok": False, "reason": "malformed subject"}],
        }
    present, alg = _lookup(body, "hash_alg")
    alg = alg if present else FORMATS[payload_type]["subject_default_hash_alg"]
    entries = [_verify_subject_item(item, alg, artifacts_dir) for item in subject]
    return {"status": "ok" if all(e["ok"] for e in entries) else "mismatch", "entries": entries}


def verify_paths(
    paths: list[str],
    tests: list[str],
    artifacts_dir: str | None = None,
    now: float | None = None,
    servers: dict[str, dict[str, object]] | None = None,
) -> dict[str, Any]:
    """Load, verify, group, evaluate the requested tests, and build the code.

    ``servers`` is the pinned Roughtime witness map for ``ceiling`` (default:
    ``roughtime.SERVERS``). ``now`` (default: the current time) is the moment commitment
    states are judged at, and is reported as ``checked_at``.
    """
    now = time.time() if now is None else now
    files = _expand(paths)

    # (ref, keyid) -> record. A commitment is a prereg's ref and its signer: the body holds
    # no key, so the same body signed by two keys is two commitments, never one whose key
    # depends on which file was read last. Only a prereg that meets the selfsig conditions is
    # one, so every keyid here is authenticated (and a string). One that passes format but
    # fails them is a rejected pre-registration: listed, with no state, never matched by key.
    preregs: dict[tuple[str, str], Any] = {}
    rejected_preregs: dict[tuple[str, str], dict[str, Any]] = {}  # by (ref, keyid as JSON)
    postregs = []
    manifests_report = []
    ceiling_trust = []

    for p, unlistable in files:
        try:
            if unlistable is not None:
                raise unlistable
            mani = manifest.load(p)
            fmt = verify_format(mani)
        except Exception as e:  # unreadable / not JSON / duplicate keys / not an object
            mani = {}
            fmt = {"ok": False, "errors": [f"malformed: {e}"]}
        # Only a file that passes format has a body: the one its body bytes hold.
        body_bytes, body = fmt.pop("body_bytes", None), fmt.pop("body", {})
        clean = fmt["ok"]
        selfsig = (
            verify_selfsig(mani, body_bytes, fmt["payload_type"])
            if clean
            else {**_SELFSIG_NOT_EXAMINED}
        )
        floor = verify_floor(body) if clean else {"status": "absent"}
        ceiling = verify_ceiling(mani, fmt["ref"], servers) if clean else {"status": "absent"}
        content = (
            verify_content(body, artifacts_dir, fmt["payload_type"])
            if clean
            else {"status": "skipped"}
        )
        if ceiling.get("status") == "verified":
            ceiling_trust.append(
                f"{p}: ceiling witnessed by {ceiling.get('witness_id')} at "
                f"{ceiling.get('midpoint')} (±{ceiling.get('radius')}s) - you are "
                f"trusting {ceiling.get('witness_id')} to be honest about time "
                f"(signature-witness trust class, distinct from the floor)."
            )
        rec = {
            "path": p,
            "phase": body.get("phase"),
            "ref": fmt.get("ref"),
            "keyid": fmt.get("keyid"),
            "format": fmt,
            "selfsig": selfsig,
            "floor": floor,
            "ceiling": ceiling,
            "content": content,
        }
        manifests_report.append(rec)
        if not clean:
            continue  # fails format: no other test examines it, so it joins no commitment
        links = LinkInput.model_validate({k: body[k] for k in LinkInput.model_fields if k in body})
        if links.phase == "prereg" and _selfsig_ok(rec):
            preregs[(rec["ref"], rec["keyid"])] = {
                "ref": rec["ref"],
                "keyid": rec["keyid"],
                "due": body.get("due"),
                "counted_postregs": [],
                "rejected_postregs": [],
                "different_key": False,  # set by the matching loop; see key_checked below
            }
        elif links.phase == "prereg":  # copies (same ref, and keyid as JSON) are listed once
            rejected_preregs.setdefault(
                (rec["ref"], _json_value(rec["keyid"])),
                {
                    "ref": rec["ref"],
                    "keyid": rec["keyid"],
                    "reason": REASON_INVALID_SIGNATURE,
                    "rejected_postregs": [],
                },
            )
        elif links.phase == "postreg":
            postregs.append((links, rec))

    # The provided preregs by ref: the commitments (``preregs`` is them by (ref, keyid)), and
    # the rejected pre-registrations, which are never looked up by their unauthenticated keyid.
    commitments_by_ref: dict[str, list[dict[str, Any]]] = {}
    for (ref, _keyid), pr in preregs.items():
        commitments_by_ref.setdefault(ref, []).append(pr)
    rejected_by_ref: dict[str, list[dict[str, Any]]] = {}
    for rp in rejected_preregs.values():
        rejected_by_ref.setdefault(rp["ref"], []).append(rp)

    # A manifest is identified by its ref, so a copy (same ref and keyid) of one already
    # listed adds nothing: the same ref is the same body, links and all. A postreg that names
    # a provided prereg counts toward the commitment of its ref whose signer it shares (it
    # meets the selfsig conditions and has that keyid); one that counts toward none is
    # rejected under every commitment of that ref (invalid signature, else a different key)
    # and every rejected pre-registration of that ref. Under a rejected pre-registration the
    # reason is always the prereg's invalid signature: its keyid is compared with nothing.
    notarization_only: list[dict[str, Any]] = []
    for links, rec in postregs:
        candidates = commitments_by_ref.get(links.fulfills, [])
        rejected_named = rejected_by_ref.get(links.fulfills, [])
        if candidates or rejected_named:
            entry = {"ref": rec["ref"], "prev_hash": links.prev_hash, "keyid": rec["keyid"]}
            different_key = False
            if not _selfsig_ok(rec):
                reason = REASON_INVALID_SIGNATURE
            elif (links.fulfills, rec["keyid"]) in preregs:  # a keyid that passed selfsig: a str
                _add_once(preregs[(links.fulfills, rec["keyid"])]["counted_postregs"], entry)
                continue
            else:
                reason, different_key = REASON_DIFFERENT_KEY, True
            for pr in candidates:
                _add_once(pr["rejected_postregs"], {**entry, "reason": reason})
                pr["different_key"] = pr["different_key"] or different_key
            for rp in rejected_named:
                _add_once(
                    rp["rejected_postregs"], {**entry, "reason": REASON_PREREG_INVALID_SIGNATURE}
                )
        else:
            _add_once(
                notarization_only,
                {"ref": rec["ref"], "fulfills": links.fulfills, "keyid": rec["keyid"]},
            )

    commitments = []
    for pr in preregs.values():
        due_present, due_ts, due_naive = _parse_due(pr.get("due"))
        state = _commitment_state(pr, now, due_present, due_ts)
        chain_ok, chain_note = _check_chain(pr["counted_postregs"])
        commitments.append(
            {
                **pr,
                "state": state,
                "due_naive": due_naive,
                "chain_ok": chain_ok,
                "chain_note": chain_note,
                # keyconsist's scope, defined here only: a commitment is key-checked iff it
                # has a counted postreg or a postreg rejected under it as signed by a
                # different key (different_key). One whose postregs all have invalid
                # signatures has no key to check: selfsig judges them. Its verdict is
                # `not different_key`.
                "key_checked": bool(pr["counted_postregs"]) or pr["different_key"],
            }
        )

    results = _evaluate(tests, manifests_report, commitments, artifacts_dir)
    code = _build_code(tests, results)
    ok = all(results[t]["result"] == "PASS" for t in tests)

    return {
        "tests": tests,
        "manifests": manifests_report,
        "commitments": commitments,
        "rejected_preregs": list(rejected_preregs.values()),
        "notarization_only": notarization_only,
        "results": results,
        "code": code,
        "ok": ok,
        "ceiling_trust": ceiling_trust,
        "checked_at": _utc_timestamp(now),
    }


def _json_value(value: Any) -> str:
    """``value`` as JSON text: two values are the same JSON value iff these are equal (in
    Python, ``1``, ``1.0`` and ``true`` are all equal, and ``NaN`` is not equal to itself)."""
    return json.dumps(value, sort_keys=True)


def _add_once(entries: list[dict[str, Any]], entry: dict[str, Any]) -> None:
    if entry not in entries:
        entries.append(entry)


def _utc_timestamp(epoch: float) -> str:
    """``epoch`` as ISO-8601 UTC to the second, e.g. ``2026-10-25T14:03:12Z``."""
    return datetime.datetime.fromtimestamp(epoch, datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _tally(units: list[bool], nowhere_reason: str, fail_noun: str) -> dict[str, Any]:
    """Turn a list of per-unit pass booleans into a test result.

    PASS iff there is at least one applicable unit and all of them pass;
    otherwise FAIL - distinguishing "applied nowhere" from "some failed" in the
    human-readable reason (never a silent omission or a pass with nothing examined).
    """
    n = len(units)
    if n == 0:
        return {"result": "FAIL", "applicable": 0, "reason": nowhere_reason}
    n_pass = sum(1 for u in units if u)
    if n_pass == n:
        return {"result": "PASS", "applicable": n, "reason": f"{n}/{n} {fail_noun} ok"}
    return {"result": "FAIL", "applicable": n, "reason": f"{n - n_pass}/{n} {fail_noun} failed"}


def _evaluate(tests, manifests, commitments, artifacts_dir) -> dict[str, dict[str, Any]]:
    res: dict[str, dict[str, Any]] = {}
    with_counted = [c for c in commitments if c["counted_postregs"]]
    key_checked = [c for c in commitments if c["key_checked"]]

    if "format" in tests:
        units = [m["format"]["ok"] for m in manifests]
        res["format"] = _tally(units, "no manifests to verify", "manifest(s)")

    if "selfsig" in tests:
        units = [_selfsig_ok(m) for m in manifests if m["selfsig"]["examined"]]
        res["selfsig"] = _tally(units, "no manifest passes format", "manifest(s)")

    if "floor" in tests:
        units = [
            m["floor"]["status"] == "verified"
            for m in manifests
            if m["floor"]["status"] != "absent"
        ]
        res["floor"] = _tally(
            units, "requested but no manifest carries an anchor.floor", "floor(s)"
        )

    if "ceiling" in tests:
        units = [
            m["ceiling"]["status"] == "verified"
            for m in manifests
            if m["ceiling"]["status"] != "absent"
        ]
        res["ceiling"] = _tally(
            units, "requested but no manifest carries a ceiling witness", "ceiling(s)"
        )

    if "content" in tests:
        units = [
            m["content"]["status"] == "ok"
            for m in manifests
            if m["content"]["status"] not in ("skipped",)
        ]
        nowhere = (
            "requested but no content could be checked "
            "(need --artifacts and a manifest with a subject)"
        )
        res["content"] = _tally(units, nowhere, "subject(s)")

    if "chain" in tests:
        units = [c["chain_ok"] for c in with_counted]
        res["chain"] = _tally(
            units, "requested but no commitment has counted postregs to chain-check", "chain(s)"
        )

    if "keyconsist" in tests:
        units = [not c["different_key"] for c in key_checked]
        res["keyconsist"] = _tally(
            units,
            "requested but no validly signed postreg names a commitment",
            "commitment(s)",
        )

    return res


def _build_code(tests: list[str], results: dict[str, dict[str, Any]]) -> str:
    tokens = [f"{name}={results[name]['result']}" for name in sorted(tests)]
    return VERIFY_CODE_VERSION + " " + " ".join(tokens)


# Why a postreg that names a prereg does not count toward its commitment, and why a prereg
# is a rejected pre-registration (REASON_INVALID_SIGNATURE), as the report shows it
# (docs/VERIFICATION.md). No verdict reads them: keyconsist reads the commitment's
# different_key flag, so rewording one cannot change a verdict.
REASON_INVALID_SIGNATURE = "invalid signature"
REASON_DIFFERENT_KEY = "signed by a different key than the pre-registration"
REASON_PREREG_INVALID_SIGNATURE = "the pre-registration's signature is invalid"


def _commitment_state(
    pr: dict[str, Any], now: float, due_present: bool, due_ts: float | None
) -> str:
    if pr["counted_postregs"]:
        return "fulfilled"
    if not due_present:
        return "open"  # no deadline declared -> cannot elapse
    if due_ts is None:
        return "invalid-due"
    return "elapsed-no-postreg" if now >= due_ts else "open"


def _check_chain(postregs: list[dict[str, Any]]):
    """A prev_hash chain over a commitment's counted postregs: exactly one root
    (no prev_hash), each other points to a present postreg, and no postreg has
    more than one successor (a single linear chain: no forks, no cycles)."""
    if not postregs:
        return True, "no counted postregs"
    refs = {r["ref"] for r in postregs}
    roots = [r for r in postregs if r["prev_hash"] is None]
    if len(roots) != 1:
        return False, f"expected exactly one chain root, found {len(roots)}"
    successors: dict[Any, int] = {}
    for r in postregs:
        prev = r["prev_hash"]
        if prev is not None and prev not in refs:
            return False, "a postreg's prev_hash points to a missing postreg (gap)"
        if prev is not None:
            successors[prev] = successors.get(prev, 0) + 1
    if any(n > 1 for n in successors.values()):
        return False, "a postreg has more than one successor (fork)"
    return True, "chain intact"


def _expand(paths: list[str]) -> list[tuple[str, OSError | None]]:
    """Each manifest file to examine, with the error that stops it being read, if any.

    A directory stands for its ``*.json`` files. A directory that cannot be listed is
    examined itself, as malformed, like a path that cannot be read."""
    out: list[tuple[str, OSError | None]] = []
    for p in paths:
        if not os.path.isdir(p):
            out.append((p, None))
            continue
        try:
            names = sorted(os.listdir(p))
        except OSError as e:
            out.append((p, e))
            continue
        out.extend((os.path.join(p, name), None) for name in names if name.endswith(".json"))
    return out
