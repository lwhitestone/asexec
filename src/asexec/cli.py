"""asexec command-line interface.

Commands: keygen, prereg, postreg, verify, identity.

``verify`` is fully offline; only the sign-time drand (``--floor``)/Roughtime (``--ceiling``)
fetches and ``identity match`` touch the network.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
import uuid
from collections import Counter
from collections.abc import Callable

from pydantic import ValidationError

from . import __version__, drand, hashing, identity, keys, manifest, parsing, verifier
from .constants import FORMATS, MANIFEST_PAYLOAD_TYPE, SUBJECT_DEFAULT_HASH_ALG
from .errors import AsexecError, ManifestError, VerificationError
from .models import STATUSES

# A ref as the format signing writes it.
REF_RE = re.compile(
    re.escape(FORMATS[MANIFEST_PAYLOAD_TYPE]["digest_ref_prefix"]) + r"[0-9a-f]{64}"
)
OK = "✓"
NO = "✗"

# Exit statuses (README "Exit status"). A ``SystemExit("error: ...")`` exits EXIT_ERROR, as
# does any error ``main`` catches. Checks that need only the arguments are argparse's, so
# they exit EXIT_USAGE; checks that need a file or the network exit EXIT_ERROR.
EXIT_OK = 0  # success; verify: every requested test PASS; identity match: bound
EXIT_ERROR = 1  # the arguments are valid but the command failed (input file, fetch, ...)
EXIT_FAIL = 2  # verify: a requested test FAIL; identity match: not bound
EXIT_USAGE = 64  # usage error (sysexits EX_USAGE): the arguments themselves are wrong


# --------------------------------------------------------------------------- #
# input helpers
# --------------------------------------------------------------------------- #
# How deep a JSON value may nest: a manifest file's limit, or one less for a value that sits one
# level down in the body (target, declaration, notes, repro_recipe), so the body is at most 64.
_FILE_DEPTH = parsing.MAX_NESTING_DEPTH
_IN_BODY_DEPTH = parsing.MAX_NESTING_DEPTH - 1


def _rule_broken(e: ManifestError, max_depth: int) -> str:
    """A JSON rule's message (``parsing.parse_json``), saying why a value inside the body is
    held one level shallower."""
    if max_depth < _FILE_DEPTH and str(e).startswith("nested more than"):
        return f"{e} (its value sits one level down in a body, which is at most {_FILE_DEPTH})"
    return str(e)


def _read_json(path: str, max_depth: int):
    """The JSON value a ``--…-file`` holds, held to a manifest file's JSON rules: UTF-8 JSON
    text (RFC 8259), no duplicate key, at most ``max_depth`` deep (``parsing.parse_json``).
    Raises ``ManifestError`` (exit 1, one line) otherwise: what a file holds is not an
    argument. Paths are shown quoted, so a newline in one can't split the error line."""
    with open(path, "rb") as f:
        data = f.read()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ManifestError(
            f"{path!r} must contain valid JSON: it is not UTF-8 text ({e})"
        ) from None
    try:
        return parsing.parse_json(text, max_depth)
    except ManifestError as e:  # a duplicate key, or nested too deep
        raise ManifestError(f"{path!r}: {_rule_broken(e, max_depth)}") from None
    except ValueError as e:  # not JSON, or an integer of more digits than Python reads
        raise ManifestError(f"{path!r} must contain valid JSON: {e}") from None


def _free_form_file(flag: str) -> Callable[[str], str | dict]:
    """A loader for ``--target-file``, ``--declaration-file`` or ``--notes-file``: what the
    field is, a JSON object or a string, and not an empty one."""

    def load(path: str) -> str | dict:
        value = _read_json(path, _IN_BODY_DEPTH)
        if not (isinstance(value, str | dict) and value):
            raise ManifestError(
                f"{flag} {path!r} must hold a non-empty JSON object or string: {_short(value)}"
            )
        return value

    return load


def _get_arg_or_file[T](
    args, arg_name: str, file_arg_name: str, load_file: Callable[[str], T]
) -> str | T | None:
    """Load a value from ``--<arg>`` or ``--<file-arg>`` (argparse allows at most one).

    The inline ``--<arg>`` value is already parsed and checked by its argparse ``type``
    (``_add_arg_or_file``), so a bad one was a usage error before anything ran. What a file
    holds is not an argument: ``load_file`` fails with exit 1."""
    value = getattr(args, arg_name, None)
    file_path = getattr(args, file_arg_name, None)
    if value is not None:
        return value
    if file_path is not None:
        flag = "--" + file_arg_name.replace("_", "-")
        try:
            mode = os.stat(file_path).st_mode
        except FileNotFoundError:
            raise SystemExit(f"error: {flag} not found: {file_path!r}") from None
        if stat.S_ISDIR(mode):  # anything else is read: a file, a pipe, /dev/stdin
            raise SystemExit(f"error: {flag} is a directory: {file_path!r}")
        return load_file(file_path)
    return None


def _get_target(args) -> str | dict | None:
    """Retrieve the target value (from arg xor file), if any."""
    return _get_arg_or_file(args, "target", "target_file", _free_form_file("--target-file"))


def _get_declaration(args) -> str | dict | None:
    """Retrieve the declaration value (from arg xor file), if any."""
    return _get_arg_or_file(
        args, "declaration", "declaration_file", _free_form_file("--declaration-file")
    )


def _get_notes(args) -> str | dict | None:
    """Retrieve the notes value (from arg xor file), if any."""
    return _get_arg_or_file(args, "notes", "notes_file", _free_form_file("--notes-file"))


# What a --plan / --evidence entry may say besides ``name``: the declared fields, text or
# absent, never tested. asexec hashes the file at ``name`` and fills in ``hash_alg``
# (--hash-alg) and ``digest``, as --subject does.
_PLAN_DECLARED = ("media_type", "label")
_EVIDENCE_DECLARED = ("media_type", "uri")


def _strict_json(text: str, max_depth: int):
    """A JSON value held to a manifest file's JSON rules (``parsing.parse_json``: no
    duplicate key, since parsers disagree on which value wins, and at most ``max_depth``
    deep); ``ValueError`` otherwise."""
    try:
        return parsing.parse_json(text, max_depth)
    except ManifestError as e:  # a duplicate key, or nested too deep
        raise ValueError(_rule_broken(e, max_depth)) from None
    except ValueError as e:  # not JSON, or an integer of more digits than Python reads
        raise ValueError(f"not valid JSON: {e}") from None


def _spec_shape(spec, flag: str, declared: tuple[str, ...]) -> dict:
    """A file described as ``{"name": <path>, <declared>...}``; ``ValueError`` if it is not
    one."""
    if not isinstance(spec, dict) or not isinstance(spec.get("name"), str):
        raise ValueError(f"{flag} needs a 'name' (a file path) in each entry: {spec!r}")
    why = hashing.describe_unstorable_name(spec["name"])
    if why:  # no path, or no body, can hold it
        raise ValueError(f"{flag}: {spec['name']!r} names no file: it has {why}")
    if "hash_alg" in spec or "digest" in spec:
        raise ValueError(
            f"{flag}: asexec hashes the file and fills in hash_alg and digest "
            "(choose the algorithm with --hash-alg)"
        )
    allowed = ("name", *declared)
    unknown = sorted(set(spec) - set(allowed))
    if unknown:
        raise ValueError(
            f"{flag}: unknown field(s) {', '.join(map(repr, unknown))}; "
            f"an entry may hold {', '.join(map(repr, allowed))}"
        )
    for field in declared:  # text, or absent
        if spec.get(field) is not None and not isinstance(spec[field], str):
            raise ValueError(f"{flag}: {field!r} must be a string: {spec[field]!r}")
    return spec


def _plan_shape(value) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f'--plan must be a JSON object, like {{"name": "plan.md"}}: {value!r}')
    return _spec_shape(value, "--plan", _PLAN_DECLARED)


def _items_shape(value) -> list:
    """``--items``: an array of ``{"id": <string>, "kind": <string>}``, ids unique."""
    if not isinstance(value, list):
        raise ValueError(f'--items must be a JSON array, like [{{"id": "S1"}}]: {value!r}')
    for item in value:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            raise ValueError(f"--items: each item needs a string 'id': {item!r}")
        unknown = sorted(set(item) - {"id", "kind"})
        if unknown:
            raise ValueError(
                f"--items: unknown field(s) {', '.join(map(repr, unknown))}; "
                "an item may hold 'id' and 'kind'"
            )
        if item.get("kind") is not None and not isinstance(item["kind"], str):
            raise ValueError(f"--items: 'kind' must be a string: {item['kind']!r}")
    counts = Counter(item["id"] for item in value)
    repeated = sorted(i for i, n in counts.items() if n > 1)
    if repeated:
        raise ValueError(f"--items lists the id {', '.join(map(repr, repeated))} twice")
    return value


def _evidence_shape(value) -> list:
    if not isinstance(value, list):
        raise ValueError(
            f'--evidence must be a JSON array, like [{{"name": "out.json"}}]: {value!r}'
        )
    if not value:
        raise ValueError("--evidence must list at least one file")
    return [_spec_shape(spec, "--evidence", _EVIDENCE_DECLARED) for spec in value]


def _shaped_arg_or_file(args, name: str, shape: Callable):
    """``--<name>`` (inline JSON) or ``--<name>-file``, held to ``shape``. An inline value that
    fails it is a usage error (64); a file's content that fails it exits 1."""

    def load_file(path: str):
        value = _read_json(path, _FILE_DEPTH)  # the same JSON rules as an inline value
        try:
            return shape(value)
        except ValueError as e:
            raise ManifestError(str(e)) from None

    return _get_arg_or_file(args, name, f"{name}_file", load_file)


def _repro_recipe_shape(value) -> dict:
    if not isinstance(value, dict):
        raise ValueError(
            f'--repro-recipe must be a JSON object, like {{"seed": 0}}: {_short(value)}'
        )
    return value


def _short(value) -> str:
    """``value`` for an error message: its repr, cut to a line's length."""
    text = repr(value)
    return text if len(text) <= 80 else text[:77] + "..."


def _described_entries(specs: list, alg: str) -> list[dict]:
    """Entries for files described as ``{"name": <path>, ...}`` (already shaped): each file
    hashed as a subject file is (``hashing.build_entries``), with its declared fields kept."""
    entries = hashing.build_entries([spec["name"] for spec in specs], alg)
    return [
        {**entry, **{k: v for k, v in spec.items() if k != "name"}}
        for entry, spec in zip(entries, specs, strict=True)
    ]


def _get_plan(args) -> dict | None:
    """``body.plan`` from --plan / --plan-file: one described file."""
    spec = _shaped_arg_or_file(args, "plan", _plan_shape)
    return None if spec is None else _described_entries([spec], args.hash_alg)[0]


def _get_items(args) -> list | None:
    """``body.items`` from --items / --items-file: a list of ``{"id", "kind"}``, as given."""
    return _shaped_arg_or_file(args, "items", _items_shape)


def _get_evidence(args) -> list | None:
    """``body.evidence`` from --evidence / --evidence-file: a non-empty list of described
    files."""
    specs = _shaped_arg_or_file(args, "evidence", _evidence_shape)
    return None if specs is None else _described_entries(specs, args.hash_alg)


def _built(build: Callable[..., dict], *args, **kwargs) -> dict:
    """A body from ``manifest.build_*``; what its writer model refuses is a clean error."""
    try:
        return build(*args, **kwargs)
    except ValidationError as e:
        raise ManifestError(
            "; ".join(f"{'.'.join(map(str, x['loc'])) or 'body'}: {x['msg']}" for x in e.errors())
        ) from None


# A drand round as its HTTP API returns one (``GET /<chain hash>/public/<round>``): what a run
# saves when it fetches the round it starts with, to sign as its floor later.
_ROUND_FIELDS = ("round", "randomness", "signature")


def _round_shape(value) -> dict:
    """``--floor-round``: a round of the chain ``--floor`` fetches from, as drand's HTTP API
    returns it, that meets every floor condition (``drand.verified_floor``: the pinned chain,
    BLS, randomness). The ``anchor.floor`` record to sign; ``ValueError`` if it is not one."""
    if not isinstance(value, dict):
        raise ValueError(
            "--floor-round must be a JSON object, as drand's HTTP API returns a round: "
            f'{{"round": ..., "randomness": ..., "signature": ...}}: {value!r}'
        )
    unknown = sorted(set(value) - set(_ROUND_FIELDS))
    if unknown:
        raise ValueError(
            f"--floor-round: unknown field(s) {', '.join(map(repr, unknown))}; a round holds "
            "'round', 'randomness' and 'signature', as drand's HTTP API returns it (the chain "
            "is the one --floor fetches from)"
        )
    missing = [f for f in _ROUND_FIELDS if f not in value]
    if missing:
        raise ValueError(f"--floor-round: missing {', '.join(map(repr, missing))}")
    if type(value["round"]) is not int:
        raise ValueError(f"--floor-round: 'round' must be an integer: {value['round']!r}")
    for field in ("randomness", "signature"):
        if not (isinstance(value[field], str) and _LOWER_HEX.fullmatch(value[field])):
            raise ValueError(
                f"--floor-round: {field!r} must be lowercase hex, as drand writes it: "
                f"{value[field]!r}"
            )
    try:
        return drand.verified_floor(value, drand.SIGNING_CHAIN)
    except ValueError as e:
        raise ValueError(f"--floor-round: {e}") from None


_LOWER_HEX = re.compile(r"(?:[0-9a-f]{2})+")


def _get_floor(args) -> dict | None:
    """The drand freshness floor (anchor.floor) to sign: a round fetched earlier
    (--floor-round / --floor-round-file, verified here, offline), the latest round fetched now
    (--floor, network), or None."""
    if args.floor_round is not None or args.floor_round_file is not None:
        return _shaped_arg_or_file(args, "floor_round", _round_shape)
    if not args.floor:
        return None
    try:
        return drand.fetch_floor(drand.SIGNING_CHAIN)
    except Exception as e:
        if not args.best_effort:
            raise SystemExit(
                f"error: drand fetch failed ({e}); nothing was signed. "
                "Retry, or pass --best-effort to sign without the freshness floor."
            ) from e
        sys.stderr.write(f"warning: drand fetch failed ({e}); continuing without freshness floor\n")
        return None


def _build_subject(paths: list[str] | None, hash_alg: str) -> list | None:
    """Construct subject data: one entry per file path, named by its normalized path
    relative to the current directory, with its own hash_alg and digest."""
    return hashing.build_subject(paths, hash_alg) if paths else None


def _load_manifest_body(path: str, flag: str) -> tuple[bytes, dict]:
    """The body bytes and body of a manifest file named by ``flag``, turning any failure
    into a clean error."""
    try:
        return manifest.read_body(manifest.load(path))
    except Exception as e:
        raise SystemExit(f"error: {flag} {path!r} is not a readable manifest: {e}") from e


def _read_prereg(path: str) -> tuple[str, dict]:
    """The ref and body of the ``--fulfills`` file, read as verify reads it. It must pass
    ``format``: a file of a format this release does not read, or a malformed one, has no ref
    or body it can take. Its signature is not checked here: verify judges it."""
    try:
        mani = manifest.load(path)
    except (ManifestError, ValueError) as e:  # not UTF-8, not JSON, not an object, ...
        raise SystemExit(f"error: --fulfills {path!r} is not a readable manifest: {e}") from None
    fmt = verifier.verify_format(mani)
    if not fmt["ok"]:
        raise SystemExit(
            f"error: --fulfills {path!r} is not a readable manifest: {fmt['errors'][0]}"
        )
    return fmt["ref"], fmt["body"]


def _resolve_ref(value: str, flag: str) -> str:
    """A --fulfills/--prev value is an existing manifest file (its ref: the digest of the
    body bytes it stores) or a well-formed ``sha-256:<64 lowercase hex>`` ref; anything else
    (e.g. a typo'd path) is an error."""
    if os.path.isfile(value):
        return manifest.ref(_load_manifest_body(value, flag)[0])
    if REF_RE.fullmatch(value):
        return value
    raise SystemExit(
        f"error: {flag} {value!r} is neither an existing manifest file nor a "
        "sha-256:<64 hex> reference"
    )


def _attach_ceiling(mani: dict, ref: str, want_ceiling: bool, best_effort: bool) -> None:
    """Optionally fetch a Roughtime ceiling witness and attach it (sign-time,
    network). The nonce is the body's ``ref``, so this must run *after* signing; it
    does not perturb ref. A failed fetch aborts (nothing is written) unless
    ``best_effort``."""
    if not want_ceiling:
        return
    from . import roughtime

    nonce = ref  # sha-256:<hex>
    try:
        ceiling = roughtime.fetch_ceiling(nonce)
    except Exception as e:
        if not best_effort:
            raise SystemExit(
                f"error: ceiling witness fetch failed ({e}); nothing was written. "
                "Retry, or pass --best-effort to sign without a ceiling."
            ) from e
        sys.stderr.write(
            f"warning: ceiling witness fetch failed ({e}); continuing without a ceiling\n"
        )
        return
    manifest.attach_ceiling(mani, ceiling)
    print(
        f"  ceiling : {ceiling.get('ceiling_type')} witness {ceiling.get('witness_id')} "
        f"@ {ceiling.get('midpoint')} (±{ceiling.get('radius')}s)"
    )


def _show(text: str) -> None:
    """Print a report line. A manifest's strings are printed as they are, except that a
    character with no UTF-8 form (a lone surrogate, which a body may hold as valid JSON) is
    shown as its escape, ``\\udXXX``, so the report never fails to print."""
    print(text.encode("utf-8", "backslashreplace").decode("utf-8"))


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #
def cmd_keygen(args) -> int:
    """Generate a cryptographic key for signing pre- and post-registrations."""
    out = args.out or f"asexec-{uuid.uuid4()}.key"
    priv, _pub = keys.generate()
    try:
        kid = keys.save(priv, out, force=args.force)
    except FileExistsError as e:
        raise SystemExit(
            f"error: {e.filename!r} already exists; refusing to overwrite a key "
            "(pass --force to replace it - the old key is lost)"
        ) from None
    print(f"{OK} generated ed25519 key")
    print(f"  secret : {out} (keep private; mode 0600)")
    print(f"  public : {out}.pub")
    print(f"  keyid  : {kid}")
    return EXIT_OK


def cmd_prereg(args) -> int:
    """Write a signed pre-registration, signalling the intended execution."""
    target = _get_target(args)  # argparse requires one
    priv, pub = keys.load_signing_key(args.key)
    subject = _build_subject(args.subject, args.hash_alg)
    plan, items = _get_plan(args), _get_items(args)
    body = _built(
        manifest.build_prereg,
        target,
        due=args.due,
        declaration=_get_declaration(args),
        subject=subject,
        floor=_get_floor(args),
        notes=_get_notes(args),
        plan=plan,
        items=items,
    )
    mani = manifest.sign(body, priv, pub)
    ref = manifest.ref(manifest.read_body(mani)[0])
    _attach_ceiling(mani, ref, args.ceiling, args.best_effort)
    manifest.save(mani, args.out)
    print(f"{OK} pre-registration written: {args.out}")
    print(f"  ref : {ref}")
    if body.get("due"):
        print(f"  due : {body['due']}")
    return EXIT_OK


def cmd_postreg(args) -> int:
    """Write a signed post-registration, documenting the execution and fulfilling
    a pre-registration as promised."""
    priv, pub = keys.load_signing_key(args.key)

    prereg_body = None  # the decoded body of the prereg file, to inherit from
    if os.path.isfile(args.fulfills):
        fulfills, prereg_body = _read_prereg(args.fulfills)
    else:
        fulfills = _resolve_ref(args.fulfills, "--fulfills")
    prev_hash = _resolve_ref(args.prev, "--prev") if args.prev else None

    # target / due / declaration inherit from the fulfilled prereg unless overridden on this
    # postreg. Each subject entry names its own hash_alg: --hash-alg, or the default.
    target = _get_target(args)
    if target is None:
        if prereg_body is None:
            raise SystemExit("error: no --target and --fulfills is not a readable prereg")
        target = prereg_body.get("target")
        if not (isinstance(target, str | dict) and target):
            raise SystemExit(
                f"error: --fulfills {args.fulfills!r} has no target to inherit (a non-empty "
                "string or JSON object); give --target or --target-file"
            )

    due = args.due or (prereg_body or {}).get("due")
    declaration = _get_declaration(args) or (prereg_body or {}).get("declaration")
    subject = _build_subject(args.subject, args.hash_alg)
    evidence = _get_evidence(args)
    body = _built(
        manifest.build_postreg,
        target,
        fulfills=fulfills,
        due=due,
        declaration=declaration,
        subject=subject,
        prev_hash=prev_hash,
        floor=_get_floor(args),
        notes=_get_notes(args),
        provenance=args.provenance,
        repro_recipe=args.repro_recipe,
        item_id=args.item_id,
        status=args.status,
        evidence=evidence,
    )
    mani = manifest.sign(body, priv, pub)
    ref = manifest.ref(manifest.read_body(mani)[0])
    _attach_ceiling(mani, ref, args.ceiling, args.best_effort)
    manifest.save(mani, args.out)
    print(f"{OK} post-registration written: {args.out}")
    print(f"  ref      : {ref}")
    print(f"  fulfills : {body['fulfills']}")
    if body.get("prev_hash"):
        print(f"  prev     : {body['prev_hash']}")
    return EXIT_OK


def cmd_verify(args) -> int:
    """Run a series of verification tests on the prereg-postreg cycle to prove that
    this execution met the desired standards. Produces a code summarizing the tests
    performed and the results of each. ``args.tests`` is already validated (see
    ``_tests_arg``).

    The verdict is decided before anything is printed, so a reader that closes stdout early
    (``asexec verify … | head -1``) does not change the exit status."""
    report = verifier.verify_paths(args.paths, args.tests, artifacts_dir=args.artifacts)
    status = EXIT_OK if report["ok"] else EXIT_FAIL
    try:
        _show_report(report)
        _flush_stdout()
    except _StdoutError as e:
        if not isinstance(e.error, BrokenPipeError):
            raise  # e.g. a full device: the report was not written, an error (main)
        _drop_stdout()  # the reader has gone: the rest of the report has no one to read it
    return status


def _show_report(report: dict) -> None:
    """The verify report, for people to read; then the code and the time it was checked."""
    _show("=== manifests ===")
    for m in report["manifests"]:
        ss = m["selfsig"]
        s = OK if (ss["signature_ok"] and ss["keyid_ok"]) else NO  # passes format and selfsig
        _show(f"{s} {m['path']}  [{m.get('phase')}]  keyid={m.get('keyid')}")
        for err in m["format"]["errors"]:
            _show(f"    {NO} format: {err}")
        fl = m["floor"]
        if fl["status"] != "absent":
            fs = OK if fl["status"] == "verified" else NO
            extra = (
                f" (created no earlier than {fl.get('created_no_earlier_than')})"
                if fl["status"] == "verified"
                else ""
            )
            _show(f"    {fs} drand freshness floor round {fl.get('round', '?')}{extra}")
        cl = m["ceiling"]
        if cl["status"] != "absent":
            cs = OK if cl["status"] == "verified" else NO
            extra = (
                f" (created no later than {cl.get('midpoint')} ±{cl.get('radius')}s, "
                f"witness {cl.get('witness_id')})"
                if cl["status"] == "verified"
                else f" ({cl.get('error', cl['status'])})"
            )
            _show(f"    {cs} ceiling witness{extra}")
        c = m["content"]
        if c["status"] not in ("skipped",):
            cs = OK if c["status"] == "ok" else NO
            _show(f"    {cs} content hashes {c['status']}")
            for e in c.get("entries", []):
                if not e["ok"]:
                    what = "" if e["field"] == "subject" else f"{e['field']} "  # plan, evidence
                    _show(f"        {NO} {what}{e['name']}: {e.get('reason', 'digest mismatch')}")

    _show_fields(report["manifests"], "untrusted", UNTRUSTED_HEADING)
    _show_fields(report["manifests"], "unknown", UNKNOWN_HEADING)

    _show("\n=== commitments ===")
    if not report["commitments"] and report["rejected_preregs"]:
        _show("  (no commitments: no pre-registration provided is validly signed)")
    elif not report["commitments"]:
        _show("  (no pre-registrations among the provided manifests)")
    for c in report["commitments"]:
        _show(f"  [{c['state'].upper()}] prereg {c['ref']}")
        _show(f"    signer       : {c.get('keyid')}")
        due = c.get("due")
        if due is None:
            due = "(none declared)"
        elif not (isinstance(due, str) and due):
            due = json.dumps(due)  # present but no timestamp, e.g. "" or 0: show it as is
        _show(f"    due          : {due}")
        if c["due_naive"]:
            _show(f"    {NO} due has no timezone; read as UTC (re-sign with an explicit offset)")
        if c["due_invalid"]:  # in any state: timely fails on it too
            _show(f"    {NO} due is not a parseable ISO-8601 timestamp")
        _show(
            f"    postregs     : {len(c['counted_postregs'])}"
            + ("" if c["chain_ok"] else f"  {NO} {c['chain_note']}")
        )
        if "timely" in report["tests"]:  # each counted postreg not shown on time, and why
            for t in c["timeliness"]:
                if t["status"] != "on-time":
                    _show(f"    {NO} postreg {t['ref']} {_NOT_ON_TIME[t['status']](t)}")
        if "order" in report["tests"]:  # each counted postreg not shown after the prereg
            _show_order(c["order"])
        _show_items(c["complete"])
        for r in c["rejected_postregs"]:
            _show(f"    {NO} postreg {r['ref']} does NOT count toward fulfillment: {r['reason']}")
    if report["rejected_preregs"]:  # pass format, fail selfsig: no commitment, no state
        _show("\n=== rejected pre-registrations ===")
        for rp in report["rejected_preregs"]:
            _show(f"  {NO} prereg {rp['ref']} is NOT a commitment: {rp['reason']}")
            _show(f"    keyid        : {rp.get('keyid')}")
            for r in rp["rejected_postregs"]:
                _show(
                    f"    {NO} postreg {r['ref']} does NOT count toward fulfillment: {r['reason']}"
                )
    if report["notarization_only"]:
        _show("\n=== notarization-only (postregs with no matching pre-registration) ===")
        for n in report["notarization_only"]:
            _show(f"  {n['ref']}  (fulfills {n.get('fulfills')})")

    _show("\n=== tests ===")
    for t in report["tests"]:
        r = report["results"][t]
        s = OK if r["result"] == "PASS" else NO
        _show(f"  {s} {t}={r['result']}  ({r['reason']})")

    if report["ceiling_trust"]:
        _show("\n=== ceiling trust (what you are accepting) ===")
        for line in report["ceiling_trust"]:
            _show(f"  - {line}")

    _show(f"\n{report['code']}")
    _show(f"Checked at {report['checked_at']}")


UNTRUSTED_HEADING = "=== untrusted (unsigned, and read by no test: nothing here was checked) ==="
UNKNOWN_HEADING = (
    "=== unknown fields (signed, but this format does not define them: nothing here was "
    "checked) ==="
)
# A key shown as ``.key`` in a path; any other is shown as JSON, ``["a b"]``.
_PLAIN_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _json_text(value) -> str:
    """``value`` as one line of ASCII JSON: a newline, a control character or any non-ASCII
    character in it is escaped, so it cannot forge a line of the report."""
    return json.dumps(value, ensure_ascii=True)


def _path_text(path: list) -> str:
    """A path of keys and indexes as the doc writes it (``body.subject[0].name``), each key that
    is not plain shown as JSON (``body["a\\nb"]``)."""
    text = ""
    for part in path:
        if isinstance(part, int):
            text += f"[{part}]"
        elif _PLAIN_KEY.fullmatch(part):
            text += f".{part}" if text else part
        else:
            text += f"[{_json_text(part)}]"
    return text


def _show_fields(manifests: list, kind: str, heading: str) -> None:
    """Under ``heading``, if any file has them: each file's ``untrusted`` or ``unknown``
    entries (``verifier._untrusted``, ``_unknown_fields``), each path and value as JSON. These
    are the file's least checked text, so none is printed raw."""
    shown = [m for m in manifests if m[kind]]
    if not shown:
        return
    _show(f"\n{heading}")
    for m in shown:
        _show(f"  {m['path']}")
        for entry in m[kind]:
            _show(f"    {_path_text(entry['path'])} = {_json_text(entry['value'])}")


def _show_items(cp: dict) -> None:
    """A commitment's items (``complete``'s view, shown whenever its prereg lists items):
    each item's status, or why it is not accounted for; then any problem with the list, and
    each counted postreg whose item_id names no listed item."""
    if not cp["examined"]:
        return
    if cp["reason"] == verifier.REASON_ITEMS_MALFORMED:
        _show(f"    {NO} {cp['reason']}")
        return
    _show(f"    items        : {len(cp['items'])}")
    for item in cp["items"]:
        text = ", ".join(item["statuses"])
        if not item["ok"]:
            text = f"{text}, but {item['reason']}" if text else item["reason"]
        _show(f"      {OK if item['ok'] else NO} {item['id']}: {text}")
    if cp["reason"] and cp["reason"].startswith("item ids repeat"):
        _show(f"    {NO} {cp['reason']}")
    for u in cp["unlisted"]:
        _show(
            f"    {NO} postreg {u['ref']} names item {u['item_id']!r}, which the prereg does "
            "not list"
        )


# Why a counted postreg is not shown on time (verifier._on_time), as the report says it.
_NOT_ON_TIME: dict[str, Callable[[dict], str]] = {
    "late": lambda t: (
        f"is late: its ceiling (no later than {verifier._utc_ceil(t['no_later_than_us'])}) "
        "is after due"
    ),
    "no-ceiling": lambda t: "is not shown on time: it has no ceiling",
    "invalid-ceiling": lambda t: "is not shown on time: its ceiling does not verify",
}


def _show_order(od: dict) -> None:
    """A commitment's ``order`` marks: a prereg whose ceiling gives no time, then each counted
    postreg not shown after the prereg, and why."""
    if not od["examined"]:
        return
    why = _PREREG_NOT_BEFORE.get(od["reason"])
    if why:
        _show(f"    {NO} the pre-registration is not shown before its postregs: {why}")
    for p in od["postregs"]:
        if p["status"] in _NOT_AFTER:
            _show(f"    {NO} postreg {p['ref']} {_NOT_AFTER[p['status']](p, od)}")


_PREREG_NOT_BEFORE = {
    verifier.REASON_ORDER_NO_CEILING: "it has no ceiling",
    verifier.REASON_ORDER_INVALID_CEILING: "its ceiling does not verify",
}
# Why a counted postreg is not shown after its prereg (verifier._order), as the report says it.
_NOT_AFTER: dict[str, Callable[[dict, dict], str]] = {
    "not-after": lambda p, od: (
        "is not shown after the pre-registration: its floor (no earlier than "
        f"{verifier._utc_floor(p['no_earlier_than_us'])}) is not after the pre-registration's "
        f"ceiling (no later than {verifier._utc_ceil(od['ceiling']['no_later_than_us'])})"
    ),
    "no-floor": lambda p, od: "is not shown after the pre-registration: it has no floor",
    "invalid-floor": lambda p, od: (
        "is not shown after the pre-registration: its floor does not verify"
    ),
}


def cmd_identity(args) -> int:
    """Standalone emit/match function pair for tying a known public identity via
    domain to a public key, no certificate authority (CA) needed. ``emit`` a json file
    which embeds the key and domain and publish it. Anyone may then check via
    ``match`` that the asserted identity is placed at the given domain."""
    if args.identity_cmd == "emit":
        _priv, pub = keys.load_signing_key(args.key)
        pair = {"keyid": keys.keyid_for(pub), "pubkey": pub.hex()}
        doc = identity.build_wellknown([pair], domain=args.domain)
        identity.write_wellknown(doc, args.out)
        print(f"{OK} wrote {args.out}")
        print("  publish at: https://<your-domain>/.well-known/asexec.json")
        print(f"  keyid     : {pair['keyid']}")
        return EXIT_OK
    # match: argparse requires exactly one of --keyid, --pubkey, --key
    keyid = args.keyid
    if args.key:
        _priv, pub = keys.load_signing_key(args.key)
        keyid = keys.keyid_for(pub)
    res = identity.match_binding(args.domain, keyid=keyid, pubkey_hex=args.pubkey)
    s = OK if res["bound"] else NO
    print(
        f"{s} key {'IS' if res['bound'] else 'is NOT'} asserted by {args.domain} "
        f"({res['listed_count']} key(s) listed)"
    )
    print(f"  caveat: {res['caveat']}")
    return EXIT_OK if res["bound"] else EXIT_FAIL


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def _add_anchor_flags(p):
    """Time-anchor parsing helper, shared by prereg and postreg."""
    floor = p.add_mutually_exclusive_group()  # one floor: fetched now, or given
    floor.add_argument(
        "--floor",
        action="store_true",
        help="attach a drand freshness floor, the latest round (proves created no earlier "
        "than T; network). Fails if the fetch fails, unless --best-effort",
    )
    floor.add_argument(
        "--floor-round",
        type=_json_arg(_round_shape, _FILE_DEPTH),
        help="attach as the floor a drand round fetched earlier, for example when a run "
        'started, as drand\'s HTTP API returns it: JSON {"round": ..., "randomness": ..., '
        '"signature": ...} of the chain --floor fetches from. Verified at signing (offline); '
        "a round that does not verify is refused",
    )
    floor.add_argument(
        "--floor-round-file",
        type=_nonempty_arg,
        help="the --floor-round JSON, from a file (a saved drand API response)",
    )
    p.add_argument(
        "--ceiling",
        action="store_true",
        help="attach a Roughtime ceiling witness (proves created no later than T; network). "
        "Fails if the fetch fails, unless --best-effort",
    )
    p.add_argument(
        "--best-effort",
        action="store_true",
        help="if a --floor/--ceiling fetch fails, warn and sign without it instead of failing",
    )


class _Parser(argparse.ArgumentParser):
    """An ``ArgumentParser`` whose usage errors exit ``EXIT_USAGE``, not argparse's 2,
    so they cannot be mistaken for a verify ``FAIL``. Subparsers inherit the class."""

    def error(self, message: str):
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


# Argument types: each validates a value at parse time, so a bad one is a usage error.
def _tests_arg(spec: str) -> list[str]:
    """``--tests``: known test names, including every one in ``verifier.REQUIRED_TESTS``."""
    try:
        return verifier.parse_tests(spec)
    except VerificationError as e:
        raise argparse.ArgumentTypeError(str(e)) from e


def _due_arg(value: str) -> str:
    """``--due``: an ISO-8601 deadline, returned verbatim, as verify parses it
    (``verifier.parse_due``, the one parse of ``due``).

    An explicit UTC offset (or ``Z``) is required: verify reads a timezone-less deadline as
    UTC, but flags it, since its writer may have meant local time.
    """
    try:
        _instant, naive = verifier.parse_due(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a valid ISO-8601 timestamp: {value!r}") from None
    if naive:
        raise argparse.ArgumentTypeError(
            "needs an explicit UTC offset or 'Z' "
            f"(e.g. 2026-08-30T00:00:00Z or 2026-08-30T00:00:00+02:00): {value!r}"
        )
    return value


def _nonempty_arg(value: str) -> str:
    """Any option's value: an empty one is no value, and is never read as absent."""
    if not value:
        raise argparse.ArgumentTypeError("must not be empty")
    return value


def _domain_arg(value: str) -> str:
    """``--domain``: a name with no whitespace or control character (it goes into a URL)."""
    _nonempty_arg(value)
    if any(c.isspace() or not c.isprintable() for c in value):
        raise argparse.ArgumentTypeError(
            f"a domain name has no whitespace or control character: {value!r}"
        )
    return value


def _json_arg(shape: Callable, max_depth: int):
    """An argparse ``type`` for an inline JSON value: not empty, JSON under a manifest file's
    rules (``_strict_json``, at most ``max_depth`` deep), and held to ``shape``. A value that
    fails is a usage error."""

    def parse(value: str):
        _nonempty_arg(value)
        try:
            return shape(_strict_json(value, max_depth))
        except ValueError as e:
            raise argparse.ArgumentTypeError(str(e)) from None

    return parse


def _add_arg_or_file(
    p, name: str, required: bool = False, help=None, file_help=None, type=_nonempty_arg
):
    """``--<name>`` and ``--<name>-file``: at most one (exactly one if ``required``). Neither
    may be empty; ``type`` checks the inline value."""
    group = p.add_mutually_exclusive_group(required=required)
    group.add_argument(f"--{name}", help=help, type=type)
    group.add_argument(f"--{name}-file", help=file_help, type=_nonempty_arg)


def build_parser() -> argparse.ArgumentParser:
    """``asexec`` parsing core."""
    p = _Parser(
        prog="asexec",
        description="Pre-registration & notarization primitive for AI evaluations. "
        "Does NOT prove identity, eval quality, provenance, or cryptographic "
        "'pre' (see 'verify' output).",
        epilog=f"exit status: {EXIT_OK} success (verify: every test PASS; identity match: "
        f"bound), {EXIT_ERROR} error, {EXIT_FAIL} verify: a test FAIL (identity match: "
        f"not bound), {EXIT_USAGE} usage error.",
    )
    p.add_argument("--version", action="version", version=f"asexec {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    # asexec keygen
    kg = sub.add_parser("keygen", help="generate an ed25519 keypair (no CA)")
    kg.add_argument(
        "--out",
        type=_nonempty_arg,
        default=None,
        help="secret key file (default: asexec-<uuid>.key)",
    )
    kg.add_argument(
        "--force", action="store_true", help="overwrite an existing key file (the old key is lost)"
    )
    kg.set_defaults(func=cmd_keygen)

    # asexec prereg
    pr = sub.add_parser("prereg", help="sign a pre-registration before a run")
    pr.add_argument("--key", required=True, type=_nonempty_arg, help="key that signs the prereg")
    _add_arg_or_file(
        pr,
        "target",
        required=True,
        help="plain-text target details (what you commit to run)",
        file_help="structured JSON target details",
    )
    pr.add_argument(
        "--due",
        type=_due_arg,
        help="disclosure deadline, ISO-8601 with an explicit offset or Z "
        "(optional; e.g. 2026-08-30T00:00:00Z)",
    )
    _add_arg_or_file(
        pr,
        "declaration",
        help="plain-language commitment text",
        file_help="structured JSON declaration",
    )
    pr.add_argument(
        "--subject",
        nargs="+",
        type=_nonempty_arg,
        help="file(s) to hash, each named by its path relative to the current directory "
        "(no directories; verify finds them under --artifacts; optional at prereg time)",
    )
    pr.add_argument(
        "--hash-alg",
        default=SUBJECT_DEFAULT_HASH_ALG,
        choices=hashing.available_algorithms(),
        help="algorithm each hashed file's entry names (default: %(default)s)",
    )
    _add_arg_or_file(
        pr,
        "notes",
        help="free-form context (hypothesis/methodology)",
        file_help="structured JSON notes",
    )
    _add_arg_or_file(
        pr,
        "plan",
        help='the plan the claim is tested against, as JSON: {"name": <file path>, '
        '"media_type": ..., "label": ...}; asexec hashes the file (--hash-alg)',
        file_help="the --plan JSON, from a file",
        type=_json_arg(_plan_shape, _FILE_DEPTH),
    )
    _add_arg_or_file(
        pr,
        "items",
        help='what the claim commits to deliver, as a JSON array: [{"id": "S1", "kind": '
        '"run"}, ...]; ids must be unique, and each is accounted for by a postreg\'s --item-id',
        file_help="the --items JSON array, from a file",
        type=_json_arg(_items_shape, _FILE_DEPTH),
    )
    _add_anchor_flags(pr)
    pr.add_argument("--out", type=_nonempty_arg, default="preregistration.json")
    pr.set_defaults(func=cmd_prereg)

    # asexec postreg
    po = sub.add_parser("postreg", help="sign a post-registration after a run")
    po.add_argument("--key", required=True, type=_nonempty_arg)
    po.add_argument(
        "--fulfills",
        required=True,
        type=_nonempty_arg,
        help="pre-registration file, or a literal sha-256:<64 hex> ref, this fulfils",
    )
    _add_arg_or_file(po, "target", help="override target (default: inherit from prereg)")
    po.add_argument(
        "--due",
        type=_due_arg,
        help="override disclosure deadline, ISO-8601 with an explicit offset or Z "
        "(default: inherit from prereg)",
    )
    _add_arg_or_file(po, "declaration")
    po.add_argument(
        "--subject",
        nargs="+",
        type=_nonempty_arg,
        help="file(s) to hash (outputs, transcript, harness files), each named by its path "
        "relative to the current directory (no directories)",
    )
    po.add_argument(
        "--hash-alg",
        default=SUBJECT_DEFAULT_HASH_ALG,
        choices=hashing.available_algorithms(),
        help="algorithm each hashed file's entry names (default: %(default)s)",
    )
    po.add_argument(
        "--prev",
        type=_nonempty_arg,
        help="prior postreg file (or sha-256:<64 hex> ref) in this commitment's chain",
    )
    po.add_argument("--provenance", choices=["asserted", "reproducible"], default="asserted")
    po.add_argument(
        "--repro-recipe",
        type=_json_arg(_repro_recipe_shape, _IN_BODY_DEPTH),
        help="JSON: {seed, decode, runtime} if provenance=reproducible",
    )
    _add_arg_or_file(po, "notes")
    po.add_argument(
        "--item-id",
        type=_nonempty_arg,
        help="the id of the prereg's item this postreg accounts for",
    )
    po.add_argument(
        "--status",
        choices=STATUSES,
        help="what happened to the item: " + " | ".join(STATUSES),
    )
    _add_arg_or_file(
        po,
        "evidence",
        help='files that back this postreg, as a JSON array: [{"name": <file path>, '
        '"media_type": ..., "uri": ...}, ...]; asexec hashes each file (--hash-alg)',
        file_help="the --evidence JSON array, from a file",
        type=_json_arg(_evidence_shape, _FILE_DEPTH),
    )
    _add_anchor_flags(po)
    po.add_argument("--out", type=_nonempty_arg, default="postregistration.json")
    po.set_defaults(func=cmd_postreg)

    # asexec verify
    vy = sub.add_parser("verify", help="verify manifests offline; produce a canonical verify code")
    vy.add_argument(
        "paths", nargs="+", type=_nonempty_arg, help="manifest file(s) or a directory of them"
    )
    vy.add_argument(
        "--tests",
        required=True,
        type=_tests_arg,
        help="comma-separated tests to run (MUST include "
        f"{' and '.join(repr(t) for t in sorted(verifier.REQUIRED_TESTS))}). "
        f"available: {', '.join(verifier.TEST_CATALOG)}",
    )
    vy.add_argument(
        "--artifacts",
        type=_nonempty_arg,
        help="directory of original artifacts, to check content hashes",
    )
    vy.set_defaults(func=cmd_verify)

    # asexec identity
    idp = sub.add_parser("identity", help="key<->domain binding via .well-known (no CA)")
    isub = idp.add_subparsers(dest="identity_cmd", required=True)
    ie = isub.add_parser("emit", help="write a .well-known/asexec.json for your key")
    ie.add_argument("--key", required=True, type=_nonempty_arg)
    ie.add_argument("--domain", type=_domain_arg)
    ie.add_argument("--out", type=_nonempty_arg, default="asexec.json")
    ie.set_defaults(func=cmd_identity)
    iv = isub.add_parser(
        "match", help="check a key matches that which is asserted by a domain (network)"
    )
    iv.add_argument("--domain", required=True, type=_domain_arg)
    which = iv.add_mutually_exclusive_group(required=True)  # exactly one key to look for
    which.add_argument("--keyid", type=_nonempty_arg)
    which.add_argument("--pubkey", type=_nonempty_arg)
    which.add_argument("--key", type=_nonempty_arg, help="a key file, to derive the keyid")
    iv.set_defaults(func=cmd_identity)

    return p


# --------------------------------------------------------------------------- #
# stdout: what writing the output can do
# --------------------------------------------------------------------------- #
class _StdoutError(Exception):
    """Writing stdout failed: its reader closed it (``BrokenPipeError``), or the device is
    full. Not an ``OSError``, so it is never taken for an input file's error."""

    def __init__(self, error: OSError):
        super().__init__(str(error))
        self.error = error


class _GuardedStdout:
    """stdout, whose write and flush failures raise ``_StdoutError``."""

    def __init__(self, stream):
        self._stream = stream

    def write(self, text: str) -> int:
        try:
            return self._stream.write(text)
        except OSError as e:
            raise _StdoutError(e) from None

    def flush(self) -> None:
        try:
            self._stream.flush()
        except OSError as e:
            raise _StdoutError(e) from None

    def __getattr__(self, name: str):
        return getattr(self._stream, name)


def _flush_stdout() -> None:
    if sys.stdout is not None:  # None: started with stdout closed (``>&-``)
        sys.stdout.flush()


def _drop_stdout() -> None:
    """Point stdout at the null device once it can't be written, so no later write, nor
    Python's flush at exit, fails again (which would print to stderr and exit 120)."""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        os.close(devnull)
    except (OSError, ValueError, AttributeError):  # no file descriptor behind stdout
        pass


def _escape_unencodable(stream) -> None:
    """Show a character the stream's encoding lacks as its escape (``\u2713``), not a
    ``UnicodeEncodeError`` (``PYTHONIOENCODING=ascii``, say)."""
    try:
        stream.reconfigure(errors="backslashreplace")
    except (AttributeError, ValueError, OSError):  # None, or not a reconfigurable stream
        pass


def main(argv: list[str] | None = None) -> int:
    stdout = sys.stdout
    _escape_unencodable(sys.stdout)
    _escape_unencodable(sys.stderr)
    if stdout is not None:
        sys.stdout = _GuardedStdout(stdout)
    try:
        try:
            status = _run(argv)
        except SystemExit:  # a usage error, --help, or an error message: flush what is printed
            _flush_finished_output()
            raise
        _flush_stdout()  # what is still buffered, before the exit status is returned
        return status
    except _StdoutError as e:
        _drop_stdout()
        if isinstance(e.error, BrokenPipeError):  # closed while the command still printed
            sys.stderr.write("error: stdout was closed before the command finished\n")
        else:
            sys.stderr.write(f"error: could not write the output: {e.error}\n")
        return EXIT_ERROR
    finally:
        sys.stdout = stdout


def _run(argv: list[str] | None) -> int:
    args = build_parser().parse_args(argv)
    try:
        status = args.func(args)
    except (AsexecError, OSError) as e:
        # an input the arguments name could not be used (missing or bad key file, failed
        # fetch, ...): a message, not a traceback. verify turns these into FAILs itself.
        sys.stderr.write(f"error: {e}\n")
        return EXIT_ERROR
    _flush_finished_output()
    return status


def _flush_finished_output() -> None:
    """Flush what a finished command (or argparse, exiting) printed. If the reader has gone,
    the status stands: stdout is dropped. Any other failure raises ``_StdoutError``."""
    try:
        _flush_stdout()
    except _StdoutError as e:
        if not isinstance(e.error, BrokenPipeError):
            raise
        _drop_stdout()
