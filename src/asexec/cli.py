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
import sys
import uuid
from collections.abc import Callable
from datetime import datetime

from pydantic import ValidationError

from . import __version__, drand, hashing, identity, keys, manifest, verifier
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
def _load_json(path: str) -> str | dict:
    """Load JSON from the given path."""
    try:
        with open(path) as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise SystemExit(f"error: {path} must contain valid JSON: {e}") from e


def _get_arg_or_file[T](
    args,
    arg_name: str,
    file_arg_name: str,
    load_file: Callable[[str], T],
    parse_value: Callable[[str], T] | None = None,
) -> str | T | None:
    """Load a value from ``--<arg>`` or ``--<file-arg>`` (argparse allows at most one).

    ``parse_value``, if given, parses the inline ``--<arg>`` value into ``T`` (for example
    ``json.loads``), as ``load_file`` reads the file. A ``ValueError`` from it is a usage
    error: only the argument is wrong, so it exits ``EXIT_USAGE`` and nothing runs."""
    value = getattr(args, arg_name, None)
    file_path = getattr(args, file_arg_name, None)
    if value:
        if parse_value is None:
            return value
        try:
            return parse_value(value)
        except ValueError as e:
            flag = "--" + arg_name.replace("_", "-")
            sys.stderr.write(f"asexec {args.cmd}: error: argument {flag}: not valid JSON: {e}\n")
            raise SystemExit(EXIT_USAGE) from None
    if file_path:
        try:
            return load_file(file_path)
        except FileNotFoundError:
            raise SystemExit(
                f"error: --{file_arg_name.replace('_', '-')} not found: {file_path}"
            ) from None
    return None


def _get_target(args) -> str | dict | None:
    """Retrieve the target value (from arg xor file), if any."""
    return _get_arg_or_file(args, "target", "target_file", _load_json)


def _get_declaration(args) -> str | dict | None:
    """Retrieve the declaration value (from arg xor file), if any."""
    return _get_arg_or_file(args, "declaration", "declaration_file", _load_json)


def _get_notes(args) -> str | dict | None:
    """Retrieve the notes value (from arg xor file), if any."""
    return _get_arg_or_file(args, "notes", "notes_file", _load_json)


# What a --plan / --evidence entry may say. asexec hashes the file at ``name`` and fills in
# ``hash_alg`` (--hash-alg) and ``digest``, as --subject does; the rest is declared, never
# tested.
_PLAN_FIELDS = ("name", "media_type", "label")
_EVIDENCE_FIELDS = ("name", "media_type", "uri")


def _described_entries(specs: list, flag: str, allowed: tuple[str, ...], alg: str) -> list[dict]:
    """Entries for files described as ``{"name": <path>, ...}``: each file hashed as a
    subject file is (``hashing.build_entries``), with its declared fields kept."""
    for spec in specs:
        if not isinstance(spec, dict) or not isinstance(spec.get("name"), str):
            raise ManifestError(f"{flag} needs a 'name' (a file path) in each entry: {spec!r}")
        if "hash_alg" in spec or "digest" in spec:
            raise ManifestError(
                f"{flag}: asexec hashes the file and fills in hash_alg and digest "
                "(choose the algorithm with --hash-alg)"
            )
        unknown = sorted(set(spec) - set(allowed))
        if unknown:
            raise ManifestError(
                f"{flag}: unknown field(s) {', '.join(map(repr, unknown))}; "
                f"an entry may hold {', '.join(map(repr, allowed))}"
            )
    entries = hashing.build_entries([spec["name"] for spec in specs], alg)
    return [
        {**entry, **{k: v for k, v in spec.items() if k != "name"}}
        for entry, spec in zip(entries, specs, strict=True)
    ]


def _get_plan(args) -> dict | None:
    """``body.plan`` from --plan / --plan-file: one described file."""
    spec = _get_arg_or_file(args, "plan", "plan_file", _load_json, json.loads)
    if spec is None:
        return None
    if not isinstance(spec, dict):
        raise ManifestError(f'--plan must be a JSON object, like {{"name": "plan.md"}}: {spec!r}')
    if "name" not in spec:
        raise ManifestError("--plan needs a 'name': the plan document's path")
    return _described_entries([spec], "--plan", _PLAN_FIELDS, args.hash_alg)[0]


def _get_items(args) -> list | None:
    """``body.items`` from --items / --items-file: a list of ``{"id", "kind"}``, as given."""
    items = _get_arg_or_file(args, "items", "items_file", _load_json, json.loads)
    if items is not None and not isinstance(items, list):
        raise ManifestError(f'--items must be a JSON array, like [{{"id": "S1"}}]: {items!r}')
    return items


def _get_evidence(args) -> list | None:
    """``body.evidence`` from --evidence / --evidence-file: a non-empty list of described
    files."""
    specs = _get_arg_or_file(args, "evidence", "evidence_file", _load_json, json.loads)
    if specs is None:
        return None
    if not isinstance(specs, list):
        raise ManifestError(
            f'--evidence must be a JSON array, like [{{"name": "out.json"}}]: {specs!r}'
        )
    if not specs:
        raise ManifestError("--evidence must list at least one file")
    return _described_entries(specs, "--evidence", _EVIDENCE_FIELDS, args.hash_alg)


def _built(build: Callable[..., dict], *args, **kwargs) -> dict:
    """A body from ``manifest.build_*``; what its writer model refuses is a clean error."""
    try:
        return build(*args, **kwargs)
    except ValidationError as e:
        raise ManifestError(
            "; ".join(f"{'.'.join(map(str, x['loc'])) or 'body'}: {x['msg']}" for x in e.errors())
        ) from None


def _get_floor(args) -> dict | None:
    """Fetch a drand freshness floor (anchor.floor) at sign time, or None."""
    if not args.floor:
        return None
    try:
        return drand.fetch_floor()
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
        raise SystemExit(f"error: {flag} {path} is not a readable manifest: {e}") from e


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


def _show(text: str = "") -> None:
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
            f"error: {e.filename} already exists; refusing to overwrite a key "
            "(pass --force to replace it - the old key is lost)"
        ) from None
    print(f"{OK} generated ed25519 key")
    print(f"  secret : {out} (keep private; mode 0600)")
    print(f"  public : {out}.pub")
    print(f"  keyid  : {kid}")
    return EXIT_OK


def cmd_prereg(args) -> int:
    """Write a signed pre-registration, signalling the intended execution."""
    target = _get_target(args)
    if target is None:  # argparse requires one; only a file holding null gets here
        raise SystemExit(f"error: --target-file {args.target_file!r} holds no target")
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

    fulfills = _resolve_ref(args.fulfills, "--fulfills")
    prev_hash = _resolve_ref(args.prev, "--prev") if args.prev else None
    prereg_body = None  # the decoded body of the prereg file, to inherit from
    if os.path.isfile(args.fulfills):
        prereg_body = _load_manifest_body(args.fulfills, "--fulfills")[1]

    # target / due / declaration inherit from the fulfilled prereg unless overridden on this
    # postreg. Each subject entry names its own hash_alg: --hash-alg, or the default.
    target = _get_target(args)
    if target is None:
        if prereg_body is None:
            raise SystemExit("error: no --target and --fulfills is not a readable prereg")
        target = prereg_body["target"]

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
    ``_tests_arg``)."""
    report = verifier.verify_paths(args.paths, args.tests, artifacts_dir=args.artifacts)

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
        if c["state"] == "invalid-due":
            _show(f"    {NO} due is not a parseable ISO-8601 timestamp")
        _show(
            f"    postregs     : {len(c['counted_postregs'])}"
            + ("" if c["chain_ok"] else f"  {NO} {c['chain_note']}")
        )
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
    return EXIT_OK if report["ok"] else EXIT_FAIL


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
    p.add_argument(
        "--floor",
        action="store_true",
        help="attach a drand freshness floor (proves created no earlier than T; network). "
        "Fails if the fetch fails, unless --best-effort",
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
    """``--due``: an ISO-8601 deadline, returned verbatim.

    An explicit UTC offset (or ``Z``) is required: a timezone-less deadline
    would mean different instants to verifiers in different timezones.
    """
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a valid ISO-8601 timestamp: {value!r}") from None
    if parsed.tzinfo is None:
        raise argparse.ArgumentTypeError(
            "needs an explicit UTC offset or 'Z' "
            f"(e.g. 2026-08-30T00:00:00Z or 2026-08-30T00:00:00+02:00): {value!r}"
        )
    return value


def _nonempty_arg(value: str) -> str:
    if not value:
        raise argparse.ArgumentTypeError("must not be empty")
    return value


def _json_arg(value: str):
    try:
        return json.loads(value)
    except json.JSONDecodeError as e:
        raise argparse.ArgumentTypeError(f"not valid JSON: {e}") from None


def _add_arg_or_file(p, name: str, required: bool = False, help=None, file_help=None, **kw):
    """``--<name>`` and ``--<name>-file``: at most one (exactly one if ``required``)."""
    group = p.add_mutually_exclusive_group(required=required)
    group.add_argument(f"--{name}", help=help, **kw)
    group.add_argument(f"--{name}-file", help=file_help)


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
    kg.add_argument("--out", default=None, help="secret key file (default: asexec-<uuid>.key)")
    kg.add_argument(
        "--force", action="store_true", help="overwrite an existing key file (the old key is lost)"
    )
    kg.set_defaults(func=cmd_keygen)

    # asexec prereg
    pr = sub.add_parser("prereg", help="sign a pre-registration before a run")
    pr.add_argument("--key", required=True, help="key that signs the prereg")
    _add_arg_or_file(
        pr,
        "target",
        required=True,
        type=_nonempty_arg,
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
    )
    _add_arg_or_file(
        pr,
        "items",
        help='what the claim commits to deliver, as a JSON array: [{"id": "S1", "kind": '
        '"run"}, ...]; ids must be unique, and each is accounted for by a postreg\'s --item-id',
        file_help="the --items JSON array, from a file",
    )
    _add_anchor_flags(pr)
    pr.add_argument("--out", default="preregistration.json")
    pr.set_defaults(func=cmd_prereg)

    # asexec postreg
    po = sub.add_parser("postreg", help="sign a post-registration after a run")
    po.add_argument("--key", required=True)
    po.add_argument(
        "--fulfills",
        required=True,
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
        help="prior postreg file (or sha-256:<64 hex> ref) in this commitment's chain",
    )
    po.add_argument("--provenance", choices=["asserted", "reproducible"], default="asserted")
    po.add_argument(
        "--repro-recipe",
        type=_json_arg,
        help="JSON: {seed, decode, runtime} if provenance=reproducible",
    )
    _add_arg_or_file(po, "notes")
    po.add_argument("--item-id", help="the id of the prereg's item this postreg accounts for")
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
    )
    _add_anchor_flags(po)
    po.add_argument("--out", default="postregistration.json")
    po.set_defaults(func=cmd_postreg)

    # asexec verify
    vy = sub.add_parser("verify", help="verify manifests offline; produce a canonical verify code")
    vy.add_argument("paths", nargs="+", help="manifest file(s) or a directory of them")
    vy.add_argument(
        "--tests",
        required=True,
        type=_tests_arg,
        help="comma-separated tests to run (MUST include "
        f"{' and '.join(repr(t) for t in sorted(verifier.REQUIRED_TESTS))}). "
        f"available: {', '.join(verifier.TEST_CATALOG)}",
    )
    vy.add_argument("--artifacts", help="directory of original artifacts, to check content hashes")
    vy.set_defaults(func=cmd_verify)

    # asexec identity
    idp = sub.add_parser("identity", help="key<->domain binding via .well-known (no CA)")
    isub = idp.add_subparsers(dest="identity_cmd", required=True)
    ie = isub.add_parser("emit", help="write a .well-known/asexec.json for your key")
    ie.add_argument("--key", required=True)
    ie.add_argument("--domain")
    ie.add_argument("--out", default="asexec.json")
    ie.set_defaults(func=cmd_identity)
    iv = isub.add_parser(
        "match", help="check a key matches that which is asserted by a domain (network)"
    )
    iv.add_argument("--domain", required=True)
    which = iv.add_mutually_exclusive_group(required=True)  # exactly one key to look for
    which.add_argument("--keyid")
    which.add_argument("--pubkey")
    which.add_argument("--key", help="a key file, to derive the keyid")
    iv.set_defaults(func=cmd_identity)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (AsexecError, OSError) as e:
        # an input the arguments name could not be used (missing or bad key file, failed
        # fetch, ...): a message, not a traceback. verify turns these into FAILs itself.
        sys.stderr.write(f"error: {e}\n")
        return EXIT_ERROR
