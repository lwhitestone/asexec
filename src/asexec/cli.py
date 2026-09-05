"""asexec command-line interface.

Commands: keygen · prereg · postreg · verify · identity.

Design boundaries: files-first; ``verify`` is fully offline; only the sign-time
drand (``--drand``) / ceiling (``--ceiling``) fetches and ``identity verify``
touch the network.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from datetime import datetime
from typing import Any, Callable, List, Optional, TypeVar, Union

from . import __version__, drand, hashing, identity, keys, manifest, verifier
from .errors import VerificationError

OK = "✓"
NO = "✗"
T = TypeVar("T")


# --------------------------------------------------------------------------- #
# input helpers — one typed "arg XOR file" primitive, reused everywhere
# --------------------------------------------------------------------------- #
def _load_json(path: str) -> Union[str, dict]:
    try:
        with open(path) as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise SystemExit(f"error: {path} must contain valid JSON: {e}")


def _get_arg_or_file(args, arg_name: str, file_arg_name: str,
                     load_file: Callable[[str], T]) -> Optional[Union[str, T]]:
    """Load a value from either ``--<arg>`` or ``--<file-arg>``, but not both."""
    value = getattr(args, arg_name, None)
    file_path = getattr(args, file_arg_name, None)
    if value and file_path:
        raise SystemExit(
            f"error: provide --{arg_name.replace('_', '-')} "
            f"OR --{file_arg_name.replace('_', '-')}, not both")
    if value:
        return value
    if file_path:
        try:
            return load_file(file_path)
        except FileNotFoundError:
            raise SystemExit(
                f"error: --{file_arg_name.replace('_', '-')} not found: {file_path}")
    return None


def _get_target(args) -> Optional[Union[str, dict]]:
    return _get_arg_or_file(args, "target", "target_file", _load_json)


def _get_declaration(args) -> Optional[Union[str, dict]]:
    return _get_arg_or_file(args, "declaration", "declaration_file", _load_json)


def _get_notes(args) -> Optional[Union[str, dict]]:
    return _get_arg_or_file(args, "notes", "notes_file", _load_json)


def _get_due(args) -> Optional[str]:
    """Validate the provided ``--due`` ISO-8601 deadline; return it verbatim."""
    if not args.due:
        return None
    try:
        datetime.fromisoformat(args.due.replace("Z", "+00:00"))
    except ValueError:
        raise SystemExit(f"error: --due is not a valid ISO-8601 timestamp: {args.due}")
    return args.due


def _get_floor(args) -> Optional[dict]:
    """Fetch a drand freshness floor (anchor.floor) at sign time, or None."""
    if not args.drand:
        return None
    try:
        return drand.fetch_floor()
    except Exception as e:
        sys.stderr.write(
            f"warning: drand fetch failed ({e}); continuing without freshness floor\n")
        return None


def _build_subject(paths: Optional[List[str]], hash_alg: str) -> Optional[list]:
    return hashing.build_subject(paths, hash_alg) if paths else None


def _resolve_ref(value: str) -> str:
    """A --fulfills/--prev value may be a manifest file path or a literal ref."""
    if os.path.isfile(value):
        return manifest.ref(manifest.get_body(manifest.load(value)))
    return value


def _attach_ceiling(mani: dict, body: dict, want_ceiling: bool) -> None:
    """Optionally fetch a Roughtime ceiling witness and attach it (sign-time,
    network). The nonce is the body ref, so this must run *after* signing; it
    does not perturb ref."""
    if not want_ceiling:
        return
    from . import roughtime

    nonce = manifest.ref(body)  # sha-256:<hex>
    try:
        ceiling = roughtime.fetch_ceiling(nonce)
    except Exception as e:
        sys.stderr.write(
            f"warning: ceiling witness fetch failed ({e}); continuing without a ceiling\n")
        return
    manifest.attach_ceiling(mani, ceiling)
    print(f"  ceiling : {ceiling.get('ceiling_type')} witness {ceiling.get('witness_id')} "
          f"@ {ceiling.get('midpoint')} (±{ceiling.get('radius')}s)")


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #
def cmd_keygen(args) -> int:
    out = args.out or f"asexec-{uuid.uuid4()}.key"
    priv, _pub = keys.generate()
    kid = keys.save(priv, out)
    print(f"{OK} generated ed25519 key")
    print(f"  secret : {out} (keep private; mode 0600)")
    print(f"  public : {out}.pub")
    print(f"  keyid  : {kid}")
    return 0


def cmd_prereg(args) -> int:
    target = _get_target(args)
    if target is None:
        raise SystemExit("error: give --target or --target-file (the only mandatory claim)")
    priv, pub = keys.load_signing_key(args.key)
    subject = _build_subject(args.subject, args.hash_alg)
    body = manifest.build_prereg(
        target,
        due=_get_due(args),
        declaration=_get_declaration(args),
        subject=subject, hash_alg=args.hash_alg,
        floor=_get_floor(args), notes=_get_notes(args),
    )
    mani = manifest.sign(body, priv, pub)
    _attach_ceiling(mani, body, args.ceiling)
    manifest.save(mani, args.out)
    print(f"{OK} pre-registration written: {args.out}")
    print(f"  ref : {manifest.ref(body)}")
    if body.get("due"):
        print(f"  due : {body['due']}")
    return 0


def cmd_postreg(args) -> int:
    priv, pub = keys.load_signing_key(args.key)

    prereg_body = None
    if os.path.isfile(args.fulfills):
        prereg_body = manifest.get_body(manifest.load(args.fulfills))

    # target / due / declaration / hash_alg inherit from the fulfilled prereg
    # unless overridden on this postreg.
    target = _get_target(args)
    if target is None:
        if prereg_body is None:
            raise SystemExit("error: no --target and --fulfills is not a readable prereg")
        target = prereg_body["target"]

    due = _get_due(args) or (prereg_body or {}).get("due")
    declaration = _get_declaration(args) or (prereg_body or {}).get("declaration")
    hash_alg = args.hash_alg or (prereg_body or {}).get("hash_alg") or hashing.DEFAULT_ALG

    subject = _build_subject(args.subject, hash_alg)
    body = manifest.build_postreg(
        target,
        fulfills=_resolve_ref(args.fulfills),
        due=due, declaration=declaration,
        subject=subject, hash_alg=hash_alg,
        prev_hash=_resolve_ref(args.prev) if args.prev else None,
        floor=_get_floor(args), notes=_get_notes(args),
        provenance=args.provenance,
        repro_recipe=json.loads(args.repro_recipe) if args.repro_recipe else None,
    )
    mani = manifest.sign(body, priv, pub)
    _attach_ceiling(mani, body, args.ceiling)
    manifest.save(mani, args.out)
    print(f"{OK} post-registration written: {args.out}")
    print(f"  ref      : {manifest.ref(body)}")
    print(f"  fulfills : {body['fulfills']}")
    if body.get("prev_hash"):
        print(f"  prev     : {body['prev_hash']}")
    return 0


def cmd_verify(args) -> int:
    try:
        tests = verifier.parse_tests(args.tests)
    except VerificationError as e:
        raise SystemExit(f"error: {e}")

    report = verifier.verify_paths(args.paths, tests, artifacts_dir=args.artifacts)

    print("=== manifests ===")
    for m in report["manifests"]:
        sig = m["signature"]
        s = OK if (sig.get("signature_ok") and sig.get("keyid_ok")) else NO
        print(f"{s} {m['path']}  [{m.get('phase')}]  keyid={m.get('keyid')}")
        fl = m["floor"]
        if fl["status"] != "absent":
            fs = OK if fl["status"] == "verified" else NO
            extra = (f" (created no earlier than {fl.get('created_no_earlier_than')})"
                     if fl["status"] == "verified" else "")
            print(f"    {fs} drand freshness floor round {fl.get('round','?')}{extra}")
        cl = m["ceiling"]
        if cl["status"] != "absent":
            cs = OK if cl["status"] == "verified" else NO
            extra = (f" (created no later than {cl.get('midpoint')} ±{cl.get('radius')}s, "
                     f"witness {cl.get('witness_id')})" if cl["status"] == "verified"
                     else f" ({cl.get('error', cl['status'])})")
            print(f"    {cs} ceiling witness{extra}")
        c = m["content"]
        if c["status"] not in ("skipped",):
            cs = OK if c["status"] == "ok" else NO
            print(f"    {cs} content hashes {c['status']}")
            for e in c.get("entries", []):
                if not e["ok"]:
                    print(f"        {NO} {e['name']}: {e.get('reason','digest mismatch')}")

    print("\n=== commitments ===")
    if not report["commitments"]:
        print("  (no pre-registrations among the provided manifests)")
    for c in report["commitments"]:
        print(f"  [{c['state'].upper()}] prereg {c['ref']}")
        print(f"    due          : {c.get('due') or '(none declared)'}")
        print(f"    postregs     : {len(c['receipts'])}"
              + ("" if c["chain_ok"] else f"  {NO} {c['chain_note']}"))
        if not c["key_consistent"]:
            print(f"    {NO} postregs signed by a different key than the pre-registration")
    if report["notarization_only"]:
        print("\n=== notarization-only (postregs with no matching pre-registration) ===")
        for n in report["notarization_only"]:
            print(f"  {n['ref']}  (fulfills {n.get('fulfills')})")

    print("\n=== tests ===")
    for t in report["tests"]:
        r = report["results"][t]
        s = OK if r["result"] == "PASS" else NO
        print(f"  {s} {t}={r['result']}  ({r['reason']})")

    if report["ceiling_trust"]:
        print("\n=== ceiling trust (what you are accepting) ===")
        for line in report["ceiling_trust"]:
            print(f"  - {line}")

    print("\n=== what this does NOT prove ===")
    for nc in report["non_claims"]:
        print(f"  - {nc}")

    print(f"\n{report['code']}")
    print(f"DISCLAIMER: {report['disclaimer']}")
    return 0 if report["ok"] else 2


def cmd_identity(args) -> int:
    if args.identity_cmd == "emit":
        _priv, pub = keys.load_signing_key(args.key)
        pair = {"keyid": keys.keyid_for(pub), "pubkey": pub.hex()}
        doc = identity.build_wellknown([pair], domain=args.domain)
        identity.write_wellknown(doc, args.out)
        print(f"{OK} wrote {args.out}")
        print(f"  publish at: https://<your-domain>/.well-known/asexec.json")
        print(f"  keyid     : {pair['keyid']}")
        return 0
    if args.identity_cmd == "verify":
        keyid = args.keyid
        pubkey = args.pubkey
        if args.key:
            _priv, pub = keys.load_signing_key(args.key)
            keyid = keys.keyid_for(pub)
        res = identity.verify_binding(args.domain, keyid=keyid, pubkey_hex=pubkey)
        s = OK if res["bound"] else NO
        print(f"{s} key {'IS' if res['bound'] else 'is NOT'} asserted by {args.domain} "
              f"({res['listed_count']} key(s) listed)")
        print(f"  caveat: {res['caveat']}")
        return 0 if res["bound"] else 2
    raise SystemExit("error: use 'identity emit' or 'identity verify'")


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def _add_anchor_flags(p):
    p.add_argument("--drand", action="store_true",
                   help="attach a drand freshness floor (proves created no earlier than T; network)")
    p.add_argument("--ceiling", action="store_true",
                   help="attach a Roughtime ceiling witness (proves created no later than T; network)")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="asexec",
        description="Pre-registration & notarization primitive for AI evaluations. "
                    "Does NOT prove identity, eval quality, provenance, or cryptographic "
                    "'pre' (see 'verify' output).",
    )
    p.add_argument("--version", action="version", version=f"asexec {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    # asexec keygen
    kg = sub.add_parser("keygen", help="generate an ed25519 keypair (no CA)")
    kg.add_argument("--out", default=None,
                    help="secret key file (default: asexec-<uuid>.key)")
    kg.set_defaults(func=cmd_keygen)

    # asexec prereg
    pr = sub.add_parser("prereg", help="sign a pre-registration before a run")
    pr.add_argument("--key", required=True, help="key that signs the prereg")
    pr.add_argument("--target", help="plain-text target details (what you commit to run)")
    pr.add_argument("--target-file", help="structured JSON target details")
    pr.add_argument("--due", help="disclosure deadline, ISO-8601 (optional; e.g. 2026-08-30T00:00:00Z)")
    pr.add_argument("--declaration", help="plain-language commitment text")
    pr.add_argument("--declaration-file", help="structured JSON declaration")
    pr.add_argument("--subject", nargs="+",
                    help="path(s) to harness/eval to hash (optional at prereg time)")
    pr.add_argument("--hash-alg", default=hashing.DEFAULT_ALG,
                    choices=hashing.available_algorithms())
    pr.add_argument("--notes", help="free-form context (hypothesis/methodology)")
    pr.add_argument("--notes-file", help="structured JSON notes")
    _add_anchor_flags(pr)
    pr.add_argument("--out", default="preregistration.json")
    pr.set_defaults(func=cmd_prereg)

    # asexec postreg
    po = sub.add_parser("postreg", help="sign a post-registration (receipt) after a run")
    po.add_argument("--key", required=True)
    po.add_argument("--fulfills", required=True,
                    help="pre-registration file (or literal ref) this fulfils")
    po.add_argument("--target", help="override target (default: inherit from prereg)")
    po.add_argument("--target-file")
    po.add_argument("--due", help="override disclosure deadline (default: inherit from prereg)")
    po.add_argument("--declaration")
    po.add_argument("--declaration-file")
    po.add_argument("--subject", nargs="+",
                    help="path(s) to outputs/transcript/harness to hash")
    po.add_argument("--hash-alg", default=None, choices=hashing.available_algorithms())
    po.add_argument("--prev", help="prior postreg file (or ref) in this commitment's chain")
    po.add_argument("--provenance", choices=["asserted", "reproducible"], default="asserted")
    po.add_argument("--repro-recipe", help="JSON: {seed, decode, runtime} if provenance=reproducible")
    po.add_argument("--notes")
    po.add_argument("--notes-file")
    _add_anchor_flags(po)
    po.add_argument("--out", default="postregistration.json")
    po.set_defaults(func=cmd_postreg)

    # asexec verify
    vy = sub.add_parser("verify", help="verify manifests offline; emit a canonical verify code")
    vy.add_argument("paths", nargs="+", help="manifest file(s) or a directory of them")
    vy.add_argument("--tests", required=True,
                    help="comma-separated tests to run (MUST include 'BDR'). "
                         f"available: {', '.join(verifier.TEST_CATALOG)}")
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
    iv = isub.add_parser("verify", help="check a key is asserted by a domain (network)")
    iv.add_argument("--domain", required=True)
    iv.add_argument("--keyid")
    iv.add_argument("--pubkey")
    iv.add_argument("--key", help="a key file, to derive the keyid")
    iv.set_defaults(func=cmd_identity)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
