"""asexec command-line interface.

Commands: keygen · preregister · seal · verify · identity.

Design boundaries (from the plan): files-first (optional ``--commit`` for git
convenience, commit only, never push); ``verify`` is fully offline; only the
sign-time drand fetch and ``identity verify`` touch the network.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from typing import List, Optional

from . import __version__, drand, hashing, identity, keys, manifest, verifier
from .errors import VerificationError

OK = "✓"
NO = "✗"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _target_identity(args) -> dict:
    if args.target_weights:
        alg = args.hash_alg
        return {"kind": "weights",
                "digest": {alg: hashing.digest_path(args.target_weights, alg)}}
    if args.target_provider or args.target_model:
        return {"kind": "api", "provider": args.target_provider or "",
                "model_id": args.target_model or "", "endpoint": args.target_endpoint or ""}
    raise SystemExit("error: give --target-weights PATH or --target-provider/--target-model")


def _disclosure_window(args) -> dict:
    win = {"closes": args.window}
    if args.declares:
        win["declares"] = args.declares
    return win


def _floor(no_drand: bool) -> Optional[dict]:
    """Fetch a drand freshness floor (anchor.floor) at sign time, or None."""
    if no_drand:
        return None
    try:
        return drand.fetch_floor()
    except Exception as e:
        sys.stderr.write(f"warning: drand fetch failed ({e}); continuing without freshness floor\n")
        return None


def _attach_ceiling(mani: dict, body: dict, want_ceiling: bool) -> None:
    """Optionally fetch a Roughtime ceiling witness and attach it to the envelope.

    Sign-time and network-touching (like the drand fetch). The nonce is the
    body ref, so this must run *after* signing; it does not perturb ref.
    """
    if not want_ceiling:
        return
    from . import roughtime

    nonce = manifest.ref(body)  # sha-256:<hex>
    try:
        ceiling = roughtime.fetch_ceiling(nonce)
    except Exception as e:
        sys.stderr.write(f"warning: ceiling witness fetch failed ({e}); continuing without a ceiling\n")
        return
    manifest.attach_ceiling(mani, ceiling)
    print(f"  ceiling : {ceiling.get('ceiling_type')} witness {ceiling.get('witness_id')} "
          f"@ {ceiling.get('midpoint')} (±{ceiling.get('radius')}s)")


def _subject(args, hash_alg: str) -> Optional[list]:
    return hashing.build_subject(args.subject, hash_alg) if args.subject else None


def _notes(args) -> Optional[dict]:
    return {"text": args.notes} if getattr(args, "notes", None) else None


def _git_commit(path: str, message: str) -> None:
    try:
        subprocess.run(["git", "add", path], check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", message], check=True, capture_output=True)
        print(f"  committed {path}")
    except Exception as e:
        sys.stderr.write(f"warning: --commit failed ({e})\n")


def _resolve_ref(value: str) -> str:
    """A --fulfills/--prev value may be a manifest file path or a literal ref."""
    import os

    if os.path.isfile(value):
        return manifest.ref(manifest.get_body(manifest.load(value)))
    return value


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #
def cmd_keygen(args) -> int:
    priv, pub = keys.generate()
    kid = keys.save(priv, args.out)
    print(f"{OK} generated ed25519 key")
    print(f"  secret : {args.out} (keep private; mode 0600)")
    print(f"  public : {args.out}.pub")
    print(f"  keyid  : {kid}")
    return 0


def cmd_preregister(args) -> int:
    priv, pub = keys.load_signing_key(args.key)
    body = manifest.build_preregistration(
        _target_identity(args), _disclosure_window(args),
        subject=_subject(args, args.hash_alg), hash_alg=args.hash_alg,
        floor=_floor(args.no_drand), notes=_notes(args),
    )
    mani = manifest.sign(body, priv, pub)
    _attach_ceiling(mani, body, args.ceiling)
    manifest.save(mani, args.out)
    print(f"{OK} pre-registration written: {args.out}")
    print(f"  ref   : {manifest.ref(body)}")
    print(f"  closes: {body['disclosure_window'].get('closes')}")
    if args.commit:
        _git_commit(args.out, f"asexec: pre-register {manifest.ref(body)}")
    return 0


def cmd_seal(args) -> int:
    priv, pub = keys.load_signing_key(args.key)
    # Inherit target_identity / window / hash_alg from the fulfilled prereg if it's a file.
    import os

    prereg_body = None
    if os.path.isfile(args.fulfills):
        prereg_body = manifest.get_body(manifest.load(args.fulfills))
    hash_alg = args.hash_alg or (prereg_body or {}).get("hash_alg") or hashing.DEFAULT_ALG

    if args.target_weights or args.target_provider or args.target_model:
        target = _target_identity(argparse.Namespace(**{**vars(args), "hash_alg": hash_alg}))
    elif prereg_body:
        target = prereg_body["target_identity"]
    else:
        raise SystemExit("error: no target identity and --fulfills is not a readable prereg")

    if args.window:
        window = _disclosure_window(args)
    elif prereg_body:
        window = prereg_body["disclosure_window"]
    else:
        raise SystemExit("error: no --window and --fulfills is not a readable prereg")

    subject = hashing.build_subject(args.subject, hash_alg)
    body = manifest.build_receipt(
        target, window,
        fulfills=_resolve_ref(args.fulfills),
        subject=subject, prev_hash=_resolve_ref(args.prev) if args.prev else None,
        hash_alg=hash_alg, floor=_floor(args.no_drand),
        provenance=args.provenance, notes=_notes(args),
        repro_recipe=json.loads(args.repro_recipe) if args.repro_recipe else None,
    )
    mani = manifest.sign(body, priv, pub)
    _attach_ceiling(mani, body, args.ceiling)
    manifest.save(mani, args.out)
    print(f"{OK} receipt written: {args.out}")
    print(f"  ref     : {manifest.ref(body)}")
    print(f"  fulfills: {body['fulfills']}")
    if body.get("prev_hash"):
        print(f"  prev    : {body['prev_hash']}")
    if args.commit:
        _git_commit(args.out, f"asexec: seal receipt {manifest.ref(body)}")
    return 0


def cmd_verify(args) -> int:
    try:
        tests = verifier.parse_tests(args.tests)
    except VerificationError as e:
        raise SystemExit(f"error: {e}")

    now = None
    if args.now:
        now = verifier._parse_iso(args.now)
    report = verifier.verify_paths(args.paths, tests, artifacts_dir=args.artifacts, now=now)

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
        print(f"    window closes : {c['window'].get('closes')}")
        print(f"    receipts      : {len(c['receipts'])}"
              + ("" if c["chain_ok"] else f"  {NO} {c['chain_note']}"))
        if not c["key_consistent"]:
            print(f"    {NO} receipts signed by a different key than the pre-registration")
    if report["notarization_only"]:
        print("\n=== notarization-only (receipts with no matching pre-registration) ===")
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
def _add_target_flags(p):
    p.add_argument("--target-weights", help="path to local/open model weights (strong identity)")
    p.add_argument("--target-provider", help="API model provider (weak identity)")
    p.add_argument("--target-model", help="API model id/version")
    p.add_argument("--target-endpoint", help="API endpoint")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="asexec",
        description="Pre-registration & notarization primitive for AI evaluations. "
                    "Does NOT prove identity, eval quality, provenance, or cryptographic "
                    "'pre' (see 'verify' output).",
    )
    p.add_argument("--version", action="version", version=f"asexec {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("keygen", help="generate an ed25519 keypair (no CA)")
    g.add_argument("--out", default="asexec.key", help="secret key file (default: asexec.key)")
    g.set_defaults(func=cmd_keygen)

    pr = sub.add_parser("preregister", help="sign a pre-registration before a run")
    pr.add_argument("--key", required=True)
    pr.add_argument("--subject", nargs="+", help="path(s) to harness/eval to hash (optional at prereg time)")
    pr.add_argument("--window", required=True, help="disclosure deadline, ISO-8601 (e.g. 2026-08-30T00:00:00Z)")
    pr.add_argument("--declares", help="plain-language commitment text")
    _add_target_flags(pr)
    pr.add_argument("--hash-alg", default=hashing.DEFAULT_ALG, choices=hashing.available_algorithms())
    pr.add_argument("--no-drand", action="store_true", help="omit the drand freshness floor")
    pr.add_argument("--ceiling", action="store_true",
                    help="attach a Roughtime ceiling witness (proves created no later than T; network)")
    pr.add_argument("--notes", help="free-form context (hypothesis/methodology)")
    pr.add_argument("--out", default="preregistration.json")
    pr.add_argument("--commit", action="store_true", help="git add+commit the file (no push)")
    pr.set_defaults(func=cmd_preregister)

    sl = sub.add_parser("seal", help="sign a receipt after a run")
    sl.add_argument("--key", required=True)
    sl.add_argument("--fulfills", required=True, help="pre-registration file (or literal ref) this fulfils")
    sl.add_argument("--subject", nargs="+", required=True, help="path(s) to outputs/transcript/harness to hash")
    sl.add_argument("--prev", help="prior receipt file (or ref) in this commitment's chain")
    sl.add_argument("--window", help="override disclosure window (default: inherit from prereg)")
    sl.add_argument("--declares")
    _add_target_flags(sl)
    sl.add_argument("--hash-alg", default=None, choices=hashing.available_algorithms())
    sl.add_argument("--no-drand", action="store_true")
    sl.add_argument("--ceiling", action="store_true",
                    help="attach a Roughtime ceiling witness (proves created no later than T; network)")
    sl.add_argument("--provenance", choices=["asserted", "reproducible"], default="asserted")
    sl.add_argument("--repro-recipe", help="JSON: {seed, decode, runtime} if provenance=reproducible")
    sl.add_argument("--notes")
    sl.add_argument("--out", default="receipt.json")
    sl.add_argument("--commit", action="store_true")
    sl.set_defaults(func=cmd_seal)

    v = sub.add_parser("verify", help="verify manifests offline; emit a canonical verify code")
    v.add_argument("paths", nargs="+", help="manifest file(s) or a directory of them")
    v.add_argument("--tests", required=True,
                   help="comma-separated tests to run (MUST include 'bedrock'). "
                        f"available: {', '.join(verifier.TEST_CATALOG)}")
    v.add_argument("--artifacts", help="directory of original artifacts, to check content hashes")
    v.add_argument("--now", help="override 'now' (ISO-8601) for window evaluation (testing)")
    v.set_defaults(func=cmd_verify)

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
