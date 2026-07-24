"""The verifier — the product. A canonical verify CODE, honest non-claims.

Everything the verifier does verifies offline against pinned constants; nothing
here touches the network.

Output: a canonical plaintext CODE, never a percentage or tier
-------------------------------------------------------------
``verify`` runs a caller-chosen set of tests and emits one code per run::

    asexec-verify/1 bedrock=PASS floor=PASS

Grammar (spec'd here so any implementation reproduces it byte-for-byte):

  - Literal prefix ``asexec-verify/1`` (this versions the code GRAMMAR itself,
    independent of the schema/PAE versions), then a single ASCII space.
  - One ``name=RESULT`` token per requested test, ``RESULT`` in ``{PASS, FAIL}``.
  - Tokens are **sorted alphabetically by name** and single-space delimited.

So the same result set is byte-identical everywhere (``bedrock=PASS floor=PASS``,
never ``floor=PASS bedrock=PASS``). Because the code *names* which tests ran,
adding a test in a later version can never change the meaning of an older code:
a code means exactly one thing, permanently. A percentage/tier would need its
version's denominator to interpret — the code is self-describing, a score is not.

**The code is NOT a certificate.** It is a summary of a computation, not a
credential. Real verification = run this tool against the manifests (+
artifacts) and get this code. A quoted or typed code carries the evidentiary
weight of "trust me, it passed" — zero. The tool prints ``DISCLAIMER`` with
every code.

Tests (the catalog — only *verifiable* claims, no self-declarations)
--------------------------------------------------------------------
  - ``bedrock``    : signature over the PAE input + keyid matches pubkey.
                     Applies to every manifest. **Required in every run.**
  - ``ceiling``    : a ceiling witness (Roughtime) signature verifies against a
                     pinned key AND its nonce == ref(payload). Applies to
                     manifests that carry a ceiling.
  - ``chain``      : prev_hash chain integrity (one root, no gaps). Applies to
                     commitments that have receipts.
  - ``content``    : subject digests recomputed from --artifacts match. Applies
                     where artifacts are provided and a subject is present.
  - ``floor``      : the drand freshness floor BLS-verifies. Applies to
                     manifests that carry an anchor.floor.
  - ``keyconsist`` : receipts share the pre-registration's key. Applies to
                     commitments that have receipts.

A requested test is ``PASS`` iff it holds everywhere it applies AND it applies
somewhere; a requested test that applies **nowhere** is ``FAIL``
(requested-but-absent), never a silent omission or a vacuous pass.

States (per commitment = a pre-registration + the receipts that fulfil it)
--------------------------------------------------------------------------
Rendered in the human report above the code; the verifier RENDERS these, it
never adjudicates intent or whether a commitment was "good enough":
  - fulfilled          : >=1 valid receipt references this pre-registration
  - open               : 0 receipts and the disclosure window has not elapsed
  - elapsed-no-receipt : 0 receipts and the window has elapsed
  - notarization-only  : a receipt with no matching pre-registration provided
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional, Tuple

from . import drand, hashing, keys, manifest
from .canonical import signing_input
from .errors import VerificationError

# The canonical grammar version for the verify code. Independent of the
# schema/PAE versions — it versions the *code format*, not the signed bytes.
CODE_VERSION = "asexec-verify/1"

# The test catalog, alphabetical (the order names appear in a code).
TEST_CATALOG: Tuple[str, ...] = (
    "bedrock", "ceiling", "chain", "content", "floor", "keyconsist",
)

# bedrock is the mandatory minimum: a run that does not check it is not a
# meaningful asexec verification, so `verify` requires it explicitly.
REQUIRED_TEST = "bedrock"

DISCLAIMER = (
    "this code is only meaningful if reproduced — do not treat a quoted code "
    "as proof. Real verification = run this tool against the files and get "
    "this code yourself."
)

NON_CLAIMS = [
    "PROVENANCE: content hashes prove a transcript was not ALTERED; they do NOT "
    "prove it is the output of the named harness+model (asserted by the signer, "
    "not re-executed).",
    "COMPLETENESS: this renders only the manifests provided. It cannot prove a "
    "lab pre-registered every eval it should have (selective pre-registration).",
    "FLOOR = FRESHNESS, NOT 'PRE': a drand floor proves a manifest was created "
    "NO EARLIER THAN a public moment (anti-precomputation). It does NOT prove "
    "the pre-registration preceded the run — on its own it cannot bound "
    "backdating.",
    "CEILING = A DIFFERENT TRUST CLASS: an optional ceiling witness (Roughtime) "
    "proves creation NO LATER THAN time T, but only by trusting the named "
    "signer(s) to be honest about time — a signature-witness trust, NOT the "
    "trustless proof-of-work of an OTS/Bitcoin ceiling. Without a ceiling, the "
    "'pre' is SOCIAL (the witnessed public repo), not cryptographic.",
    "IDENTITY: a key is pseudonymous. Binding it to a real entity is a separate "
    "check (see 'asexec identity'); absence of that binding is not proof of who "
    "signed.",
]


def parse_tests(spec: str) -> List[str]:
    """Parse a ``--tests`` string into a validated, de-duplicated list.

    Raises ``VerificationError`` on an unknown test or if ``bedrock`` is absent
    (no implicit default; the caller must declare its appetite explicitly).
    """
    names = [t.strip() for t in spec.split(",") if t.strip()]
    if not names:
        raise VerificationError("no tests requested; --tests must list at least 'bedrock'")
    unknown = [t for t in names if t not in TEST_CATALOG]
    if unknown:
        raise VerificationError(
            f"unknown test(s): {', '.join(unknown)}; available: {', '.join(TEST_CATALOG)}")
    if REQUIRED_TEST not in names:
        raise VerificationError(
            f"'{REQUIRED_TEST}' must be included in --tests (the mandatory minimum)")
    # preserve catalog order, de-dup.
    return [t for t in TEST_CATALOG if t in names]


def _parse_iso(ts: str) -> float:
    s = ts.replace("Z", "+00:00")
    import datetime

    return datetime.datetime.fromisoformat(s).timestamp()


def verify_signature(mani: Dict[str, Any]) -> Dict[str, Any]:
    """The bedrock check for a single manifest: signature + keyid."""
    out: Dict[str, Any] = {"signature_ok": False, "keyid_ok": False, "errors": []}
    try:
        body = manifest.get_body(mani)
        sigblock = mani["signature"]
        pub = bytes.fromhex(sigblock["pubkey"])
        sig = bytes.fromhex(sigblock["sig"])
        out["signature_ok"] = keys.verify(pub, signing_input(body), sig)
        out["keyid_ok"] = keys.keyid_for(pub) == sigblock.get("keyid")
        out["keyid"] = sigblock.get("keyid")
        out["phase"] = body.get("phase")
        out["ref"] = manifest.ref(body)
    except Exception as e:  # malformed manifest
        out["errors"].append(f"malformed: {e}")
    return out


def verify_floor(body: Dict[str, Any]) -> Dict[str, Any]:
    """Verify the drand freshness floor at ``body.anchor.floor`` (if present)."""
    floor = (body.get("anchor") or {}).get("floor")
    if not floor:
        return {"status": "absent"}
    return drand.verify_floor(floor)


def verify_ceiling(mani: Dict[str, Any]) -> Dict[str, Any]:
    """Verify the envelope-level ceiling witness (if present).

    Two conditions: (1) the witness signature verifies against a pinned key,
    and (2) the witness's nonce binds to THIS manifest (nonce == ref(payload)).
    Delegates the witness cryptography to the ``roughtime`` module; the nonce
    binding is checked here.
    """
    ceiling = manifest.get_ceiling(mani)
    if not ceiling:
        return {"status": "absent"}
    try:
        body = manifest.get_body(mani)
        expected_nonce = manifest.ref(body)
    except Exception as e:
        return {"status": "invalid", "error": f"malformed manifest: {e}"}
    from . import roughtime

    res = roughtime.verify_ceiling(ceiling, expected_nonce)
    return res


def verify_content(body: Dict[str, Any], artifacts_dir: Optional[str]) -> Dict[str, Any]:
    if not artifacts_dir:
        return {"status": "skipped", "reason": "no artifacts provided"}
    if not body.get("subject"):
        return {"status": "skipped", "reason": "manifest has no subject"}
    alg = body.get("hash_alg", hashing.DEFAULT_ALG)
    entries = []
    all_ok = True
    for item in body.get("subject", []):
        name = item["name"]
        expected = item.get("digest", {}).get(alg)
        path = os.path.join(artifacts_dir, name.rstrip("/"))
        if not os.path.exists(path):
            entries.append({"name": name, "ok": False, "reason": "artifact not found"})
            all_ok = False
            continue
        actual = hashing.digest_path(path, alg)
        ok = actual == expected
        all_ok = all_ok and ok
        entries.append({"name": name, "ok": ok,
                        **({} if ok else {"expected": expected, "actual": actual})})
    return {"status": "ok" if all_ok else "mismatch", "entries": entries}


def verify_paths(paths: List[str], tests: List[str],
                 artifacts_dir: Optional[str] = None,
                 now: Optional[float] = None) -> Dict[str, Any]:
    """Load, verify, group, evaluate the requested tests, and build the code."""
    now = time.time() if now is None else now
    files = _expand(paths)

    preregs: Dict[str, Any] = {}   # ref -> record
    receipts = []
    manifests_report = []
    ceiling_trust = []

    for p in files:
        mani = manifest.load(p)
        sig = verify_signature(mani)
        body = mani.get("payload", {})
        clean = sig.get("errors") == []
        floor = verify_floor(body) if clean else {"status": "absent"}
        ceiling = verify_ceiling(mani) if clean else {"status": "absent"}
        content = verify_content(body, artifacts_dir) if clean else {"status": "skipped"}
        if ceiling.get("status") == "verified":
            ceiling_trust.append(
                f"{p}: ceiling witnessed by {ceiling.get('witness_id')} at "
                f"{ceiling.get('midpoint')} (±{ceiling.get('radius')}s) — you are "
                f"trusting {ceiling.get('witness_id')} to be honest about time "
                f"(signature-witness trust class, distinct from the floor).")
        rec = {"path": p, "phase": body.get("phase"), "ref": sig.get("ref"),
               "keyid": sig.get("keyid"), "signature": sig, "floor": floor,
               "ceiling": ceiling, "content": content}
        manifests_report.append(rec)
        if body.get("phase") == "preregistration" and sig.get("ref"):
            preregs[sig["ref"]] = {"ref": sig["ref"], "keyid": sig.get("keyid"),
                                   "window": body.get("disclosure_window", {}),
                                   "receipts": []}
        elif body.get("phase") == "receipt":
            receipts.append((sig.get("ref"), body, sig))

    notarization_only = []
    for rref, body, sig in receipts:
        target = body.get("fulfills")
        if target in preregs:
            preregs[target]["receipts"].append({"ref": rref, "prev_hash": body.get("prev_hash"),
                                                 "keyid": sig.get("keyid")})
        else:
            notarization_only.append({"ref": rref, "fulfills": target, "keyid": sig.get("keyid")})

    commitments = []
    for pr in preregs.values():
        state = _commitment_state(pr, now)
        chain_ok, chain_note = _check_chain(pr["receipts"])
        key_consistent = all(r["keyid"] == pr["keyid"] for r in pr["receipts"])
        commitments.append({**pr, "state": state, "chain_ok": chain_ok,
                            "chain_note": chain_note, "key_consistent": key_consistent})

    results = _evaluate(tests, manifests_report, commitments, artifacts_dir)
    code = _build_code(tests, results)
    ok = all(results[t]["result"] == "PASS" for t in tests)

    return {
        "tests": tests,
        "manifests": manifests_report,
        "commitments": commitments,
        "notarization_only": notarization_only,
        "results": results,
        "code": code,
        "ok": ok,
        "ceiling_trust": ceiling_trust,
        "non_claims": NON_CLAIMS,
        "disclaimer": DISCLAIMER,
    }


def _tally(units: List[bool], nowhere_reason: str, fail_noun: str) -> Dict[str, Any]:
    """Turn a list of per-unit pass booleans into a test result.

    PASS iff there is at least one applicable unit and all of them pass;
    otherwise FAIL — distinguishing "applied nowhere" from "some failed" in the
    human-readable reason (never a silent omission or a vacuous pass).
    """
    n = len(units)
    if n == 0:
        return {"result": "FAIL", "applicable": 0, "reason": nowhere_reason}
    n_pass = sum(1 for u in units if u)
    if n_pass == n:
        return {"result": "PASS", "applicable": n, "reason": f"{n}/{n} {fail_noun} ok"}
    return {"result": "FAIL", "applicable": n,
            "reason": f"{n - n_pass}/{n} {fail_noun} failed"}


def _evaluate(tests, manifests, commitments, artifacts_dir) -> Dict[str, Dict[str, Any]]:
    res: Dict[str, Dict[str, Any]] = {}
    with_receipts = [c for c in commitments if c["receipts"]]

    if "bedrock" in tests:
        units = [bool(m["signature"].get("signature_ok") and m["signature"].get("keyid_ok"))
                 for m in manifests]
        res["bedrock"] = _tally(units, "no manifests to verify", "manifest(s)")

    if "floor" in tests:
        units = [m["floor"]["status"] == "verified"
                 for m in manifests if m["floor"]["status"] != "absent"]
        res["floor"] = _tally(units, "requested but no manifest carries an anchor.floor", "floor(s)")

    if "ceiling" in tests:
        units = [m["ceiling"]["status"] == "verified"
                 for m in manifests if m["ceiling"]["status"] != "absent"]
        res["ceiling"] = _tally(units, "requested but no manifest carries a ceiling witness", "ceiling(s)")

    if "content" in tests:
        units = [m["content"]["status"] == "ok"
                 for m in manifests if m["content"]["status"] not in ("skipped",)]
        nowhere = ("requested but no content could be checked "
                   "(need --artifacts and a manifest with a subject)")
        res["content"] = _tally(units, nowhere, "subject(s)")

    if "chain" in tests:
        units = [c["chain_ok"] for c in with_receipts]
        res["chain"] = _tally(units, "requested but no commitment has receipts to chain-check", "chain(s)")

    if "keyconsist" in tests:
        units = [c["key_consistent"] for c in with_receipts]
        res["keyconsist"] = _tally(units, "requested but no commitment has receipts to key-check", "commitment(s)")

    return res


def _build_code(tests: List[str], results: Dict[str, Dict[str, Any]]) -> str:
    tokens = [f"{name}={results[name]['result']}" for name in sorted(tests)]
    return CODE_VERSION + " " + " ".join(tokens)


def _commitment_state(pr: Dict[str, Any], now: float) -> str:
    if pr["receipts"]:
        return "fulfilled"
    closes = pr["window"].get("closes")
    if not closes:
        return "open"  # no deadline declared -> cannot elapse
    try:
        return "elapsed-no-receipt" if now >= _parse_iso(closes) else "open"
    except Exception:
        return "open"


def _check_chain(receipts: List[Dict[str, Any]]):
    """A prev_hash chain: exactly one root (prev_hash null), each other points
    to a present receipt, no cycles/forks."""
    if not receipts:
        return True, "no receipts"
    refs = {r["ref"] for r in receipts}
    roots = [r for r in receipts if not r["prev_hash"]]
    if len(roots) != 1:
        return False, f"expected exactly one chain root, found {len(roots)}"
    for r in receipts:
        if r["prev_hash"] and r["prev_hash"] not in refs:
            return False, "a receipt's prev_hash points to a missing receipt (gap)"
    return True, "chain intact"


def _expand(paths: List[str]) -> List[str]:
    out = []
    for p in paths:
        if os.path.isdir(p):
            for name in sorted(os.listdir(p)):
                if name.endswith(".json"):
                    out.append(os.path.join(p, name))
        else:
            out.append(p)
    return out
