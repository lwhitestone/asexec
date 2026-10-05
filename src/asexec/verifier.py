"""The verifier. A canonical verify code. Trust comes from reproducibility.

Everything the verifier does verifies offline against pinned constants; nothing
here touches the network.

Output: a canonical plaintext code
-------------------------------------------------------------
``verify`` runs a caller-chosen set of tests and emits one code per run::

    asexec-verify/1 BDR=PASS floor=PASS

Grammar (spec'd here so any implementation reproduces it byte-for-byte):

  - Literal prefix ``asexec-verify/1`` (this versions the code GRAMMAR itself,
    independent of the schema/PAE versions), then a single ASCII space.
  - One ``name=RESULT`` token per requested test, ``RESULT`` in ``{PASS, FAIL}``.
  - Tokens are sorted alphabetically by name and single-space delimited.

The same result set is byte-identical everywhere. Because the code *names* which
tests ran, adding a test in a later version can never change the meaning of an
older code: a code means exactly one thing, permanently.

The verify code is a summary of a computation, not a credential. Real verification
= run this tool against the manifests (+artifacts) and get this code.

Tests (the catalog - only verifiable claims, no self-declarations)
--------------------------------------------------------------------
  - ``BDR``        : bedrock - signature over the PAE input + keyid matches
                     pubkey. Applies to every manifest. **Required in every run.**
  - ``ceiling``    : a ceiling witness (Roughtime) signature verifies against a
                     pinned key AND its nonce == ref(payload). Applies to
                     manifests that carry a ceiling.
  - ``chain``      : prev_hash chain integrity (one root, no gaps, no forks: a
                     single linear chain). Applies to
                     commitments that have receipts.
  - ``content``    : subject digests recomputed from --artifacts match. Subject
                     names must resolve inside --artifacts (an escape is a
                     mismatch). Applies where artifacts are provided and a
                     subject is present.
  - ``floor``      : the drand freshness floor BLS-verifies. Applies to
                     manifests that carry an anchor.floor.
  - ``keyconsist`` : receipts share the pre-registration's key. Applies to
                     commitments that have receipts.

A requested test is ``PASS`` iff it holds everywhere it applies AND it applies
somewhere; a requested test that applies **nowhere** is ``FAIL``
(requested-but-absent), never a silent omission or a vacuous pass.

States (per commitment = a prereg + the postregs that fulfil it)
----------------------------------------------------------------
Rendered in the human report above the code; the verifier RENDERS these, it
never adjudicates intent or whether a commitment was "good enough":
  - fulfilled          : >=1 postreg references this prereg AND is validly
                         signed by the prereg's own key. Postregs that reference
                         it but fail either condition are listed separately
                         (``rejected_receipts``) and never count.
  - open               : 0 postregs and the ``due`` deadline has not elapsed
                         (or no ``due`` was declared - an open-ended commitment)
  - elapsed-no-receipt : 0 postregs and the ``due`` deadline has elapsed
  - invalid-due        : 0 postregs and ``due`` is present but is not a parseable
                         ISO-8601 timestamp (never silently rendered ``open``)
  - notarization-only  : a postreg with no matching prereg provided
"""

from __future__ import annotations

import datetime
import os
import time
from typing import Any

from . import drand, hashing, keys, manifest
from .canonical import signing_input
from .errors import VerificationError

# The canonical grammar version for the verify code. Independent of the
# schema/PAE versions - it versions the *code format*, not the signed bytes.
CODE_VERSION = "asexec-verify/1"

# The test catalog, alphabetical (the order names appear in a code).
TEST_CATALOG: tuple[str, ...] = (
    "BDR",
    "ceiling",
    "chain",
    "content",
    "floor",
    "keyconsist",
)

# BDR (bedrock) is the mandatory minimum: a run that does not check it is not a
# meaningful asexec verification, so `verify` requires it explicitly.
REQUIRED_TEST = "BDR"

DISCLAIMER = (
    "this code is only meaningful if reproduced - do not treat a quoted code "
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
    "the pre-registration preceded the run - on its own it cannot bound "
    "backdating.",
    "CEILING = A DIFFERENT TRUST CLASS: an optional ceiling witness (Roughtime) "
    "proves creation NO LATER THAN time T, but only by trusting the named "
    "signer(s) to be honest about time - a signature-witness trust, NOT the "
    "trustless proof-of-work of an OTS/Bitcoin ceiling. Without a ceiling, the "
    "'pre' is SOCIAL (the witnessed public repo), not cryptographic.",
    "IDENTITY: a key is pseudonymous. Binding it to a real entity is a separate "
    "check (see 'asexec identity'); absence of that binding is not proof of who "
    "signed.",
]


def parse_tests(spec: str) -> list[str]:
    """Parse a ``--tests`` string into a validated, de-duplicated list.

    Raises ``VerificationError`` on an unknown test or if ``BDR`` is absent
    (no implicit default; the caller must declare its appetite explicitly).
    """
    names = [t.strip() for t in spec.split(",") if t.strip()]
    if not names:
        raise VerificationError("no tests requested; --tests must list at least 'BDR'")
    unknown = [t for t in names if t not in TEST_CATALOG]
    if unknown:
        raise VerificationError(
            f"unknown test(s): {', '.join(unknown)}; available: {', '.join(TEST_CATALOG)}"
        )
    if REQUIRED_TEST not in names:
        raise VerificationError(
            f"'{REQUIRED_TEST}' must be included in --tests (the mandatory minimum)"
        )
    # preserve catalog order, de-dup.
    return [t for t in TEST_CATALOG if t in names]


def _parse_due(due: Any) -> tuple[float | None, bool]:
    """Parse a ``due`` value to ``(epoch_seconds, naive)``.

    A timezone-less value is read as UTC so the result never depends on the
    verifier's local timezone; ``naive`` flags it. ``(None, False)`` if ``due``
    is not a parseable ISO-8601 string.
    """
    if not isinstance(due, str):
        return None, False
    try:
        dt = datetime.datetime.fromisoformat(due.replace("Z", "+00:00"))
    except ValueError:
        return None, False
    naive = dt.tzinfo is None
    if naive:
        dt = dt.replace(tzinfo=datetime.UTC)
    return dt.timestamp(), naive


def verify_signature(mani: dict[str, Any]) -> dict[str, Any]:
    """The bedrock check for a single manifest: signature + keyid."""
    out: dict[str, Any] = {"signature_ok": False, "keyid_ok": False, "errors": []}
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


def verify_floor(body: dict[str, Any]) -> dict[str, Any]:
    """Verify the drand freshness floor at ``body.anchor.floor`` (if present)."""
    anchor = body.get("anchor")
    floor = anchor.get("floor") if isinstance(anchor, dict) else anchor
    if not floor:
        return {"status": "absent"}
    if not isinstance(floor, dict):
        return {"status": "invalid", "error": "malformed anchor.floor"}
    try:
        return drand.verify_floor(floor)
    except Exception as e:  # a signed-but-malformed floor must fail, not crash
        return {"status": "invalid", "error": f"malformed anchor.floor: {e}"}


def verify_ceiling(mani: dict[str, Any]) -> dict[str, Any]:
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

    try:
        return roughtime.verify_ceiling(ceiling, expected_nonce)
    except Exception as e:  # an unsigned, attacker-shaped envelope field must not crash verify
        return {"status": "invalid", "error": f"malformed ceiling: {e}"}


def _resolve_inside(artifacts_dir: str, name: str) -> str | None:
    """Resolve a subject ``name`` under ``artifacts_dir``; None if it escapes
    (``..``, an absolute name, or a symlink pointing outside)."""
    root = os.path.realpath(artifacts_dir)
    path = os.path.realpath(os.path.join(root, name.rstrip("/")))
    if path != root and not path.startswith(root + os.sep):
        return None
    return path


def _verify_subject_item(item: Any, alg: Any, artifacts_dir: str) -> dict[str, Any]:
    try:
        name = item["name"]
        expected = item.get("digest", {}).get(alg)
        if not isinstance(name, str) or not isinstance(expected, str):
            return {"name": str(name), "ok": False, "reason": "malformed subject entry"}
    except Exception:
        return {"name": str(item)[:80], "ok": False, "reason": "malformed subject entry"}
    if not isinstance(alg, str) or alg not in hashing.available_algorithms():
        return {"name": name, "ok": False, "reason": f"algorithm unavailable: {alg!r}"}
    path = _resolve_inside(artifacts_dir, name)
    if path is None:
        return {"name": name, "ok": False, "reason": "path resolves outside --artifacts"}
    if not os.path.exists(path):
        return {"name": name, "ok": False, "reason": "artifact not found"}
    try:
        actual = hashing.digest_path(path, alg)
    except OSError as e:
        return {"name": name, "ok": False, "reason": f"artifact unreadable: {e.strerror or e}"}
    ok = actual == expected
    return {"name": name, "ok": ok, **({} if ok else {"expected": expected, "actual": actual})}


def verify_content(body: dict[str, Any], artifacts_dir: str | None) -> dict[str, Any]:
    if not artifacts_dir:
        return {"status": "skipped", "reason": "no artifacts provided"}
    subject = body.get("subject")
    if not subject:
        return {"status": "skipped", "reason": "manifest has no subject"}
    if not isinstance(subject, list):
        return {
            "status": "mismatch",
            "entries": [{"name": "(subject)", "ok": False, "reason": "malformed subject"}],
        }
    alg = body.get("hash_alg", hashing.DEFAULT_ALG)
    entries = [_verify_subject_item(item, alg, artifacts_dir) for item in subject]
    return {"status": "ok" if all(e["ok"] for e in entries) else "mismatch", "entries": entries}


def verify_paths(
    paths: list[str], tests: list[str], artifacts_dir: str | None = None, now: float | None = None
) -> dict[str, Any]:
    """Load, verify, group, evaluate the requested tests, and build the code."""
    now = time.time() if now is None else now
    files = _expand(paths)

    preregs: dict[str, Any] = {}  # ref -> record
    receipts = []
    manifests_report = []
    ceiling_trust = []

    for p in files:
        try:
            mani = manifest.load(p)
            sig = verify_signature(mani)
        except Exception as e:  # unreadable / not JSON / duplicate keys / not an object
            mani = {}
            sig = {"signature_ok": False, "keyid_ok": False, "errors": [f"malformed: {e}"]}
        body = mani.get("payload")
        if not isinstance(body, dict):
            body = {}
        clean = sig.get("errors") == []
        floor = verify_floor(body) if clean else {"status": "absent"}
        ceiling = verify_ceiling(mani) if clean else {"status": "absent"}
        content = verify_content(body, artifacts_dir) if clean else {"status": "skipped"}
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
            "ref": sig.get("ref"),
            "keyid": sig.get("keyid"),
            "signature": sig,
            "floor": floor,
            "ceiling": ceiling,
            "content": content,
        }
        manifests_report.append(rec)
        if body.get("phase") == "prereg" and sig.get("ref"):
            preregs[sig["ref"]] = {
                "ref": sig["ref"],
                "keyid": sig.get("keyid"),
                "due": body.get("due"),
                "receipts": [],
                "rejected_receipts": [],
            }
        elif body.get("phase") == "postreg":
            receipts.append((sig.get("ref"), body, sig))

    notarization_only = []
    for rref, body, sig in receipts:
        target = body.get("fulfills")
        if isinstance(target, str) and target in preregs:
            pr = preregs[target]
            entry = {"ref": rref, "prev_hash": body.get("prev_hash"), "keyid": sig.get("keyid")}
            reason = _get_postreg_rejection_reason(sig, pr)
            if reason:
                pr["rejected_receipts"].append({**entry, "reason": reason})
            else:
                pr["receipts"].append(entry)
        else:
            notarization_only.append({"ref": rref, "fulfills": target, "keyid": sig.get("keyid")})

    commitments = []
    for pr in preregs.values():
        state = _commitment_state(pr, now)
        _, due_naive = _parse_due(pr.get("due"))
        chain_ok, chain_note = _check_chain(pr["receipts"])
        key_consistent = not any(
            r["reason"].startswith("signed by a different key") for r in pr["rejected_receipts"]
        )
        commitments.append(
            {
                **pr,
                "state": state,
                "due_naive": due_naive,
                "chain_ok": chain_ok,
                "chain_note": chain_note,
                "key_consistent": key_consistent,
            }
        )

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


def _tally(units: list[bool], nowhere_reason: str, fail_noun: str) -> dict[str, Any]:
    """Turn a list of per-unit pass booleans into a test result.

    PASS iff there is at least one applicable unit and all of them pass;
    otherwise FAIL - distinguishing "applied nowhere" from "some failed" in the
    human-readable reason (never a silent omission or a vacuous pass).
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
    with_receipts = [c for c in commitments if c["receipts"]]
    referenced = [c for c in commitments if c["receipts"] or c["rejected_receipts"]]

    if "BDR" in tests:
        units = [
            bool(m["signature"].get("signature_ok") and m["signature"].get("keyid_ok"))
            for m in manifests
        ]
        res["BDR"] = _tally(units, "no manifests to verify", "manifest(s)")

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
        units = [c["chain_ok"] for c in with_receipts]
        res["chain"] = _tally(
            units, "requested but no commitment has receipts to chain-check", "chain(s)"
        )

    if "keyconsist" in tests:
        units = [c["key_consistent"] for c in referenced]
        res["keyconsist"] = _tally(
            units,
            "requested but no commitment has receipts to key-check",
            "commitment(s)",
        )

    return res


def _build_code(tests: list[str], results: dict[str, dict[str, Any]]) -> str:
    tokens = [f"{name}={results[name]['result']}" for name in sorted(tests)]
    return CODE_VERSION + " " + " ".join(tokens)


def _get_postreg_rejection_reason(sig: dict[str, Any], prereg: dict[str, Any]) -> str | None:
    """Why a postreg that references ``prereg`` does not count toward fulfilling
    it, or None if it counts: validly signed by the prereg's own key."""
    if sig.get("errors") or not (sig.get("signature_ok") and sig.get("keyid_ok")):
        return "invalid signature"
    if sig.get("keyid") != prereg["keyid"]:
        return "signed by a different key than the pre-registration"
    return None


def _commitment_state(pr: dict[str, Any], now: float) -> str:
    if pr["receipts"]:
        return "fulfilled"
    due = pr.get("due")
    if not due:
        return "open"  # no deadline declared -> cannot elapse
    due_ts, _naive = _parse_due(due)
    if due_ts is None:
        return "invalid-due"
    return "elapsed-no-receipt" if now >= due_ts else "open"


def _check_chain(receipts: list[dict[str, Any]]):
    """A prev_hash chain: exactly one root (prev_hash null), each other points
    to a present receipt, and no receipt has more than one successor (a single
    linear chain: no forks, no cycles)."""
    if not receipts:
        return True, "no receipts"
    refs = {r["ref"] for r in receipts}
    roots = [r for r in receipts if not r["prev_hash"]]
    if len(roots) != 1:
        return False, f"expected exactly one chain root, found {len(roots)}"
    successors: dict[Any, int] = {}
    for r in receipts:
        prev = r["prev_hash"]
        if prev and prev not in refs:
            return False, "a receipt's prev_hash points to a missing receipt (gap)"
        if prev:
            successors[prev] = successors.get(prev, 0) + 1
    if any(n > 1 for n in successors.values()):
        return False, "a receipt has more than one successor (fork)"
    return True, "chain intact"


def _expand(paths: list[str]) -> list[str]:
    out = []
    for p in paths:
        if os.path.isdir(p):
            for name in sorted(os.listdir(p)):
                if name.endswith(".json"):
                    out.append(os.path.join(p, name))
        else:
            out.append(p)
    return out
