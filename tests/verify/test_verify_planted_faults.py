"""Planted faults: inputs the production writer refuses or cannot produce.

Built from ``tests/manifest_data.py`` alone, without ``Scenario``, to show what verify does
with files that someone else wrote. Faults that a ``test_verify_<name>.py`` file already
covers are not repeated here. Naming: ``test_fault__<what>``. An ``xfail`` marks behaviour
that looks wrong against docs/VERIFICATION.md; it is recorded here, not fixed.
"""

import json

import manifest_data as d
import pytest

from asexec import keys
from asexec.verifier import verify_paths

PREFIX = "asexec-verify/1 "
TESTS_LINKED = ("BDR", "chain", "keyconsist")


def _run(tmp_path, *manifests, tests=("BDR",)):
    """Verify ``manifests`` (envelopes, or raw file text) with the scenario's artifacts."""
    paths = []
    for i, mani in enumerate(manifests):
        path = tmp_path / f"m{i}.json"
        path.write_text(mani if isinstance(mani, str) else json.dumps(mani))
        paths.append(str(path))
    for rel, text in d.ARTIFACTS.items():
        (tmp_path / "artifacts" / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / "artifacts" / rel).write_text(text)
    return verify_paths(paths, list(tests), artifacts_dir=str(tmp_path / "artifacts"))


def _pair(prereg):
    """``prereg`` and the base postreg, re-linked to it, both signed."""
    return d.sign(prereg), d.sign(d.with_field(d.POSTREG, "fulfills", d.ref(prereg)))


def _content_reasons(report):
    return [
        e.get("reason", "digest mismatch")
        for m in report["manifests"]
        for e in (m.get("content") or {}).get("entries", [])
        if not e["ok"]
    ]


# --- subject and hash_alg -------------------------------------------------------- #


def test_fault__hash_alg_missing_beside_a_subject(tmp_path):
    """The writer refuses a subject without hash_alg; verify reads it as sha-256."""
    pre, post = (d.sign(d.without_field(b, "hash_alg")) for b in (d.PREREG, d.POSTREG))
    report = _run(tmp_path, pre, post, tests=("BDR", "content"))
    assert report["code"] == PREFIX + "BDR=PASS content=PASS"


def test_fault__subject_entry_without_a_digest(tmp_path):
    report = _run(
        tmp_path, d.sign(d.without_field(d.PREREG, "subject.0.digest")), tests=("BDR", "content")
    )
    assert report["code"] == PREFIX + "BDR=PASS content=FAIL"
    assert _content_reasons(report) == ["malformed subject entry"]


def test_fault__subject_digest_in_uppercase_hex(tmp_path):
    """Digests compare as strings (content #6), so uppercase hex of the right bytes fails."""
    upper = d.DIGESTS["harness/"].upper()
    report = _run(
        tmp_path,
        d.sign(d.with_field(d.PREREG, "subject.0.digest.sha-256", upper)),
        tests=("BDR", "content"),
    )
    assert report["code"] == PREFIX + "BDR=PASS content=FAIL"
    assert _content_reasons(report) == ["digest mismatch"]


# --- fields the writer would never write ----------------------------------------- #


@pytest.mark.parametrize(
    "path,value",
    [
        ("surprise", {"x": 1}),
        ("target", 5),
        ("declaration", ["a"]),
        ("notes", {"n": None}),
    ],
    ids=["unknown-field", "target-int", "declaration-list", "notes-object"],
)
def test_fault__signed_body_field_verify_does_not_examine(tmp_path, path, value):
    """Unknown fields and wrong types in fields no test examines change nothing."""
    report = _run(tmp_path, *_pair(d.with_field(d.PREREG, path, value)), tests=TESTS_LINKED)
    assert report["code"] == PREFIX + "BDR=PASS chain=PASS keyconsist=PASS"
    assert report["commitments"][0]["state"] == "fulfilled"


def test_fault__empty_signed_body_passes_BDR(tmp_path):
    """Documented: BDR does not establish that payload is a well-formed asexec body."""
    report = _run(tmp_path, d.sign({}))
    assert report["code"] == PREFIX + "BDR=PASS"
    assert report["commitments"] == [] and report["notarization_only"] == []


def test_fault__phase_not_a_string_joins_nothing(tmp_path):
    report = _run(tmp_path, d.sign(d.with_field(d.PREREG, "phase", ["prereg"])))
    assert report["code"] == PREFIX + "BDR=PASS"
    assert report["commitments"] == [] and report["notarization_only"] == []


_HEX = d.ref(d.PREREG).split(":")[1]


@pytest.mark.parametrize(
    "post",
    [
        d.with_field(d.POSTREG, "fulfills", "sha-256:" + _HEX.upper()),
        d.with_field(d.POSTREG, "fulfills", _HEX),
        d.without_field(d.POSTREG, "fulfills"),
    ],
    ids=["uppercase-hex", "no-prefix", "missing"],
)
def test_fault__fulfills_not_exactly_the_ref(tmp_path, post):
    """Counting #1 compares fulfills to ref(prereg) exactly; anything else links nowhere."""
    report = _run(tmp_path, d.sign(d.PREREG), d.sign(post), tests=TESTS_LINKED)
    assert report["code"] == PREFIX + "BDR=PASS chain=FAIL keyconsist=FAIL"
    assert report["commitments"][0]["receipts"] == []
    assert len(report["notarization_only"]) == 1


# --- envelope -------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "edit",
    [
        lambda env: env.update(surprise=1),
        lambda env: env.pop("payloadType"),
        lambda env: env["signature"].pop("alg"),
    ],
    ids=["unknown-field", "payloadType-missing", "signature-alg-missing"],
)
def test_fault__unsigned_envelope_field_verify_does_not_examine(tmp_path, edit):
    pre, post = _pair(d.PREREG)
    edit(pre)
    assert _run(tmp_path, pre, post, tests=TESTS_LINKED)["code"] == (
        PREFIX + "BDR=PASS chain=PASS keyconsist=PASS"
    )


SIG = d.sign(d.PREREG)["signature"]


@pytest.mark.parametrize(
    "changes",
    [
        {"keyid": None},
        {"sig": SIG["sig"][:-2]},
        {"sig": ""},
        {"pubkey": "00" * 31, "keyid": keys.keyid_for(bytes(31))},
        {"pubkey": "00" * 33},
    ],
    ids=["keyid-missing", "sig-63-bytes", "sig-empty", "pubkey-31-bytes", "pubkey-33-bytes"],
)
def test_fault__signature_fields_of_the_wrong_shape(tmp_path, changes):
    """Hex of the wrong length, or a missing keyid, fails BDR without raising."""
    env = d.sign(d.PREREG)
    for key, value in changes.items():
        if value is None:
            del env["signature"][key]
        else:
            env["signature"][key] = value
    assert _run(tmp_path, env)["code"] == PREFIX + "BDR=FAIL"


@pytest.mark.parametrize("payload", [[1], "x"], ids=["list", "string"])
def test_fault__payload_not_an_object(tmp_path, payload):
    env = {**d.sign(d.PREREG), "payload": payload}
    assert _run(tmp_path, env)["code"] == PREFIX + "BDR=FAIL"


def test_fault__very_deep_file_fails_BDR_everywhere(tmp_path):
    """100,000 levels: rejected before parsing, so the code is the same on every Python
    version and machine (the parser's own limit is not)."""
    raw = json.dumps(d.sign(d.PREREG))[:-1] + ', "junk": ' + "[" * 100_000 + "]" * 100_000 + "}"
    assert _run(tmp_path, raw)["code"] == PREFIX + "BDR=FAIL"


def test_fault__body_with_no_canonical_form_fails_BDR(tmp_path):
    """A lone surrogate escape is valid JSON but has no UTF-8 form, so no canonical bytes."""
    raw = json.dumps(d.sign(d.PREREG)).replace('"notes": "prereg"', '"notes": "\\ud800"')
    assert "\\ud800" in raw
    assert _run(tmp_path, raw)["code"] == PREFIX + "BDR=FAIL"


def test_fault__nan_in_the_body_is_valid_json(tmp_path):
    """Valid JSON is what json.load accepts, and it accepts NaN."""
    assert _run(tmp_path, d.sign(d.with_field(d.PREREG, "notes", float("nan"))))["code"] == (
        PREFIX + "BDR=PASS"
    )


# --- the same manifest supplied twice --------------------------------------------- #


def test_fault__identical_prereg_files_are_one_commitment(tmp_path):
    pre, post = _pair(d.PREREG)
    report = _run(tmp_path, pre, pre, post, tests=TESTS_LINKED)
    assert report["code"] == PREFIX + "BDR=PASS chain=PASS keyconsist=PASS"
    assert len(report["commitments"]) == 1


@pytest.mark.xfail(
    strict=True,
    reason="an identical postreg supplied twice counts twice and becomes a second root, so "
    "chain fails, while an identical prereg is merged; VERIFICATION.md defines neither",
)
def test_fault__identical_postreg_files_count_once(tmp_path):
    pre, post = _pair(d.PREREG)
    report = _run(tmp_path, pre, post, post, tests=TESTS_LINKED)
    assert report["code"] == PREFIX + "BDR=PASS chain=PASS keyconsist=PASS"
    assert len(report["commitments"][0]["receipts"]) == 1
