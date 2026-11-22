"""``content`` (subject digests): docs/VERIFICATION.md `### content`. Naming: see conftest.py.

The scenario's prereg and postregs each carry a subject (the file ``harness/eval.py``, plus
one transcript file for each postreg) that matches ``scenario.artifacts``. Each entry names
one file by its relative path and carries its own ``hash_alg``.
"""

import json
import os

import manifest_data as d
import pytest

from asexec import hashing
from asexec.verifier import verify_paths

PASS = "asexec-verify/1 content=PASS format=PASS selfsig=PASS"
FAIL = "asexec-verify/1 content=FAIL format=PASS selfsig=PASS"
EMPTY = (
    "requested but no content could be checked"
    " (need --artifacts and a manifest with a subject, plan or evidence)"
)
EVAL_DIGEST = d.DIGESTS["harness/eval.py"]


def _get_entry_reasons(report, field=None):
    """Failure reasons of every entry (of ``field`` only, if given) that did not match."""
    return [
        entry["reason"]
        for mani in report["manifests"]
        for entry in mani["content"].get("entries", [])
        if not entry["ok"] and field in (None, entry["field"])
    ]


def _add_claim_record(scenario):
    """The prereg carries a plan, and postreg0 evidence, both matching --artifacts."""
    scenario.set("prereg", "body.plan", d.PLAN)
    scenario.set("postreg0", "body.evidence", d.EVIDENCE)


def _keep_only_prereg(scenario):
    for name in ("postreg0", "postreg1", "postreg2"):
        scenario.drop(name)


def _set_prereg_subject(scenario, *entries):
    """The prereg's subject is ``entries``; the postregs are not provided."""
    _keep_only_prereg(scenario)
    scenario.set("prereg", "body.subject", list(entries))


def _make_entry(name, digest=EVAL_DIGEST, alg="sha-256"):
    return {"name": name, "hash_alg": alg, "digest": {alg: digest}}


def _make_symlink(link, target):
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this platform")


def test_content__pass__all(scenario):
    """content #1-#9: well-formed, alg available, a normalized relative name, unique, inside
    --artifacts, exists, a file, readable, equal."""
    report = scenario.verify("content")
    assert report["code"] == PASS
    assert all(m["content"]["status"] == "ok" for m in report["manifests"])


@pytest.mark.parametrize(
    "entry",
    [
        {"name": 3, "hash_alg": "sha-256", "digest": {"sha-256": EVAL_DIGEST}},
        {"name": "harness/eval.py", "digest": {"sha-256": EVAL_DIGEST}},
        {"name": "harness/eval.py", "hash_alg": None, "digest": {"sha-256": EVAL_DIGEST}},
        {"name": "harness/eval.py", "hash_alg": 5, "digest": {"sha-256": EVAL_DIGEST}},
        {"name": "harness/eval.py", "hash_alg": ["sha-256"], "digest": {"sha-256": EVAL_DIGEST}},
        {"name": "harness/eval.py", "hash_alg": "sha-256", "digest": {"sha-256": 5}},
        {"name": "harness/eval.py", "hash_alg": "sha-256", "digest": {}},
        {"name": "harness/eval.py", "hash_alg": "sha-256", "digest": {"sha-256": "zz"}},
        {"name": "harness/eval.py", "hash_alg": "sha-256", "digest": EVAL_DIGEST},
        {"name": "harness/eval.py", "hash_alg": "sha-256"},
        3,
    ],
    ids=[
        "name-not-string",
        "hash_alg-missing",
        "hash_alg-null",
        "hash_alg-number",
        "hash_alg-list",
        "digest-not-string",
        "digest-missing-for-alg",
        "digest-not-hex",
        "digest-not-object",
        "digest-missing",
        "entry-not-object",
    ],
)
def test_content__fail__1_entry_is_well_formed(scenario, entry):
    """content #1: each entry's name is a string, its own hash_alg is a string, and
    digest[hash_alg] is hex. There is no default hash_alg: an entry without one fails."""
    _set_prereg_subject(scenario, entry)
    report = scenario.verify("content")
    assert report["code"] == FAIL
    assert _get_entry_reasons(report) == ["malformed subject entry"]


@pytest.mark.parametrize("subject", [[], "x", {}], ids=["empty-list", "string", "object"])
def test_content__fail__1_subject_is_a_non_empty_array(scenario, subject):
    """content #1: a present body.subject is a non-empty array."""
    scenario.set("prereg", "body.subject", subject)
    assert scenario.code("content") == FAIL


@pytest.mark.parametrize("body_alg", ["blake9", 5, None], ids=["unknown", "number", "null"])
def test_content__pass__1_body_level_hash_alg_is_not_read(scenario, body_alg):
    """content #1: each entry carries its own hash_alg; a body-level hash_alg, whatever it
    holds, is not read."""
    scenario.mutate_all(lambda body: body.update(hash_alg=body_alg))
    assert scenario.code("content") == PASS


def test_content__fail__2_hash_alg_is_available(scenario):
    """content #2: the entry's hash_alg is available in this install."""
    _set_prereg_subject(scenario, _make_entry("harness/eval.py", "00", "blake9"))
    report = scenario.verify("content")
    assert report["code"] == FAIL
    assert _get_entry_reasons(report) == ["algorithm unavailable: 'blake9'"]


@pytest.mark.parametrize(
    "name",
    [
        "/abs/harness/eval.py",
        "./harness/eval.py",
        "harness/./eval.py",
        "harness//eval.py",
        "harness/eval.py/",
        "harness/../harness/eval.py",
        "../outside.txt",
        "harness\\eval.py",
        "",
        ".",
    ],
    ids=[
        "absolute",
        "dot-first",
        "dot-inside",
        "empty-segment",
        "trailing-slash",
        "dotdot-inside",
        "dotdot-first",
        "backslash",
        "empty",
        "dot",
    ],
)
def test_content__fail__3_name_is_a_normalized_relative_path(scenario, name):
    """content #3: name is a relative path in normal form: segments separated by "/", none
    empty, "." or "..", and no backslash. A name that would still resolve to the right file
    (./harness/eval.py) fails too, so one file has one name."""
    _set_prereg_subject(scenario, _make_entry(name))
    report = scenario.verify("content")
    assert report["code"] == FAIL
    assert _get_entry_reasons(report) == ["name is not a normalized relative path"]


@pytest.mark.parametrize("second_digest", ["same", "other"])
def test_content__fail__4_names_are_unique(scenario, second_digest):
    """content #4: no two entries of one subject have the same name, whatever their
    digests; each of them fails."""
    second = d.make_subject_entry("harness/eval.py")
    if second_digest == "other":
        second = _make_entry("harness/eval.py", d.DIGESTS["transcript0.txt"])
    _set_prereg_subject(scenario, d.make_subject_entry("harness/eval.py"), second)
    report = scenario.verify("content")
    assert report["code"] == FAIL
    assert _get_entry_reasons(report) == ["duplicate name"] * 2


def test_content__pass__4_the_same_name_in_two_manifests_is_not_a_duplicate(scenario):
    """content #4: names are unique within one subject; every postreg also names
    harness/eval.py, and passes."""
    assert scenario.code("content") == PASS


def test_content__fail__5_name_resolves_inside_artifacts(scenario):
    """content #5: name resolved with symlinks stays inside --artifacts (a symlink that
    points outside fails)."""
    _make_symlink(scenario.artifacts / "link.txt", scenario.outside)
    digest = hashing.hash_file(str(scenario.outside), "sha-256")
    _set_prereg_subject(scenario, _make_entry("link.txt", digest))
    report = scenario.verify("content")
    assert report["code"] == FAIL
    assert _get_entry_reasons(report) == ["path resolves outside --artifacts"]


def test_content__pass__5_symlink_inside_is_hashed_through_to_its_target(scenario):
    """content #5: a listed symlink that resolves inside --artifacts is hashed as the bytes
    read through it."""
    _make_symlink(scenario.artifacts / "link.py", scenario.artifacts / "harness" / "eval.py")
    _set_prereg_subject(scenario, _make_entry("link.py"))
    assert scenario.code("content") == PASS


@pytest.mark.parametrize("case", ["deleted", "dangling-symlink"])
def test_content__fail__6_artifact_exists(scenario, case):
    """content #6: the resolved path exists."""
    if case == "deleted":
        (scenario.artifacts / "transcript0.txt").unlink()
        report = scenario.verify("content")
    else:
        _make_symlink(scenario.artifacts / "gone.py", scenario.artifacts / "nothing-here.py")
        _set_prereg_subject(scenario, _make_entry("gone.py"))
        report = scenario.verify("content")
    assert report["code"] == FAIL
    assert _get_entry_reasons(report) == ["artifact not found"]


@pytest.mark.parametrize("case", ["directory", "symlink-to-directory", "fifo"])
def test_content__fail__7_artifact_is_a_file(scenario, case):
    """content #7: the resolved path is a regular file. A directory (even one whose old v1
    directory hash is given), a symlink to one, or a FIFO fails, and is never read."""
    name = {"directory": "harness", "symlink-to-directory": "dirlink", "fifo": "pipe"}[case]
    if case == "symlink-to-directory":
        _make_symlink(scenario.artifacts / "dirlink", scenario.artifacts / "harness")
    elif case == "fifo":
        if not hasattr(os, "mkfifo"):
            pytest.skip("os.mkfifo is POSIX-only")
        os.mkfifo(scenario.artifacts / "pipe")
    old_dir_hash = "2edb1fb893693308cab35ab8fa26f2be6a8a459b02f6f3fcd2100c712115ce09"
    _set_prereg_subject(scenario, _make_entry(name, old_dir_hash))
    report = scenario.verify("content")
    assert report["code"] == FAIL
    assert _get_entry_reasons(report) == ["artifact is not a file"]


def test_content__fail__8_artifact_is_readable(scenario, monkeypatch):
    """content #8: the resolved file is readable."""

    def deny(path, alg):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(hashing, "hash_file", deny)
    report = scenario.verify("content")
    assert report["code"] == FAIL
    assert set(_get_entry_reasons(report)) == {"artifact unreadable: Permission denied"}


@pytest.mark.parametrize("target", ["transcript0.txt", "harness/eval.py"])
def test_content__fail__9_digest_equals_recomputed(scenario, target):
    """content #9: the recomputed digest of the file, under the entry's hash_alg, equals
    digest[hash_alg]."""
    (scenario.artifacts / target).write_text("TAMPERED\n")
    report = scenario.verify("content")
    assert report["code"] == FAIL
    assert all(
        "expected" in e for m in report["manifests"] for e in m["content"]["entries"] if not e["ok"]
    )


def test_content__pass__9_digest_hex_accepts_either_case_and_whitespace(scenario):
    """content #9: the digest's bytes are compared, so any hex spelling of them matches."""

    def respell(body):
        digest = body["subject"][0]["digest"]["sha-256"].upper()
        body["subject"][0]["digest"]["sha-256"] = digest[:8] + " " + digest[8:]

    scenario.mutate_all(respell)
    assert scenario.code("content") == PASS


# --- plan and evidence: each checked the way a subject entry is ------------------ #


def test_content__pass__1_plan_and_evidence_are_checked_like_subject_entries(scenario):
    """content #1-#9 for body.plan (one entry) and each body.evidence entry: their media_type,
    label and uri are not read."""
    _add_claim_record(scenario)
    report = scenario.verify("content")
    assert report["code"] == PASS
    fields = sorted({e["field"] for m in report["manifests"] for e in m["content"]["entries"]})
    assert fields == ["evidence", "plan", "subject"]


@pytest.mark.parametrize("field", ["plan", "evidence"])
def test_content__pass__1_a_plan_or_evidence_alone_is_examined(scenario, field):
    """content (*): a manifest with only a plan, or only evidence, is examined."""
    scenario.mutate_all(lambda body: body.pop("subject"))
    _keep_only_prereg(scenario)
    value = d.PLAN if field == "plan" else d.EVIDENCE
    scenario.set("prereg", f"body.{field}", value)
    report = scenario.verify("content")
    assert report["code"] == PASS
    assert report["results"]["content"]["applicable"] == 1


@pytest.mark.parametrize(
    "plan",
    [
        "plan.md",
        ["plan.md"],
        {"name": "plan.md", "digest": {"sha-256": d.DIGESTS["plan.md"]}},
        {**d.PLAN, "digest": {"sha-256": "zz"}},
    ],
    ids=["string", "list", "hash_alg-missing", "digest-not-hex"],
)
def test_content__fail__1_plan_is_a_well_formed_entry(scenario, plan):
    """content #1: a present body.plan is one well-formed entry."""
    _keep_only_prereg(scenario)
    scenario.set("prereg", "body.plan", plan)
    report = scenario.verify("content")
    assert report["code"] == FAIL
    assert _get_entry_reasons(report) == ["malformed plan entry"]


@pytest.mark.parametrize(
    "evidence,reason",
    [
        ([], "malformed evidence"),
        (d.EVIDENCE[0], "malformed evidence"),
        ([{"name": "results/scores.json"}], "malformed evidence entry"),
        ([5], "malformed evidence entry"),
    ],
    ids=["empty-list", "object", "entry-without-digest", "entry-not-object"],
)
def test_content__fail__1_evidence_is_a_non_empty_array_of_entries(scenario, evidence, reason):
    """content #1: a present body.evidence is a non-empty array of well-formed entries."""
    scenario.set("postreg0", "body.evidence", evidence)
    report = scenario.verify("content")
    assert report["code"] == FAIL
    assert _get_entry_reasons(report) == [reason]


@pytest.mark.parametrize("field", ["plan", "evidence"])
def test_content__fail__3_plan_and_evidence_names_are_normalized(scenario, field):
    """content #3: as for a subject entry."""
    _add_claim_record(scenario)
    name = "body.plan.name" if field == "plan" else "body.evidence.0.name"
    scenario.set("prereg" if field == "plan" else "postreg0", name, "./" + d.EVIDENCE[0]["name"])
    report = scenario.verify("content")
    assert report["code"] == FAIL
    assert _get_entry_reasons(report, field) == ["name is not a normalized relative path"]


def test_content__fail__4_evidence_names_are_unique(scenario):
    """content #4: no two evidence entries have the same name."""
    scenario.set("postreg0", "body.evidence", d.EVIDENCE * 2)
    report = scenario.verify("content")
    assert report["code"] == FAIL
    assert _get_entry_reasons(report, "evidence") == ["duplicate name"] * 2


def test_content__pass__4_a_name_in_subject_and_evidence_is_not_a_duplicate(scenario):
    """content #4: names are unique within one list; a file may be a subject and evidence."""
    scenario.set("postreg0", "body.evidence", [d.make_subject_entry("transcript0.txt")])
    assert scenario.code("content") == PASS


@pytest.mark.parametrize("field", ["plan", "evidence"])
def test_content__fail__7_plan_and_evidence_name_a_file(scenario, field):
    """content #7: a plan or evidence entry naming a directory fails."""
    _add_claim_record(scenario)
    path = "body.plan.name" if field == "plan" else "body.evidence.0.name"
    scenario.set("prereg" if field == "plan" else "postreg0", path, "harness")
    report = scenario.verify("content")
    assert report["code"] == FAIL
    assert _get_entry_reasons(report, field) == ["artifact is not a file"]


@pytest.mark.parametrize("target", ["plan.md", "results/scores.json"])
def test_content__fail__9_plan_and_evidence_digests(scenario, target):
    """content #9: the plan document and the evidence files are hashed and compared."""
    _add_claim_record(scenario)
    (scenario.artifacts / target).write_text("CHANGED\n")
    report = scenario.verify("content")
    assert report["code"] == FAIL
    (bad,) = [e for m in report["manifests"] for e in m["content"]["entries"] if not e["ok"]]
    assert bad["field"] == ("plan" if target == "plan.md" else "evidence")
    assert bad["name"] == target and "expected" in bad


def test_content__fail__empty_no_artifacts_provided(scenario):
    """content (*): without --artifacts, nothing is examined."""
    report = scenario.verify("content", artifacts=False)
    assert report["code"] == FAIL
    assert report["results"]["content"]["applicable"] == 0
    assert report["results"]["content"]["reason"] == EMPTY


def test_content__fail__empty_artifacts_given_as_empty_string(scenario):
    """content (*): ``--artifacts ""`` is read as not given, so nothing is examined."""
    report = verify_paths(scenario.write(), ["content", "format", "selfsig"], artifacts_dir="")
    assert report["code"] == FAIL
    assert report["results"]["content"]["applicable"] == 0
    assert report["results"]["content"]["reason"] == EMPTY


@pytest.mark.parametrize("absent", ["missing", "null"])
def test_content__fail__empty_no_manifest_has_a_subject(scenario, absent):
    """content (*): with --artifacts but no manifest carrying a subject (missing or null),
    nothing is examined."""
    if absent == "missing":
        scenario.mutate_all(lambda body: body.pop("subject"))
    else:
        scenario.mutate_all(lambda body: body.update(subject=None))
    report = scenario.verify("content")
    assert report["code"] == FAIL
    assert report["results"]["content"]["applicable"] == 0
    assert report["results"]["content"]["reason"] == EMPTY


def test_content__fail__empty_malformed_manifest_not_examined(scenario):
    """content (*): a malformed manifest is not examined, even if it carries a subject."""
    scenario.mutate_all(lambda body: body.pop("subject"))
    subject = [{"name": "harness/eval.py", "hash_alg": "sha-256", "digest": {"sha-256": "00"}}]
    scenario.add_raw("bad", json.dumps(d.make_malformed({"subject": subject})))
    report = scenario.verify("content")
    assert report["results"]["content"]["applicable"] == 0
    assert report["code"] == "asexec-verify/1 content=FAIL format=FAIL selfsig=PASS"
    assert report["results"]["content"]["reason"] == EMPTY
