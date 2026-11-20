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
EMPTY = "requested but no content could be checked (need --artifacts and a manifest with a subject)"
EVAL_DIGEST = d.DIGESTS["harness/eval.py"]


def _entry_reasons(report):
    """Failure reasons of every subject entry that did not match."""
    return [
        entry["reason"]
        for mani in report["manifests"]
        for entry in mani["content"].get("entries", [])
        if not entry["ok"]
    ]


def _only_prereg(scenario):
    for name in ("postreg0", "postreg1", "postreg2"):
        scenario.drop(name)


def _prereg_subject(scenario, *entries):
    """The prereg's subject is ``entries``; the postregs are not provided."""
    _only_prereg(scenario)
    scenario.set("prereg", "body.subject", list(entries))


def _entry(name, digest=EVAL_DIGEST, alg="sha-256"):
    return {"name": name, "hash_alg": alg, "digest": {alg: digest}}


def _symlink(link, target):
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
    _prereg_subject(scenario, entry)
    report = scenario.verify("content")
    assert report["code"] == FAIL
    assert _entry_reasons(report) == ["malformed subject entry"]


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
    _prereg_subject(scenario, _entry("harness/eval.py", "00", "blake9"))
    report = scenario.verify("content")
    assert report["code"] == FAIL
    assert _entry_reasons(report) == ["algorithm unavailable: 'blake9'"]


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
    _prereg_subject(scenario, _entry(name))
    report = scenario.verify("content")
    assert report["code"] == FAIL
    assert _entry_reasons(report) == ["name is not a normalized relative path"]


@pytest.mark.parametrize("second_digest", ["same", "other"])
def test_content__fail__4_names_are_unique(scenario, second_digest):
    """content #4: no two entries of one subject have the same name, whatever their
    digests; each of them fails."""
    second = d.subject_entry("harness/eval.py")
    if second_digest == "other":
        second = _entry("harness/eval.py", d.DIGESTS["transcript0.txt"])
    _prereg_subject(scenario, d.subject_entry("harness/eval.py"), second)
    report = scenario.verify("content")
    assert report["code"] == FAIL
    assert _entry_reasons(report) == ["duplicate name"] * 2


def test_content__pass__4_the_same_name_in_two_manifests_is_not_a_duplicate(scenario):
    """content #4: names are unique within one subject; every postreg also names
    harness/eval.py, and passes."""
    assert scenario.code("content") == PASS


def test_content__fail__5_name_resolves_inside_artifacts(scenario):
    """content #5: name resolved with symlinks stays inside --artifacts (a symlink that
    points outside fails)."""
    _symlink(scenario.artifacts / "link.txt", scenario.outside)
    digest = hashing.hash_file(str(scenario.outside))
    _prereg_subject(scenario, _entry("link.txt", digest))
    report = scenario.verify("content")
    assert report["code"] == FAIL
    assert _entry_reasons(report) == ["path resolves outside --artifacts"]


def test_content__pass__5_symlink_inside_is_hashed_through_to_its_target(scenario):
    """content #5: a listed symlink that resolves inside --artifacts is hashed as the bytes
    read through it."""
    _symlink(scenario.artifacts / "link.py", scenario.artifacts / "harness" / "eval.py")
    _prereg_subject(scenario, _entry("link.py"))
    assert scenario.code("content") == PASS


@pytest.mark.parametrize("case", ["deleted", "dangling-symlink"])
def test_content__fail__6_artifact_exists(scenario, case):
    """content #6: the resolved path exists."""
    if case == "deleted":
        (scenario.artifacts / "transcript0.txt").unlink()
        report = scenario.verify("content")
    else:
        _symlink(scenario.artifacts / "gone.py", scenario.artifacts / "nothing-here.py")
        _prereg_subject(scenario, _entry("gone.py"))
        report = scenario.verify("content")
    assert report["code"] == FAIL
    assert _entry_reasons(report) == ["artifact not found"]


@pytest.mark.parametrize("case", ["directory", "symlink-to-directory", "fifo"])
def test_content__fail__7_artifact_is_a_file(scenario, case):
    """content #7: the resolved path is a regular file. A directory (even one whose old v1
    directory hash is given), a symlink to one, or a FIFO fails, and is never read."""
    name = {"directory": "harness", "symlink-to-directory": "dirlink", "fifo": "pipe"}[case]
    if case == "symlink-to-directory":
        _symlink(scenario.artifacts / "dirlink", scenario.artifacts / "harness")
    elif case == "fifo":
        if not hasattr(os, "mkfifo"):
            pytest.skip("os.mkfifo is POSIX-only")
        os.mkfifo(scenario.artifacts / "pipe")
    old_dir_hash = "2edb1fb893693308cab35ab8fa26f2be6a8a459b02f6f3fcd2100c712115ce09"
    _prereg_subject(scenario, _entry(name, old_dir_hash))
    report = scenario.verify("content")
    assert report["code"] == FAIL
    assert _entry_reasons(report) == ["artifact is not a file"]


def test_content__fail__8_artifact_is_readable(scenario, monkeypatch):
    """content #8: the resolved file is readable."""

    def deny(path, alg):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(hashing, "hash_file", deny)
    report = scenario.verify("content")
    assert report["code"] == FAIL
    assert set(_entry_reasons(report)) == {"artifact unreadable: Permission denied"}


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
    scenario.add_raw("bad", json.dumps(d.malformed({"subject": subject})))
    report = scenario.verify("content")
    assert report["results"]["content"]["applicable"] == 0
    assert report["code"] == "asexec-verify/1 content=FAIL format=FAIL selfsig=PASS"
    assert report["results"]["content"]["reason"] == EMPTY
