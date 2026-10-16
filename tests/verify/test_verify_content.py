"""``content`` (subject digests): docs/VERIFICATION.md `### content`. Naming: see conftest.py.

The scenario's prereg and postregs each carry a subject (the ``harness/`` directory,
plus one transcript file for each postreg) that matches ``scenario.artifacts``.
"""

import pytest

from asexec import hashing

PASS = "asexec-verify/1 BDR=PASS content=PASS"
FAIL = "asexec-verify/1 BDR=PASS content=FAIL"


def _entry_reasons(report):
    """Failure reasons of every subject entry that did not match."""
    return [
        entry["reason"]
        for mani in report["manifests"]
        for entry in mani["content"].get("entries", [])
        if not entry["ok"]
    ]


def _subject_of_outside_file(scenario, name):
    digest = hashing.hash_file(str(scenario.outside))
    return lambda body: body.update(subject=[{"name": name, "digest": {"sha-256": digest}}])


def test_content__pass__all(scenario):
    """content #1-#6: well-formed, alg available, inside --artifacts, exists, readable, equal."""
    report = scenario.verify("content")
    assert report["code"] == PASS
    assert all(m["content"]["status"] == "ok" for m in report["manifests"])


@pytest.mark.parametrize(
    "entry",
    [
        {"name": 3, "digest": {"sha-256": "00"}},
        {"name": "harness/", "digest": {"sha-256": 5}},
        {"name": "harness/", "digest": {}},
        3,
    ],
    ids=["name-not-string", "digest-not-string", "digest-missing-for-alg", "entry-not-object"],
)
def test_content__fail__1_entry_is_well_formed(scenario, entry):
    """content #1: name is a string and digest[hash_alg] is a string."""
    scenario.set("prereg", "payload.subject", [entry])
    report = scenario.verify("content")
    assert report["code"] == FAIL
    assert _entry_reasons(report) == ["malformed subject entry"]


@pytest.mark.parametrize("subject", [[], "x", {}], ids=["empty-list", "string", "object"])
def test_content__fail__1_subject_is_a_non_empty_array(scenario, subject):
    """content #1: a present payload.subject is a non-empty array."""
    scenario.set("prereg", "payload.subject", subject)
    assert scenario.code("content") == FAIL


def test_content__pass__2_null_hash_alg_is_absent(scenario):
    """content #2: a null hash_alg is absent, so it defaults to sha-256. (The writer would
    refuse to sign a subject without hash_alg; a signer need not use the writer.)"""
    scenario.mutate_all(lambda body: body.update(hash_alg=None))
    scenario.skip_writer_gate()
    assert scenario.code("content") == PASS


def test_content__fail__2_hash_alg_is_available(scenario):
    """content #2: hash_alg is available in this install."""

    def unknown_alg(body):
        body["hash_alg"] = "blake9"
        body["subject"][0]["digest"] = {"blake9": "00"}

    scenario.mutate("prereg", unknown_alg)
    report = scenario.verify("content")
    assert report["code"] == FAIL
    assert _entry_reasons(report) == ["algorithm unavailable: 'blake9'"]


@pytest.mark.parametrize("case", ["dotdot", "absolute", "dotdot-inside", "symlink"])
def test_content__fail__3_name_resolves_inside_artifacts(scenario, case):
    """content #3: name resolves inside --artifacts (.., absolute, escaping symlinks fail)."""
    names = {
        "dotdot": "../outside.txt",
        "absolute": str(scenario.outside),
        "dotdot-inside": "harness/../../outside.txt",
        "symlink": "link.txt",
    }
    if case == "symlink":
        try:
            (scenario.artifacts / "link.txt").symlink_to(scenario.outside)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks unavailable on this platform")
    scenario.mutate("prereg", _subject_of_outside_file(scenario, names[case]))
    report = scenario.verify("content")
    assert report["code"] == FAIL
    assert _entry_reasons(report) == ["path resolves outside --artifacts"]


def test_content__fail__4_artifact_exists(scenario):
    """content #4: the resolved path exists."""
    (scenario.artifacts / "transcript0.txt").unlink()
    report = scenario.verify("content")
    assert report["code"] == FAIL
    assert _entry_reasons(report) == ["artifact not found"]


def test_content__fail__5_artifact_is_readable(scenario, monkeypatch):
    """content #5: the resolved path is readable."""

    def deny(path, alg):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(hashing, "digest_path", deny)
    report = scenario.verify("content")
    assert report["code"] == FAIL
    assert set(_entry_reasons(report)) == {"artifact unreadable: Permission denied"}


@pytest.mark.parametrize("target", ["file", "directory"])
def test_content__fail__6_digest_equals_recomputed(scenario, target):
    """content #6: the recomputed digest, of a file or a directory, equals digest[hash_alg]."""
    path = {
        "file": scenario.artifacts / "transcript0.txt",
        "directory": scenario.artifacts / "harness" / "eval.py",
    }[target]
    path.write_text("TAMPERED\n")
    report = scenario.verify("content")
    assert report["code"] == FAIL
    assert all(
        "expected" in e for m in report["manifests"] for e in m["content"]["entries"] if not e["ok"]
    )


def test_content__fail__vacuous_no_artifacts_provided(scenario):
    """content (*): without --artifacts, nothing is examined."""
    report = scenario.verify("content", artifacts=False)
    assert report["code"] == FAIL
    assert report["results"]["content"]["applicable"] == 0


@pytest.mark.parametrize("absent", ["missing", "null"])
def test_content__fail__vacuous_no_manifest_has_a_subject(scenario, absent):
    """content (*): with --artifacts but no manifest carrying a subject (missing or null),
    nothing is examined."""
    if absent == "missing":
        scenario.mutate_all(lambda body: (body.pop("subject"), body.pop("hash_alg")))
    else:
        scenario.mutate_all(lambda body: body.update(subject=None))
    report = scenario.verify("content")
    assert report["code"] == FAIL
    assert report["results"]["content"]["applicable"] == 0
