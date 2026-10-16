"""Conventions: docs/VERIFICATION.md `## Conventions` (Result, Code, Run rules).

Naming: ``test_<section>__<rule>`` where section is ``tests_arg`` (`--tests`), ``code``,
``run`` (the pass/fail rules) or ``never_raises`` (malformed input is a failure, never
an exception). Per-test items live in the ``test_verify_<name>.py`` files.
"""

import socket
import urllib.request

import pytest

from asexec import drand
from asexec.errors import VerificationError
from asexec.verifier import parse_tests, verify_ceiling, verify_paths

# --- `--tests` argument ------------------------------------------------------ #


def test_tests_arg__must_include_BDR():
    with pytest.raises(VerificationError, match="BDR"):
        parse_tests("floor,content")


def test_tests_arg__must_name_only_catalog_tests():
    with pytest.raises(VerificationError, match="unknown test"):
        parse_tests("BDR,nope")


def test_tests_arg__must_not_be_empty():
    with pytest.raises(VerificationError, match="no tests requested"):
        parse_tests("")


def test_tests_arg__is_deduplicated_in_catalog_order():
    assert parse_tests("floor,BDR,floor") == ["BDR", "floor"]


# --- Code -------------------------------------------------------------------- #


def test_code__BDR_alone_is_a_complete_statement(scenario):
    report = scenario.verify()
    assert report["code"] == "asexec-verify/1 BDR=PASS"
    assert report["ok"] is True


def test_code__one_token_per_requested_test_sorted_by_name(scenario):
    scenario.write()
    forwards = verify_paths(
        [str(scenario.manifest_dir)], ["BDR", "chain", "keyconsist"], str(scenario.artifacts)
    )
    backwards = verify_paths(
        [str(scenario.manifest_dir)], ["keyconsist", "chain", "BDR"], str(scenario.artifacts)
    )
    assert forwards["code"] == backwards["code"]
    assert forwards["code"] == "asexec-verify/1 BDR=PASS chain=PASS keyconsist=PASS"


def test_code__one_failing_token_makes_the_run_not_ok(scenario):
    report = scenario.verify("floor")  # nothing carries a floor: vacuous, so FAIL
    assert report["code"] == "asexec-verify/1 BDR=PASS floor=FAIL"
    assert report["ok"] is False


# --- Run rules --------------------------------------------------------------- #


def test_run__every_examined_manifest_must_pass(scenario):
    """One failing manifest among passing ones fails the test."""
    (scenario.artifacts / "transcript2.txt").write_text("TAMPERED\n")  # only postreg2's subject
    report = scenario.verify("content")
    assert report["code"] == "asexec-verify/1 BDR=PASS content=FAIL"
    assert report["results"]["content"]["reason"] == "1/4 subject(s) failed"


def test_run__manifest_lacking_the_examined_properties_is_not_examined(scenario):
    """(*) A manifest without the examined properties neither fails nor counts toward the test."""
    scenario.with_ceiling("prereg")  # only the prereg carries a ceiling
    report = scenario.verify("ceiling")
    assert report["code"] == "asexec-verify/1 BDR=PASS ceiling=PASS"
    assert report["results"]["ceiling"]["applicable"] == 1


@pytest.mark.parametrize("target", ["not-json", "binary", "duplicate-key", "missing-file"])
def test_run__malformed_file_fails_BDR_and_no_other_test_examines_it(scenario, target):
    """A malformed file fails BDR; every other test's verdict is as if it were absent."""
    scenario.with_ceiling("prereg")
    if target == "duplicate-key":
        raw = scenario.read("prereg").replace(
            '"phase": "prereg"', '"phase": "prereg", "phase": "x"', 1
        )
        scenario.add_raw("bad", raw)
    elif target == "missing-file":
        scenario.add_missing("missing")
    else:
        scenario.add_raw("bad", {"not-json": "{nope", "binary": b"\xff\xfe\x00"}[target])
    report = scenario.verify("ceiling", "chain", "content", "keyconsist")
    assert report["code"] == (
        "asexec-verify/1 BDR=FAIL ceiling=PASS chain=PASS content=PASS keyconsist=PASS"
    )


def test_run__file_unreadable_by_BDR_is_examined_by_no_other_test(scenario):
    """A file BDR cannot even read (bad hex) is not examined for floor, ceiling or content."""
    scenario.with_floor("prereg")
    scenario.with_ceiling("prereg")
    bad_floor = {"floor_type": "drand", "round": 1001, "signature": "00"}
    scenario.add_raw(
        "bad",
        '{"payload": {"phase": "prereg", "anchor": {"floor": '
        + str(bad_floor).replace("'", '"')
        + '}, "subject": [{"name": "harness/", "digest": {"sha-256": "00"}}]},'
        ' "signature": {"pubkey": "zz", "sig": "zz"},'
        ' "ceiling": {"ceiling_type": "roughtime"}}',
    )
    report = scenario.verify("ceiling", "content", "floor")
    assert report["code"] == "asexec-verify/1 BDR=FAIL ceiling=PASS content=PASS floor=PASS"


def test_run__verification_is_offline(scenario, monkeypatch):
    """No test touches the network: with sockets and urlopen disabled, all six still pass."""
    scenario.with_floor("prereg")
    scenario.with_ceiling("prereg")

    def no_network(*args, **kwargs):
        raise AssertionError("verify touched the network")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket.socket, "connect_ex", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    monkeypatch.setattr(urllib.request, "urlopen", no_network)
    report = scenario.verify("ceiling", "chain", "content", "floor", "keyconsist")
    assert report["code"] == (
        "asexec-verify/1 BDR=PASS ceiling=PASS chain=PASS content=PASS floor=PASS keyconsist=PASS"
    )


def test_run__directory_argument_expands_to_json_files_only(scenario):
    (scenario.manifest_dir / "notes.txt").write_text("not a manifest")
    (scenario.manifest_dir / "subdir").mkdir()  # not recursed into
    scenario.write()
    report = verify_paths([str(scenario.manifest_dir)], ["BDR"])
    names = sorted(m["path"].rsplit("/", 1)[-1] for m in report["manifests"])
    assert names == ["postreg0.json", "postreg1.json", "postreg2.json", "prereg.json"]


# --- Malformed input is a failure, never an exception ------------------------ #

SIGNED_JUNK = [
    pytest.param("anchor", "x", id="anchor-not-object"),
    pytest.param("anchor", {"floor": "x"}, id="floor-not-object"),
    pytest.param("anchor", {"floor": {"round": "nope", "signature": 5}}, id="floor-fields"),
    pytest.param("subject", "x", id="subject-not-list"),
    pytest.param("subject", [{"name": 3}], id="subject-entry-fields"),
    pytest.param("hash_alg", ["a"], id="hash_alg-not-string"),
    pytest.param("fulfills", {"a": 1}, id="fulfills-not-string"),
    pytest.param("prev_hash", ["a"], id="prev_hash-not-string"),
    pytest.param("due", ["a"], id="due-not-string"),
]


@pytest.mark.parametrize("field,value", SIGNED_JUNK)
def test_never_raises__validly_signed_junk_in_a_body_field(scenario, field, value):
    """BDR checks only the signature, so a signed-but-junk body must not crash any test."""
    scenario.mutate("postreg1", lambda body: body.update({field: value}))
    if field not in ("fulfills", "prev_hash"):
        scenario.mutate("prereg", lambda body: body.update({field: value}))
    report = scenario.verify("ceiling", "chain", "content", "floor", "keyconsist")
    assert report["code"].startswith("asexec-verify/1 BDR=PASS")


def test_never_raises__floor_verifier_exception(scenario, monkeypatch):
    """An exception inside the drand check is reported as an invalid floor."""
    scenario.with_floor("prereg")

    def boom(_floor):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(drand, "verify_floor", boom)
    report = scenario.verify("floor")
    assert report["code"] == "asexec-verify/1 BDR=PASS floor=FAIL"
    assert "malformed anchor.floor: kaboom" in report["manifests"][0]["floor"]["error"]


def test_never_raises__ceiling_on_a_manifest_without_payload():
    result = verify_ceiling({"ceiling": {"ceiling_type": "roughtime"}})
    assert result["status"] == "invalid"
    assert result["error"].startswith("malformed manifest:")


@pytest.mark.parametrize(
    "junk",
    [
        pytest.param("x", id="not-object"),
        pytest.param([1], id="list"),
        pytest.param({"witness_id": 5}, id="witness_id-not-string"),
        pytest.param({"ceiling_type": {}}, id="ceiling_type-not-string"),
    ],
)
def test_never_raises__junk_ceiling_member(scenario, junk):
    """A malformed ceiling member fails the ceiling test; it never raises."""
    scenario.with_ceiling("prereg")
    scenario.ceilings["prereg"] = lambda nonce_hex: junk
    assert scenario.code("ceiling") == "asexec-verify/1 BDR=PASS ceiling=FAIL"
