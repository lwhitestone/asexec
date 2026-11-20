"""Conventions: docs/VERIFICATION.md `## Conventions` (Result, Code, Run rules).

Naming: ``test_<section>__<rule>`` where section is ``tests_arg`` (`--tests`), ``code``,
``run`` (the pass/fail rules) or ``never_raises`` (malformed input is a failure, never
an exception). Per-test items live in the ``test_verify_<name>.py`` files.
"""

import re
import socket
import urllib.request

import pytest

from asexec.errors import VerificationError
from asexec.verifier import parse_tests, verify_paths

# --- `--tests` argument ------------------------------------------------------ #


@pytest.mark.parametrize(
    "spec,missing",
    [
        ("floor,content", "'format', 'selfsig'"),
        ("format,floor", "'selfsig'"),
        ("selfsig,floor", "'format'"),
    ],
    ids=["neither", "no-selfsig", "no-format"],
)
def test_tests_arg__must_include_format_and_selfsig(spec, missing):
    """Both required tests must be named; the error names the one(s) missing."""
    with pytest.raises(VerificationError, match=re.escape(f"missing required test(s) {missing}")):
        parse_tests(spec)


def test_tests_arg__must_name_only_catalog_tests():
    with pytest.raises(VerificationError, match="unknown test"):
        parse_tests("format,selfsig,nope")


def test_tests_arg__must_not_be_empty():
    with pytest.raises(VerificationError, match="no tests requested"):
        parse_tests("")


def test_tests_arg__is_deduplicated_in_catalog_order():
    assert parse_tests("selfsig,floor,format,floor") == ["floor", "format", "selfsig"]


# --- Code -------------------------------------------------------------------- #


def test_code__the_required_tests_alone_are_a_complete_statement(scenario):
    report = scenario.verify()
    assert report["code"] == "asexec-verify/1 format=PASS selfsig=PASS"
    assert report["ok"] is True


def test_code__one_token_per_requested_test_sorted_by_name(scenario):
    scenario.write()
    forwards = verify_paths(
        [str(scenario.manifest_dir)],
        ["chain", "format", "keyconsist", "selfsig"],
        str(scenario.artifacts),
    )
    backwards = verify_paths(
        [str(scenario.manifest_dir)],
        ["selfsig", "keyconsist", "format", "chain"],
        str(scenario.artifacts),
    )
    assert forwards["code"] == backwards["code"]
    assert forwards["code"] == (
        "asexec-verify/1 chain=PASS format=PASS keyconsist=PASS selfsig=PASS"
    )


def test_code__one_failing_token_makes_the_run_not_ok(scenario):
    report = scenario.verify("floor")  # nothing carries a floor: nothing to examine, so FAIL
    assert report["code"] == "asexec-verify/1 floor=FAIL format=PASS selfsig=PASS"
    assert report["ok"] is False


# --- Run rules --------------------------------------------------------------- #


def test_run__every_examined_manifest_must_pass(scenario):
    """One failing manifest among passing ones fails the test."""
    (scenario.artifacts / "transcript2.txt").write_text("TAMPERED\n")  # only postreg2's subject
    report = scenario.verify("content")
    assert report["code"] == "asexec-verify/1 content=FAIL format=PASS selfsig=PASS"
    assert report["results"]["content"]["applicable"] == 4


def test_run__manifest_lacking_the_examined_properties_is_not_examined(scenario):
    """(*) A manifest without the examined properties neither fails nor counts toward the test."""
    scenario.with_ceiling("prereg")  # only the prereg carries a ceiling
    report = scenario.verify("ceiling")
    assert report["code"] == "asexec-verify/1 ceiling=PASS format=PASS selfsig=PASS"
    assert report["results"]["ceiling"]["applicable"] == 1


@pytest.mark.parametrize("target", ["not-json", "binary", "duplicate-key", "missing-file"])
def test_run__malformed_file_fails_format_and_no_other_test_examines_it(scenario, target):
    """A malformed file fails format; every other test's verdict, selfsig's included, is as
    if it were absent."""
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
        "asexec-verify/1 ceiling=PASS chain=PASS content=PASS format=FAIL keyconsist=PASS"
        " selfsig=PASS"
    )


def test_run__file_failing_format_is_examined_by_no_other_test(scenario):
    """A file that fails format (bad hex) is not examined for selfsig, floor, ceiling or
    content."""
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
    assert report["code"] == (
        "asexec-verify/1 ceiling=PASS content=PASS floor=PASS format=FAIL selfsig=PASS"
    )


def test_run__malformed_postreg_joins_no_commitment(scenario):
    """A malformed postreg (here: non-hex pubkey) fulfilling the prereg is neither counted
    nor rejected, so chain and keyconsist have nothing to examine."""
    scenario.drop("postreg1")
    scenario.drop("postreg2")
    scenario.set("postreg0", "signature.pubkey", "zz")
    report = scenario.verify("chain", "keyconsist")
    assert report["code"] == ("asexec-verify/1 chain=FAIL format=FAIL keyconsist=FAIL selfsig=PASS")
    assert report["results"]["keyconsist"]["applicable"] == 0
    (commitment,) = report["commitments"]
    assert commitment["counted_postregs"] == [] and commitment["rejected_postregs"] == []
    assert report["notarization_only"] == []


def test_run__verification_is_offline(scenario, monkeypatch):
    """No test touches the network: with sockets and urlopen disabled, all seven still pass."""
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
        "asexec-verify/1 ceiling=PASS chain=PASS content=PASS floor=PASS format=PASS"
        " keyconsist=PASS selfsig=PASS"
    )


def test_run__directory_argument_expands_to_json_files_only(scenario):
    (scenario.manifest_dir / "notes.txt").write_text("not a manifest")
    (scenario.manifest_dir / "subdir").mkdir()  # not recursed into
    scenario.write()
    report = verify_paths([str(scenario.manifest_dir)], ["format", "selfsig"])
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
    """selfsig checks only the signature, so a signed-but-junk body must not crash any test."""
    scenario.set("postreg1", f"payload.{field}", value)
    if field not in ("fulfills", "prev_hash"):
        scenario.set("prereg", f"payload.{field}", value)
    report = scenario.verify("ceiling", "chain", "content", "floor", "keyconsist")
    assert {"format=PASS", "selfsig=PASS"} <= set(report["code"].split()[1:])


@pytest.mark.parametrize(
    "path,value",
    [
        pytest.param("round", 2**70, id="round-overflows-8-bytes"),
        pytest.param("round", -1, id="round-negative"),
        pytest.param("round", True, id="round-bool"),
        pytest.param("signature", 5, id="signature-not-string"),
        pytest.param("signature", "abc", id="signature-odd-length"),
        pytest.param("randomness", 5, id="randomness-not-string"),
        pytest.param("chain_hash", [], id="chain_hash-not-string"),
        pytest.param("floor_type", {}, id="floor_type-not-string"),
    ],
)
def test_never_raises__junk_floor_member(scenario, path, value):
    """A validly signed but malformed anchor.floor member fails floor; it never raises."""
    scenario.with_floor("prereg")
    scenario.set("prereg", f"payload.anchor.floor.{path}", value)
    assert scenario.code("floor") == "asexec-verify/1 floor=FAIL format=PASS selfsig=PASS"


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
    assert scenario.code("ceiling") == "asexec-verify/1 ceiling=FAIL format=PASS selfsig=PASS"
