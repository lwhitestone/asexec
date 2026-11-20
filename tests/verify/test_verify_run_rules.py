"""Conventions: docs/VERIFICATION.md `## Conventions` (Result, Code, Run rules).

Naming: ``test_<section>__<rule>`` where section is ``tests_arg`` (`--tests`), ``code``,
``run`` (the pass/fail rules) or ``never_raises`` (malformed input is a failure, never
an exception). Per-test items live in the ``test_verify_<name>.py`` files.
"""

import json
import re
import socket
import urllib.request

import manifest_data as d
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


def _relabelled(envelope: dict, payload_type: str) -> dict:
    return {**envelope, "dsse": {**envelope["dsse"], "payloadType": payload_type}}


@pytest.mark.parametrize(
    "target",
    [
        "not-json",
        "binary",
        "duplicate-key",
        "duplicate-key-in-body",
        "not-base64",
        "missing-file",
        "unknown-format",
    ],
)
def test_run__malformed_file_fails_format_and_no_other_test_examines_it(scenario, target):
    """A malformed file, or one of a format this release does not read, fails format; every
    other test's verdict, selfsig's included, is as if it were absent."""
    scenario.with_ceiling("prereg")
    envelope = json.loads(scenario.read("prereg"))
    if target == "unknown-format":  # a copy of the prereg, ceiling and all, relabelled
        scenario.add_raw("bad", json.dumps(_relabelled(envelope, "application/vnd.asexec.v2+json")))
    elif target == "duplicate-key":
        raw = scenario.read("prereg")
        pubkey = envelope["pubkey"]
        scenario.add_raw(
            "bad", raw.replace(f'"pubkey": "{pubkey}"', f'"pubkey": "{pubkey}", "pubkey": "00"', 1)
        )
    elif target == "duplicate-key-in-body":  # validly signed, ceiling kept
        dup = d.decoded(envelope).replace(b'"phase":"prereg"', b'"phase":"prereg","phase":"x"')
        scenario.add_raw("bad", json.dumps({**d.sign_bytes(dup), "ceiling": envelope["ceiling"]}))
    elif target == "not-base64":
        envelope["dsse"]["payload"] += "="  # excess padding, whatever it had
        scenario.add_raw("bad", json.dumps(envelope))
    elif target == "missing-file":
        scenario.add_missing("missing")
    else:
        scenario.add_raw("bad", {"not-json": "{nope", "binary": b"\xff\xfe\x00"}[target])
    report = scenario.verify("ceiling", "chain", "content", "keyconsist")
    assert report["code"] == (
        "asexec-verify/1 ceiling=PASS chain=PASS content=PASS format=FAIL keyconsist=PASS"
        " selfsig=PASS"
    )


# A body every optional test would examine, and fail: a junk floor and a subject whose digest
# matches nothing.
_JUNK_BODY = {
    "phase": "prereg",
    "anchor": {"floor": {"floor_type": "drand", "round": 1001, "signature": "00"}},
    "subject": [{"name": "harness/eval.py", "hash_alg": "sha-256", "digest": {"sha-256": "00"}}],
}


@pytest.mark.parametrize("case", ["duplicate-key-in-body", "body-not-object", "unknown-format"])
def test_run__file_failing_format_is_examined_by_no_other_test(scenario, case):
    """A file that fails format (a body with a duplicate key or that is no object, though
    validly signed, or a format this release does not read) is not examined for selfsig,
    floor, ceiling or content."""
    scenario.with_floor("prereg")
    scenario.with_ceiling("prereg")
    raw = d.body_bytes(_JUNK_BODY)
    if case == "duplicate-key-in-body":
        raw = raw.replace(b'"phase":"prereg"', b'"phase":"prereg","phase":"prereg"')
    elif case == "body-not-object":
        raw = b"[" + raw + b"]"
    envelope = d.sign_bytes(raw)
    if case == "unknown-format":
        envelope = _relabelled(envelope, "application/vnd.asexec.v2+json")
    scenario.add_raw("bad", json.dumps({**envelope, "ceiling": {"ceiling_type": "roughtime"}}))
    report = scenario.verify("ceiling", "content", "floor")
    assert report["code"] == (
        "asexec-verify/1 ceiling=PASS content=PASS floor=PASS format=FAIL selfsig=PASS"
    )


@pytest.mark.parametrize(
    "path,value",
    [
        ("dsse.signatures", "x"),
        ("dsse.payload", "not base64"),
        ("dsse.payloadType", "application/vnd.asexec.v2+json"),
        ("dsse.payloadType", "application/vnd.asexec.0.3.0b1+json"),
    ],
    ids=["signatures-not-array", "payload-not-base64", "newer-format", "beta-format"],
)
def test_run__malformed_postreg_joins_no_commitment(scenario, path, value):
    """A postreg that fails format (here: no array of signatures, a payload that is not
    base64, or a format this release does not read) fulfilling the prereg is neither
    counted nor rejected, so chain and keyconsist have nothing to examine."""
    scenario.drop("postreg1")
    scenario.drop("postreg2")
    scenario.set("postreg0", path, value)
    report = scenario.verify("chain", "keyconsist")
    assert report["code"] == ("asexec-verify/1 chain=FAIL format=FAIL keyconsist=FAIL selfsig=PASS")
    assert report["results"]["keyconsist"]["applicable"] == 0
    (commitment,) = report["commitments"]
    assert commitment["counted_postregs"] == [] and commitment["rejected_postregs"] == []
    assert report["notarization_only"] == []


@pytest.mark.parametrize(
    "path,value",
    [
        ("pubkey", "zz"),
        ("pubkey", None),
        ("dsse.signatures[0].sig", None),
        ("dsse.signatures[0].keyid", None),
        ("dsse.signatures", []),
        ("dsse.signatures[1]", {"keyid": "sha-256:00", "sig": "00"}),
    ],
    ids=[
        "pubkey-not-hex",
        "pubkey-missing",
        "sig-missing",
        "keyid-missing",
        "no-signature",
        "two-signatures",
    ],
)
def test_run__postreg_failing_only_selfsig_is_rejected_under_its_commitment(scenario, path, value):
    """A postreg that passes format but fails selfsig (a missing or non-hex pubkey, a missing sig, a
    missing keyid, zero or two signatures) is read: it names the commitment, so it is
    listed under it as rejected for invalid signature, with dsse.signatures[0].keyid (if
    any) as its keyid, and is not counted."""
    scenario.drop("postreg1")
    scenario.drop("postreg2")
    if path == "dsse.signatures[1]":  # a second entry beside the valid one
        scenario.tamper("postreg0", lambda env: env["dsse"]["signatures"].append(value))
    else:
        scenario.set("postreg0", path, value)
    report = scenario.verify("chain", "keyconsist")
    assert report["code"] == ("asexec-verify/1 chain=FAIL format=PASS keyconsist=FAIL selfsig=FAIL")
    (commitment,) = report["commitments"]
    assert commitment["counted_postregs"] == []
    (rejected,) = commitment["rejected_postregs"]
    assert rejected["reason"] == "invalid signature"
    postreg = json.loads(scenario.read("postreg0"))
    signatures = postreg["dsse"]["signatures"]
    assert rejected["keyid"] == (signatures[0].get("keyid") if signatures else None)
    assert report["notarization_only"] == []


@pytest.mark.parametrize(
    "path,value",
    [
        ("dsse.signatures", "x"),
        ("dsse.payloadType", "application/vnd.asexec.v2+json"),
    ],
    ids=["signatures-not-array", "newer-format"],
)
def test_run__prereg_failing_format_is_not_a_provided_prereg(scenario, path, value):
    """A prereg that fails format (here: no array of signatures, or a format this release
    does not read) is not a provided prereg: there is no commitment, and a valid postreg
    naming it is notarization-only, so chain and keyconsist have nothing to examine."""
    scenario.drop("postreg1")
    scenario.drop("postreg2")
    scenario.set("prereg", path, value)
    report = scenario.verify("chain", "keyconsist")
    assert report["code"] == ("asexec-verify/1 chain=FAIL format=FAIL keyconsist=FAIL selfsig=PASS")
    assert report["results"]["selfsig"]["applicable"] == 1  # the postreg, which is valid
    assert report["results"]["keyconsist"]["applicable"] == 0
    assert report["commitments"] == []
    (lone,) = report["notarization_only"]
    assert lone["fulfills"] == d.ref(d.decoded(json.loads(scenario.read("prereg"))))


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
    pytest.param("hash_alg", ["a"], id="body-hash_alg-not-string"),
    pytest.param("subject", [{"name": "a", "hash_alg": ["a"], "digest": {}}], id="entry-hash_alg"),
    pytest.param("subject", [{"name": "a", "hash_alg": {}, "digest": []}], id="entry-hash_alg-obj"),
    pytest.param("subject", [{"name": ["a"], "hash_alg": "sha-256"}], id="entry-name-list"),
    pytest.param("fulfills", {"a": 1}, id="fulfills-not-string"),
    pytest.param("prev_hash", ["a"], id="prev_hash-not-string"),
    pytest.param("due", ["a"], id="due-not-string"),
    pytest.param("plan", "x", id="plan-not-object"),
    pytest.param("plan", [1], id="plan-list"),
    pytest.param("plan", {"name": {}, "hash_alg": [], "digest": "x"}, id="plan-fields"),
    pytest.param("items", "x", id="items-not-list"),
    pytest.param("items", [1, {"id": {}}, {"kind": 5}], id="items-entries"),
    pytest.param("items", {"id": "S1"}, id="items-object"),
    pytest.param("item_id", {"a": 1}, id="item_id-object"),
    pytest.param("item_id", ["S1"], id="item_id-list"),
    pytest.param("status", 5, id="status-number"),
    pytest.param("status", ["reported"], id="status-list"),
    pytest.param("items", [{"id": "S1"}, {"id": "S1"}, {"id": []}], id="items-repeat-and-junk"),
    pytest.param("items", [{"id": "\x00"}], id="items-nul-id"),
    pytest.param("evidence", "x", id="evidence-not-list"),
    pytest.param("evidence", [{"name": None, "digest": 5}], id="evidence-entry-fields"),
    pytest.param("evidence", {}, id="evidence-object"),
]


@pytest.mark.parametrize("field,value", SIGNED_JUNK)
def test_never_raises__validly_signed_junk_in_a_body_field(scenario, field, value):
    """selfsig checks only the signature, so a signed-but-junk body must not crash any test."""
    scenario.set("postreg1", f"body.{field}", value)
    if field not in ("fulfills", "prev_hash"):
        scenario.set("prereg", f"body.{field}", value)
    tests = ("ceiling", "chain", "complete", "content", "floor", "keyconsist", "order", "timely")
    report = scenario.verify(*tests)
    assert {"format=PASS", "selfsig=PASS"} <= set(report["code"].split()[1:])


@pytest.mark.parametrize(
    "junk",
    [
        pytest.param("x", id="not-object"),
        pytest.param([1], id="list"),
        pytest.param({"ceiling_type": "roughtime", "witness_id": [], "nonce": 5}, id="fields"),
        pytest.param({"ceiling_type": "roughtime", "response": "zz"}, id="response-not-hex"),
        pytest.param({"midpoint": "soon", "radius": [1]}, id="unsigned-time-junk"),
    ],
)
def test_never_raises__junk_ceiling_on_a_counted_postreg(scenario, junk):
    """A counted postreg whose ceiling is junk is not shown on time (timely #3); it never
    raises."""
    scenario.with_ceiling("postreg0")
    scenario.ceilings["postreg0"] = lambda nonce_hex: junk
    report = scenario.verify("ceiling", "timely")
    assert report["code"] == "asexec-verify/1 ceiling=FAIL format=PASS selfsig=PASS timely=FAIL"


def test_never_raises__witness_time_past_year_9999(scenario, make_server):
    """A witness-signed MIDP of 2**62 microseconds (year ~146,000) has no ISO-8601 form:
    the time is still compared, and shown as epoch seconds, never raised on."""
    pub, sign = make_server(midpoint_us=2**62, maxt=2**63)
    scenario.server_pub, scenario.sign_response = pub, sign
    scenario.pin_server(pub)
    for name in ("prereg", "postreg0", "postreg1", "postreg2"):
        scenario.with_ceiling(name)
    report = scenario.verify("ceiling", "complete", "order", "timely")
    assert report["code"] == (
        "asexec-verify/1 ceiling=PASS complete=FAIL format=PASS order=FAIL selfsig=PASS timely=FAIL"
    )
    assert all("epoch seconds" in line for line in report["ceiling_trust"])


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
    scenario.set("prereg", f"body.anchor.floor.{path}", value)
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


@pytest.mark.parametrize(
    "path,value",
    [
        pytest.param("round", 2**70, id="round-overflows-8-bytes"),
        pytest.param("round", -1, id="round-negative"),
        pytest.param("round", 0, id="round-zero"),
        pytest.param("round", True, id="round-bool"),
        pytest.param("signature", 5, id="signature-not-string"),
        pytest.param("randomness", [], id="randomness-a-list"),
        pytest.param("chain_hash", [], id="chain_hash-not-string"),
        pytest.param("floor_type", {}, id="floor_type-not-string"),
    ],
)
def test_never_raises__junk_floor_on_a_counted_postreg(scenario, path, value):
    """order reads the floor of each counted postreg: a validly signed but malformed one is
    no time (order #4), and never raises."""
    scenario.with_ceiling("prereg")
    scenario.set("postreg0", "body.anchor.floor", {**d.FLOOR, path: value})
    report = scenario.verify("floor", "order")
    assert report["code"] == "asexec-verify/1 floor=FAIL format=PASS order=FAIL selfsig=PASS"


@pytest.mark.parametrize(
    "junk",
    [
        pytest.param("x", id="not-object"),
        pytest.param([1], id="list"),
        pytest.param({"ceiling_type": "roughtime", "witness_id": [], "nonce": 5}, id="fields"),
        pytest.param({"ceiling_type": "roughtime", "response": "zz"}, id="response-not-hex"),
        pytest.param({"midpoint": "soon", "radius": [1]}, id="unsigned-time-junk"),
    ],
)
def test_never_raises__junk_ceiling_on_a_prereg(scenario, junk):
    """order reads the prereg's ceiling: a junk one is no time (order #2), and never raises."""
    scenario.with_ceiling("prereg")
    scenario.ceilings["prereg"] = lambda nonce_hex: junk
    report = scenario.verify("ceiling", "order")
    assert report["code"] == "asexec-verify/1 ceiling=FAIL format=PASS order=FAIL selfsig=PASS"


@pytest.mark.parametrize(
    "keyid", [{"a": 1}, ["a"], 5], ids=["keyid-object", "keyid-list", "keyid-number"]
)
@pytest.mark.parametrize("name", ["prereg", "postreg0"])
def test_never_raises__keyid_not_a_string(scenario, name, keyid):
    """A dsse.signatures[0].keyid that is not a string passes format and fails selfsig (#4),
    as a prereg or a postreg; it never raises. Such a prereg is no commitment, and such a
    postreg is rejected for invalid signature."""
    scenario.set(name, "dsse.signatures[0].keyid", keyid)
    report = scenario.verify("chain", "keyconsist")
    assert {"format=PASS", "selfsig=FAIL"} <= set(report["code"].split()[1:])
    if name == "prereg":
        assert report["commitments"] == []
        (rejected,) = report["rejected_preregs"]
        assert rejected["keyid"] == keyid
        assert rejected["reason"] == "invalid signature"
    else:
        (commitment,) = report["commitments"]
        (rejected,) = commitment["rejected_postregs"]
        assert rejected["keyid"] == keyid
        assert rejected["reason"] == "invalid signature"


# A lone surrogate escape is valid JSON text, and the body bytes are never re-serialized, so
# a body may hold one, validly signed. It is a string that equals no ref, parses as no time
# and names no file: it fails only the tests that compare it, and never raises.
LONE = b'"\\ud800"'


def _lone(scenario, name, path):
    scenario.set(name, path, "LONE")
    scenario.edit_body_bytes(name, lambda raw: raw.replace(b'"LONE"', LONE))


@pytest.mark.parametrize(
    "name,path",
    [
        ("prereg", "body.phase"),
        ("prereg", "body.target"),
        ("prereg", "body.declaration"),
        ("prereg", "body.notes"),
        ("prereg", "body.due"),
        ("prereg", "body.subject.0.hash_alg"),
        ("prereg", "body.subject.0.name"),
        ("prereg", "body.subject.0.digest.sha-256"),
        ("postreg0", "body.fulfills"),
        ("postreg1", "body.prev_hash"),
    ],
)
def test_never_raises__lone_surrogate_escape_in_the_body(scenario, name, path):
    """A lone surrogate escape in any body string passes format and selfsig (the bytes are as
    signed), and every other test judges it as the string it is, without raising."""
    scenario.with_ceiling("prereg")
    _lone(scenario, name, path)
    report = scenario.verify("ceiling", "chain", "content", "keyconsist")
    assert {"format=PASS", "selfsig=PASS", "ceiling=PASS"} <= set(report["code"].split()[1:])


@pytest.mark.parametrize("name", ["\ud800", "harness\x00.py"], ids=["lone-surrogate", "nul"])
def test_never_raises__subject_named_as_no_path_can_be(scenario, name):
    """content #6: a subject name that no path on this system can have (a lone surrogate,
    or a NUL) names no artifact: it is not found, and verify does not raise."""
    if name == "\ud800":
        _lone(scenario, "prereg", "body.subject.0.name")
    else:
        scenario.set("prereg", "body.subject.0.name", name)
    report = scenario.verify("content")
    assert report["code"] == "asexec-verify/1 content=FAIL format=PASS selfsig=PASS"
    (prereg,) = [m for m in report["manifests"] if m["phase"] == "prereg"]
    assert prereg["content"]["entries"] == [
        {"field": "subject", "name": name, "ok": False, "reason": "artifact not found"}
    ]


def test_never_raises__lone_surrogate_escape_as_due_or_link(scenario):
    """A lone surrogate due is not a parseable time (invalid-due); one as fulfills names no
    prereg (notarization-only)."""
    _lone(scenario, "prereg", "body.due")
    _lone(scenario, "postreg0", "body.fulfills")
    scenario.drop("postreg1")
    scenario.drop("postreg2")
    report = scenario.verify()
    assert report["code"] == "asexec-verify/1 format=PASS selfsig=PASS"
    (commitment,) = report["commitments"]
    assert commitment["due"] == "\ud800"
    assert commitment["state"] == "invalid-due"
    (lone,) = report["notarization_only"]
    assert lone["fulfills"] == "\ud800"


def test_never_raises__lone_surrogate_escape_as_a_claimed_keyid(scenario):
    """A dsse.signatures[0].keyid holding a lone surrogate fails selfsig #4 and, on a prereg,
    is listed as the rejected pre-registration's keyid."""
    scenario.set("prereg", "dsse.signatures[0].keyid", "\ud800")
    report = scenario.verify("chain", "keyconsist")
    assert {"format=PASS", "selfsig=FAIL"} <= set(report["code"].split()[1:])
    (rejected,) = report["rejected_preregs"]
    assert rejected["keyid"] == "\ud800"
