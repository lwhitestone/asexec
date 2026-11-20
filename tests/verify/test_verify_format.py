"""``format`` (the file can be read): docs/VERIFICATION.md `### format`. Naming: see conftest.py.

``selfsig`` does not examine a file that fails ``format``, so a malformed file, or one of a
format this release does not read, among valid ones reads ``format=FAIL selfsig=PASS``: the
code tells "unreadable" and "upgrade" apart from "changed since it was signed"
(``test_verify_selfsig.py``). Malformed means only what stops verify reading a manifest: a
missing or non-hex ``pubkey`` or ``sig``, or the wrong number of signatures, is judged by
``selfsig``.
"""

import base64
import hashlib
import json
import os

import manifest_data as d
import pytest

from asexec.verifier import verify_paths

PASS = "asexec-verify/1 format=PASS selfsig=PASS"
FAIL = "asexec-verify/1 format=FAIL selfsig=PASS"  # selfsig still passes the other files
REQUIRED = ["format", "selfsig"]
NONE_PASSES = "no manifest passes format"
NEWER = "payloadType names a format newer than this release: upgrade asexec to read it"
BETA = "payloadType names an asexec beta format, and betas are not supported"
PRE_V1 = (
    "payloadType names the format of asexec before 0.4.0, which is not supported:"
    " re-sign with this release"
)
NOT_BASE64 = (
    "malformed: dsse.payload: Value error, not strict base64 (the standard alphabet, padded,"
    " no whitespace, one spelling per byte string)"
)
_MISSING = object()


def _entry(report, name):
    (entry,) = [m for m in report["manifests"] if m["path"].endswith(f"{os.sep}{name}.json")]
    return entry


def _errors(scenario, name="postreg0"):
    report = scenario.verify()
    assert report["code"] == FAIL
    assert report["results"]["selfsig"]["applicable"] == 3  # the malformed file is not examined
    return _entry(report, name)["format"]["errors"]


def test_format__pass__all(scenario):
    """format #1-#3: every file is a JSON object with an object dsse holding a string
    payloadType and an array of signatures, its dsse.payload is strict base64 of a JSON
    object, and its payloadType names a format this release reads."""
    report = scenario.verify()
    assert report["code"] == PASS
    assert report["ok"] is True
    assert len(report["manifests"]) == 4
    assert report["results"]["format"]["applicable"] == 4


MALFORMED_FILES = {
    "empty": "",
    "not-json": "{nope",
    "binary": b"\xff\xfe\x00",
    "array": "[1, 2]",
    "string": '"x"',
    "null": "null",
    "missing-dsse": json.dumps({"pubkey": "00"}),
    "dsse-not-object": json.dumps({"dsse": [d.MANIFEST_PAYLOAD_TYPE]}),
    "missing-signatures": json.dumps(
        {"dsse": {"payloadType": d.MANIFEST_PAYLOAD_TYPE, "payload": "e30="}}
    ),
    "missing-payload": json.dumps(
        {"dsse": {"payloadType": d.MANIFEST_PAYLOAD_TYPE, "signatures": []}}
    ),
}


def _with_unsigned_nesting(raw: str, levels: int) -> str:
    """``raw`` (a file, nested 1 deep at its top) plus an unsigned field ``levels`` arrays
    deep, so the file nests ``1 + levels`` deep."""
    return raw.rstrip()[:-1] + ', "junk": ' + "[" * levels + "]" * levels + "}"


def _nested_body(levels: int) -> bytes:
    """Body bytes of an object holding an array ``levels`` deep: nested ``1 + levels``."""
    return b'{"phase":"prereg","junk":' + b"[" * levels + b"]" * levels + b"}"


def test_format__pass__1_nesting_at_the_limit(scenario):
    """format #1: a file nested exactly 64 deep is well-formed."""
    scenario.add_raw("deep", _with_unsigned_nesting(scenario.read("prereg"), 63))
    assert scenario.code() == PASS


def test_format__pass__1_brackets_inside_strings_do_not_nest(scenario):
    """format #1: only arrays and objects nest; brackets in a string, escaped quote and all,
    don't."""
    raw = scenario.read("prereg").rstrip()[:-1] + ', "junk": "\\"' + "[{" * 100 + '"}'
    scenario.add_raw("brackets", raw)
    assert scenario.code() == PASS


def test_format__pass__2_body_nesting_is_counted_in_the_body_alone(scenario):
    """format #2: the body is held to the file's JSON rules on its own. Its outermost object
    is level 1, whatever depth the file holds it at, so a body nested exactly 64 deep is
    well-formed."""
    scenario.edit_body_bytes("prereg", lambda raw: _nested_body(63))
    assert scenario.code() == PASS


def test_format__pass__2_brackets_inside_body_strings_do_not_nest(scenario):
    """format #2: in the body too, brackets inside a string don't nest."""
    scenario.set("prereg", "body.notes", '\\"' + "[{" * 100)
    assert scenario.code() == PASS


def test_format__pass__2_body_bytes_are_read_as_stored(scenario):
    """format #2: any JSON object text is a body, however it is spaced or ordered. Nothing
    re-serializes it: ref is the sha-256 of the bytes as stored, and selfsig checks them."""
    raw = b'{ "target" : "m",\n  "phase": "prereg"\n}\n'
    scenario.drop("postreg0")
    scenario.drop("postreg1")
    scenario.drop("postreg2")
    scenario.edit_body_bytes("prereg", lambda _raw: raw)
    report = scenario.verify()
    assert report["code"] == PASS
    assert _entry(report, "prereg")["ref"] == "sha-256:" + hashlib.sha256(raw).hexdigest()


def test_format__pass__2_lone_surrogate_escape_in_the_body_is_valid_json(scenario):
    """format #2: a lone surrogate escape (``"\\ud800"``) is valid JSON text. The body bytes
    are stored and checked as they are, so it passes format and its signature verifies."""
    scenario.set("prereg", "body.notes", "LONE")
    scenario.edit_body_bytes("prereg", lambda raw: raw.replace(b'"LONE"', b'"\\ud800"'))
    assert b"\\ud800" in d.decoded(json.loads(scenario.read("prereg")))
    assert scenario.code() == PASS


@pytest.mark.parametrize("raw", MALFORMED_FILES.values(), ids=MALFORMED_FILES.keys())
def test_format__fail__1_well_formed_file(scenario, raw):
    """format #1: the file is a JSON object, with an object dsse that holds a string
    payloadType and an array of signatures."""
    scenario.add_raw("bad", raw)
    report = scenario.verify()
    assert report["code"] == FAIL
    assert report["results"]["format"]["applicable"] == 5
    assert report["results"]["selfsig"]["applicable"] == 4  # the malformed file is not examined


def test_format__fail__1_no_duplicate_keys(scenario):
    """format #1: no duplicate JSON keys in the file. The repeat has the same value, so the
    file would verify if either copy were accepted: only the duplicate itself can fail it."""
    raw = scenario.read("prereg")
    pubkey = json.loads(raw)["pubkey"]
    dup = raw.replace(f'"pubkey": "{pubkey}"', f'"pubkey": "{pubkey}", "pubkey": "{pubkey}"', 1)
    assert dup != raw
    scenario.add_raw("dup", dup)
    assert scenario.code() == FAIL


def test_format__fail__1_nested_at_most_64_deep(scenario):
    """format #1: a file nested 65 deep is malformed, even where the extra level is unsigned."""
    scenario.add_raw("deep", _with_unsigned_nesting(scenario.read("prereg"), 64))
    assert scenario.code() == FAIL


def test_format__fail__1_missing_file_is_examined_and_malformed(tmp_path):
    """format #1: a path that is not a directory is examined even if it does not exist. It
    is the only file and fails format, so selfsig has nothing to examine."""
    report = verify_paths([str(tmp_path / "absent.json")], REQUIRED)
    assert report["code"] == "asexec-verify/1 format=FAIL selfsig=FAIL"
    assert report["results"]["format"]["applicable"] == 1
    assert report["results"]["selfsig"]["applicable"] == 0
    assert report["results"]["selfsig"]["reason"] == NONE_PASSES


def test_format__fail__1_unlistable_directory_is_examined_and_malformed(tmp_path, monkeypatch):
    """format #1: a directory that cannot be listed is examined itself, as malformed, never
    an exception."""

    def denied(path):
        raise PermissionError(13, "Permission denied", path)

    monkeypatch.setattr(os, "listdir", denied)
    report = verify_paths([str(tmp_path)], REQUIRED)
    assert report["code"] == "asexec-verify/1 format=FAIL selfsig=FAIL"
    assert report["results"]["format"]["applicable"] == 1
    (entry,) = report["manifests"]
    assert entry["path"] == str(tmp_path)
    assert entry["format"]["errors"] == [f"malformed: [Errno 13] Permission denied: '{tmp_path}'"]


@pytest.mark.parametrize(
    "value,error",
    [
        (_MISSING, "malformed: dsse: Field required"),
        (None, "malformed: dsse: Field required"),
        ([], "malformed: dsse: Input should be a valid dictionary or instance of DsseInput"),
        ("x", "malformed: dsse: Input should be a valid dictionary or instance of DsseInput"),
    ],
    ids=["missing", "null", "list", "string"],
)
def test_format__fail__1_dsse_is_an_object(scenario, value, error):
    """format #1: the file holds an object dsse."""
    if value is _MISSING:
        scenario.unset("postreg0", "dsse")
    else:
        scenario.set("postreg0", "dsse", value)
    assert _errors(scenario) == [error]


@pytest.mark.parametrize(
    "value,error",
    [
        (_MISSING, "malformed: dsse.payloadType: Field required"),
        (None, "malformed: dsse.payloadType: Field required"),
        (1, "malformed: dsse.payloadType: Input should be a valid string"),
        ([d.MANIFEST_PAYLOAD_TYPE], "malformed: dsse.payloadType: Input should be a valid string"),
        ({}, "malformed: dsse.payloadType: Input should be a valid string"),
    ],
    ids=["missing", "null", "number", "list", "object"],
)
def test_format__fail__1_payload_type_is_a_string(scenario, value, error):
    """format #1: dsse holds a string payloadType. A file without one is malformed, and is
    never read under some format's rules instead. A payloadType at the top level, where
    the format is not read, does not stand in for it."""
    if value is _MISSING:
        scenario.unset("postreg0", "dsse.payloadType")
    else:
        scenario.set("postreg0", "dsse.payloadType", value)
    scenario.set("postreg0", "payloadType", d.MANIFEST_PAYLOAD_TYPE)
    assert _errors(scenario) == [error]


@pytest.mark.parametrize(
    "value,error",
    [
        (_MISSING, "malformed: dsse.signatures: Field required"),
        (None, "malformed: dsse.signatures: Field required"),
        ({}, "malformed: dsse.signatures: Input should be a valid list"),
        ("x", "malformed: dsse.signatures: Input should be a valid list"),
    ],
    ids=["missing", "null", "object", "string"],
)
def test_format__fail__1_signatures_is_an_array(scenario, value, error):
    """format #1: dsse holds an array signatures. What it holds is selfsig's to judge."""
    if value is _MISSING:
        scenario.unset("postreg0", "dsse.signatures")
    else:
        scenario.set("postreg0", "dsse.signatures", value)
    assert _errors(scenario) == [error]


# A small body, validly signed: 31 bytes, so its base64 ends "==".
SMALL = d.sign_bytes(b'{"phase":"prereg","target":"m"}')


def _raw_errors(scenario, payload):
    """The format errors of SMALL with dsse.payload replaced by ``payload`` (removed if
    _MISSING), beside the scenario's four valid files."""
    envelope = json.loads(json.dumps(SMALL))
    if payload is _MISSING:
        del envelope["dsse"]["payload"]
    else:
        envelope["dsse"]["payload"] = payload
    scenario.add_raw("bad", json.dumps(envelope))
    report = scenario.verify()
    assert report["code"] == FAIL
    assert report["results"]["selfsig"]["applicable"] == 4
    return _entry(report, "bad")["format"]["errors"]


def test_format__pass__2_small_body_as_signed(scenario):
    """format #2: the body the strict base64 cases below respell passes as it was signed."""
    spelled = SMALL["dsse"]["payload"]
    assert spelled == "eyJwaGFzZSI6InByZXJlZyIsInRhcmdldCI6Im0ifQ=="
    scenario.add_raw("small", json.dumps(SMALL))
    assert scenario.code() == PASS


_SPELLED = SMALL["dsse"]["payload"]


@pytest.mark.parametrize(
    "payload,error",
    [
        (_MISSING, "malformed: dsse.payload: Field required"),
        (None, "malformed: dsse.payload: Field required"),
        (5, "malformed: dsse.payload: Input should be a valid string"),
        ([_SPELLED], "malformed: dsse.payload: Input should be a valid string"),
        (_SPELLED.rstrip("="), NOT_BASE64),
        (_SPELLED[:-1], NOT_BASE64),
        (_SPELLED + "=", NOT_BASE64),
        (_SPELLED[:10] + "\n" + _SPELLED[10:], NOT_BASE64),
        (_SPELLED[:10] + " " + _SPELLED[10:], NOT_BASE64),
        (_SPELLED + "\n", NOT_BASE64),
        (_SPELLED[:10] + "-" + _SPELLED[11:], NOT_BASE64),
        (_SPELLED[:10] + "_" + _SPELLED[11:], NOT_BASE64),
        (_SPELLED[:10] + "!" + _SPELLED[11:], NOT_BASE64),
        (_SPELLED[:10] + "é" + _SPELLED[11:], NOT_BASE64),
        (_SPELLED[:-3] + "R==", NOT_BASE64),
    ],
    ids=[
        "missing",
        "null",
        "number",
        "list",
        "padding-dropped",
        "padding-short",
        "padding-extra",
        "newline-inside",
        "space-inside",
        "newline-after",
        "url-safe-minus",
        "url-safe-underscore",
        "outside-the-alphabet",
        "not-ascii",
        "unused-bits-set",
    ],
)
def test_format__fail__2_payload_is_strict_base64(scenario, payload, error):
    """format #2: dsse.payload is strict base64: the standard alphabet, padded, with no
    whitespace, and the one spelling base64 encoding gives its bytes (no unused bit set in
    the last character). The signature is left as it was, so only the spelling fails it."""
    assert _raw_errors(scenario, payload) == [error]


@pytest.mark.parametrize("spelled", ["e31=", "e32=", "e33="])
def test_format__fail__2_payload_has_one_spelling_per_byte_string(scenario, spelled):
    """format #2: each of these decodes to the bytes ``{}``, but only ``e30=`` is their
    base64: the others set unused bits. So a body has one dsse.payload, and the file that
    spells it otherwise is malformed even where its signature is valid."""
    assert base64.b64decode(spelled) == b"{}"
    envelope = d.sign_bytes(b"{}")
    assert envelope["dsse"]["payload"] == "e30="
    scenario.add_raw("canonical", json.dumps(envelope))
    envelope["dsse"]["payload"] = spelled
    scenario.add_raw("respelled", json.dumps(envelope))
    report = scenario.verify()
    assert report["code"] == FAIL
    assert _entry(report, "canonical")["format"]["errors"] == []
    assert _entry(report, "respelled")["format"]["errors"] == [NOT_BASE64]


@pytest.mark.parametrize(
    "raw",
    [
        b'{"phase":"prereg","notes":"caf\xe9"}',  # Latin-1, not UTF-8
        b'{"phase":"prereg","notes":"\xed\xa0\x80"}',  # a surrogate encoded as if UTF-8
        b'\xef\xbb\xbf{"phase":"prereg"}',  # a byte order mark
        '{"phase":"prereg"}'.encode("utf-16"),
    ],
    ids=["latin-1", "encoded-surrogate", "bom", "utf-16"],
)
def test_format__fail__2_body_is_utf8(scenario, raw):
    """format #2: the body bytes are UTF-8 JSON text (RFC 8259), with no byte order mark.
    They are validly signed: the encoding alone fails them."""
    scenario.edit_body_bytes("postreg0", lambda _raw: raw)
    (error,) = _errors(scenario)
    assert error.startswith("malformed: body: ")


@pytest.mark.parametrize(
    "raw,error",
    [
        (b"", "malformed: body: Expecting value: line 1 column 1 (char 0)"),
        (b"{nope", "malformed: body: Expecting property name enclosed in double quotes:"),
        (b'{"phase":"prereg"', "malformed: body: Expecting ',' delimiter:"),
        (b'{"phase":"prereg"} {}', "malformed: body: Extra data:"),
        (b"[1, 2]", "malformed: body: the body must be a JSON object"),
        (b'"x"', "malformed: body: the body must be a JSON object"),
        (b"null", "malformed: body: the body must be a JSON object"),
        (b"1", "malformed: body: the body must be a JSON object"),
    ],
    ids=["empty", "not-json", "truncated", "two-values", "array", "string", "null", "number"],
)
def test_format__fail__2_body_is_a_json_object(scenario, raw, error):
    """format #2: the body bytes are the JSON text of an object, validly signed or not."""
    scenario.edit_body_bytes("postreg0", lambda _raw: raw)
    (reason,) = _errors(scenario)
    assert reason.startswith(error)


def test_format__fail__2_body_has_no_duplicate_keys(scenario):
    """format #2: no duplicate JSON keys in the body, checked on the body itself (the file
    holds it as a string). The repeat has the same value and is validly signed, so only the
    duplicate can fail it."""

    def duplicate(raw):
        dup = raw.replace(b'"phase":"postreg"', b'"phase":"postreg","phase":"postreg"', 1)
        assert dup != raw
        return dup

    scenario.edit_body_bytes("postreg0", duplicate)
    assert _errors(scenario) == ["malformed: body: duplicate JSON key 'phase'"]


def test_format__fail__2_duplicate_key_nested_in_the_body(scenario):
    """format #2: a duplicate key at any level of the body."""
    scenario.edit_body_bytes(
        "postreg0", lambda raw: raw.replace(b'"model_id":"m"', b'"model_id":"m","model_id":"x"', 1)
    )
    assert _errors(scenario) == ["malformed: body: duplicate JSON key 'model_id'"]


def test_format__fail__2_body_nested_at_most_64_deep(scenario):
    """format #2: a body nested 65 deep is malformed, though the file around it nests only 3
    deep: the body's depth is counted in the body alone."""
    scenario.edit_body_bytes("postreg0", lambda raw: _nested_body(64))
    assert _errors(scenario) == ["malformed: body: nested more than 64 deep"]


@pytest.mark.parametrize(
    "payload_type,reason",
    [
        ("application/vnd.asexec.v2+json", NEWER),
        ("application/vnd.asexec.v10+json", NEWER),
        ("application/something-else", NEWER),
        ("", NEWER),
        (d.MANIFEST_PAYLOAD_TYPE.upper(), NEWER),
        (d.MANIFEST_PAYLOAD_TYPE + " ", NEWER),
        ("application/vnd.asexec.0.3.0b1+json", BETA),
        ("application/vnd.asexec.1.12.3b20+json", BETA),
        ("application/vnd.asexec+json", PRE_V1),
    ],
    ids=[
        "v2",
        "v10",
        "not-asexec",
        "empty",
        "other-case",
        "trailing-space",
        "beta",
        "beta-wide",
        "before-0.4.0",
    ],
)
def test_format__fail__3_payload_type_names_a_known_format(scenario, payload_type, reason):
    """format #3: dsse.payloadType names a format this release reads, exactly. A file that
    names another fails format with a reason saying which kind it is, and is not examined by
    selfsig, which still passes for the other files: version skew reads as format=FAIL, not
    as a bad signature. The type is changed after signing, so the file's signature no longer
    covers it either; only format judges it."""
    scenario.set("postreg0", "dsse.payloadType", payload_type)
    report = scenario.verify()
    assert report["code"] == FAIL
    assert report["results"]["format"]["reason"] == "1/4 manifest(s) failed"
    assert report["results"]["selfsig"]["applicable"] == 3
    assert _entry(report, "postreg0")["format"]["errors"] == [reason]


def test_format__fail__3_unknown_format_is_not_judged_by_this_formats_frame(scenario):
    """format #3: a file of a format this release does not read is held only to the part of
    #1 that comes before any format (a readable JSON object, nested at most 64 deep, with no
    duplicate keys, and a string dsse.payloadType): a newer format may lay out the rest
    differently. With no signatures and a payload that is not base64, it fails with the
    upgrade reason, not as malformed."""
    scenario.add_raw(
        "v2", '{"dsse": {"payloadType": "application/vnd.asexec.v2+json", "payload": "?"}}'
    )
    report = scenario.verify()
    assert report["code"] == FAIL
    assert report["results"]["selfsig"]["applicable"] == 4
    assert _entry(report, "v2")["format"]["errors"] == [NEWER]


def test_format__fail__3_never_falls_back_to_this_releases_rules(scenario):
    """format #3: a file whose signature would verify under this release's rules with its own
    payloadType in the PAE still fails format: no other entry's rules are applied to it."""
    scenario.add_raw(
        "labelled", json.dumps(d.sign_labelled(d.PREREG, "application/vnd.asexec.v2+json"))
    )
    report = scenario.verify()
    assert report["code"] == FAIL
    assert report["results"]["selfsig"]["applicable"] == 4
    assert _entry(report, "labelled")["format"]["errors"] == [NEWER]


@pytest.mark.parametrize(
    "payload_type,errors",
    [
        ("application/vnd.asexec+json", [PRE_V1]),
        (d.MANIFEST_PAYLOAD_TYPE, ["malformed: dsse: Field required"]),
    ],
    ids=["0.3.x-type", "current-type"],
)
def test_format__fail__3_file_laid_out_before_0_4_0(scenario, payload_type, errors):
    """format #3: a file laid out as asexec wrote it before 0.4.0 (no dsse; a top-level
    payloadType, payload object and signature) with the type those releases wrote fails
    format with the pre-0.4.0 reason. Under any other type that layout is malformed."""
    old = {
        "payloadType": payload_type,
        "payload": d.PREREG,
        "signature": {"alg": "ed25519", "keyid": "sha-256:00", "pubkey": "00", "sig": "00"},
    }
    scenario.add_raw("old", json.dumps(old))
    report = scenario.verify()
    assert report["code"] == FAIL
    assert _entry(report, "old")["format"]["errors"] == errors


def test_format__fail__empty_no_manifests():
    """format (*): with no manifest to verify, format fails rather than passing with nothing
    examined, and so does selfsig."""
    report = verify_paths([], REQUIRED)
    assert report["code"] == "asexec-verify/1 format=FAIL selfsig=FAIL"
    assert report["results"]["format"]["reason"] == "no manifests to verify"
    assert report["results"]["selfsig"]["reason"] == NONE_PASSES


def test_format__fail__empty_directory_with_no_json_files(tmp_path):
    """format (*): a directory with no *.json file in it yields no manifest file to examine."""
    (tmp_path / "notes.txt").write_text("not a manifest")
    report = verify_paths([str(tmp_path)], REQUIRED)
    assert report["code"] == "asexec-verify/1 format=FAIL selfsig=FAIL"
    assert report["results"]["format"]["applicable"] == 0
    assert report["results"]["format"]["reason"] == "no manifests to verify"
