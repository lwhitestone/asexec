"""``format`` (the file can be read): docs/VERIFICATION.md `### format`. Naming: see conftest.py.

``selfsig`` does not examine a file that fails ``format``, so a malformed file, or one of a
format this release does not read, among valid ones reads ``format=FAIL selfsig=PASS``: the
code tells "unreadable" and "upgrade" apart from "changed since it was signed"
(``test_verify_selfsig.py``).
"""

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
_MISSING = object()


def _entry(report, name):
    (entry,) = [m for m in report["manifests"] if m["path"].endswith(f"{os.sep}{name}.json")]
    return entry


def test_format__pass__all(scenario):
    """format #1-#3: every file is a JSON object with an object payload, a string
    payloadType and an object signature, has hex pubkey and sig, and names a format this
    release reads."""
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
    "missing-payload": '{"payloadType": "application/vnd.asexec.v1+json", "signature": {}}',
    "missing-signature": '{"payloadType": "application/vnd.asexec.v1+json", "payload": {}}',
}


def _spaced_upper(hex_str: str) -> str:
    """The same bytes as ``hex_str``, in uppercase with whitespace between byte pairs."""
    pairs = [hex_str[i : i + 2].upper() for i in range(0, len(hex_str), 2)]
    return " ".join(pairs[:4]) + "\n\t" + "".join(pairs[4:])


def _with_unsigned_nesting(raw: str, levels: int) -> str:
    """``raw`` (an envelope, nested 1 deep at its top) plus an unsigned field ``levels``
    arrays deep, so the file nests ``1 + levels`` deep."""
    return raw.rstrip()[:-1] + ', "junk": ' + "[" * levels + "]" * levels + "}"


def test_format__pass__1_nesting_at_the_limit(scenario):
    """format #1: a file nested exactly 64 deep is well-formed."""
    scenario.add_raw("deep", _with_unsigned_nesting(scenario.read("prereg"), 63))
    assert scenario.code() == PASS


def test_format__pass__1_brackets_inside_strings_do_not_nest(scenario):
    """format #1: only arrays and objects nest; brackets in a string, escaped quote and all,
    don't."""
    scenario.set("prereg", "payload.notes", '\\"' + "[{" * 100)
    assert scenario.code() == PASS


@pytest.mark.parametrize("field", ["pubkey", "sig"])
def test_format__pass__2_hex_accepts_either_case_and_whitespace(scenario, field):
    """format #2: hex is what bytes.fromhex accepts (Conventions, Hex), case and spacing
    aside. The bytes are unchanged, so selfsig passes too."""

    def respell(envelope):
        envelope["signature"][field] = _spaced_upper(envelope["signature"][field])

    scenario.tamper("postreg0", respell)
    assert scenario.code() == PASS


@pytest.mark.parametrize("raw", MALFORMED_FILES.values(), ids=MALFORMED_FILES.keys())
def test_format__fail__1_well_formed_file(scenario, raw):
    """format #1: the file is a JSON object, with an object payload and signature."""
    scenario.add_raw("bad", raw)
    report = scenario.verify()
    assert report["code"] == FAIL
    assert report["results"]["format"]["applicable"] == 5
    assert report["results"]["selfsig"]["applicable"] == 4  # the malformed file is not examined


def test_format__fail__1_no_duplicate_keys(scenario):
    """format #1: no duplicate JSON keys. The repeat has the same value, so the payload would
    verify if either copy were accepted: only the duplicate itself can fail it."""
    raw = scenario.read("prereg")
    dup = raw.replace('"phase": "prereg"', '"phase": "prereg", "phase": "prereg"', 1)
    assert dup != raw
    scenario.add_raw("dup", dup)
    assert scenario.code() == FAIL


def test_format__fail__1_nested_at_most_64_deep(scenario):
    """format #1: a file nested 65 deep is malformed, even where the extra level is unsigned."""
    scenario.add_raw("deep", _with_unsigned_nesting(scenario.read("prereg"), 64))
    assert scenario.code() == FAIL


def test_format__fail__1_payload_has_canonical_bytes(scenario):
    """format #1: a lone surrogate escape is valid JSON but has no UTF-8 form, so the payload
    has no canonical bytes."""
    scenario.set("prereg", "payload.notes", "LONE")
    raw = scenario.read("prereg").replace('"LONE"', '"\\ud800"')
    assert "\\ud800" in raw
    scenario.add_raw("lone", raw)
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
        (_MISSING, "malformed: payloadType: Field required"),
        (None, "malformed: payloadType: Field required"),
        (1, "malformed: payloadType: Input should be a valid string"),
        (
            ["application/vnd.asexec.v1+json"],
            "malformed: payloadType: Input should be a valid string",
        ),
        ({}, "malformed: payloadType: Input should be a valid string"),
    ],
    ids=["missing", "null", "number", "list", "object"],
)
def test_format__fail__1_payload_type_is_a_string(scenario, value, error):
    """format #1: the envelope has a string payloadType. A file without one is malformed,
    and is never read under some format's rules instead."""
    if value is _MISSING:
        scenario.unset("postreg0", "payloadType")
    else:
        scenario.set("postreg0", "payloadType", value)
    report = scenario.verify()
    assert report["code"] == FAIL
    assert report["results"]["selfsig"]["applicable"] == 3
    assert _entry(report, "postreg0")["format"]["errors"] == [error]


@pytest.mark.parametrize("field", ["pubkey", "sig"])
def test_format__fail__2_pubkey_and_sig_are_hex(scenario, field):
    """format #2: signature.pubkey and signature.sig are hex. A file where either is not
    fails format, and selfsig does not examine it."""
    scenario.tamper("postreg0", lambda envelope: envelope["signature"].update({field: "zz"}))
    report = scenario.verify()
    assert report["code"] == FAIL
    assert report["results"]["selfsig"]["applicable"] == 3


@pytest.mark.parametrize(
    "payload_type,reason",
    [
        ("application/vnd.asexec.v2+json", NEWER),
        ("application/vnd.asexec.v10+json", NEWER),
        ("application/something-else", NEWER),
        ("", NEWER),
        ("APPLICATION/VND.ASEXEC.V1+JSON", NEWER),
        ("application/vnd.asexec.v1+json ", NEWER),
        ("application/vnd.asexec.0.4.0b1+json", BETA),
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
    """format #3: payloadType names a format this release reads, exactly. A file that names
    another fails format with a reason saying which kind it is, and is not examined by
    selfsig, which still passes for the other files: version skew reads as format=FAIL, not
    as a bad signature. The type is changed after signing, so the file's signature no longer
    covers it either; only format judges it."""
    scenario.set("postreg0", "payloadType", payload_type)
    report = scenario.verify()
    assert report["code"] == FAIL
    assert report["results"]["format"]["reason"] == "1/4 manifest(s) failed"
    assert report["results"]["selfsig"]["applicable"] == 3
    assert _entry(report, "postreg0")["format"]["errors"] == [reason]


def test_format__fail__3_unknown_format_is_not_judged_by_this_formats_frame(scenario):
    """format #3: a file of a format this release does not read is not held to this format's
    frame (#1) or hex (#2): a newer format may be laid out differently. It fails with the
    upgrade reason, not as malformed."""
    scenario.add_raw(
        "v2", '{"payloadType": "application/vnd.asexec.v2+json", "dsse": {"payload": "e30="}}'
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
