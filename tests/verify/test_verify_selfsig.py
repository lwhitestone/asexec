"""``selfsig`` (unchanged since its own key signed it): docs/VERIFICATION.md `### selfsig`.

Naming: see conftest.py. ``selfsig`` examines only files that pass ``format``
(``test_verify_format.py``), so every ``fail`` test here keeps ``format=PASS``: a missing or
non-hex ``pubkey`` or ``sig``, a missing ``keyid`` and the wrong number of signatures do not
stop verify reading the file, so they are selfsig's to fail.
"""

import copy

import pytest

from asexec import keys
from asexec.verifier import verify_paths

PASS = "asexec-verify/1 format=PASS selfsig=PASS"
FAIL = "asexec-verify/1 format=PASS selfsig=FAIL"
NONE_PASSES = "no manifest passes format"
_MISSING = object()


def _spaced_upper(hex_str: str) -> str:
    """The same bytes as ``hex_str``, in uppercase with whitespace between byte pairs."""
    pairs = [hex_str[i : i + 2].upper() for i in range(0, len(hex_str), 2)]
    return " ".join(pairs[:4]) + "\n\t" + "".join(pairs[4:])


def _fails_selfsig_only(scenario):
    report = scenario.verify()
    assert report["code"] == FAIL
    assert report["results"]["format"]["reason"] == "4/4 manifest(s) ok"
    assert report["results"]["selfsig"]["reason"] == "1/4 manifest(s) failed"
    return report


def test_selfsig__pass__all(scenario):
    """selfsig #1-#4: each file has one signature, its pubkey and sig are hex, the signature
    verifies over the PAE of its payloadType and body bytes by its pubkey, and each keyid
    derives from its pubkey."""
    report = scenario.verify()
    assert report["code"] == PASS
    assert report["ok"] is True
    assert report["results"]["selfsig"]["applicable"] == 4


@pytest.mark.parametrize("path", ["pubkey", "dsse.signatures[0].sig"])
def test_selfsig__pass__2_hex_accepts_either_case_and_whitespace(scenario, path):
    """selfsig #2: hex is what bytes.fromhex accepts (Conventions, Hex), case and spacing
    aside. The bytes are unchanged, so the signature still verifies."""

    def respell(envelope):
        holder, key = (
            (envelope, "pubkey") if path == "pubkey" else (envelope["dsse"]["signatures"][0], "sig")
        )
        holder[key] = _spaced_upper(holder[key])

    scenario.tamper("postreg0", respell)
    assert scenario.code() == PASS


def _second_signature(envelope, other):
    """``envelope`` with a second dsse.signatures entry: a copy of the first, or (``other``)
    another key's valid signature over the same PAE."""
    first = envelope["dsse"]["signatures"][0]
    if other is None:
        envelope["dsse"]["signatures"].append(copy.deepcopy(first))
    else:
        envelope["dsse"]["signatures"].append(other)


@pytest.mark.parametrize(
    "edit",
    [
        pytest.param(lambda env: env["dsse"].update(signatures=[]), id="none"),
        pytest.param(lambda env: _second_signature(env, None), id="two-the-same"),
        pytest.param(
            lambda env: _second_signature(env, {"keyid": "sha-256:00", "sig": "00" * 64}),
            id="two-the-second-junk",
        ),
        pytest.param(lambda env: env["dsse"]["signatures"].insert(0, {}), id="two-the-first-empty"),
        pytest.param(lambda env: env["dsse"].update(signatures=["x"]), id="entry-a-string"),
        pytest.param(lambda env: env["dsse"].update(signatures=[None]), id="entry-null"),
        pytest.param(lambda env: env["dsse"].update(signatures=[[]]), id="entry-an-array"),
    ],
)
def test_selfsig__fail__1_exactly_one_signature(scenario, edit):
    """selfsig #1: dsse.signatures holds exactly one entry, an object. Zero, two (even two
    copies of the one valid signature) and an entry that is not an object fail; none of
    them is malformed."""
    scenario.tamper("postreg0", edit)
    _fails_selfsig_only(scenario)


@pytest.mark.parametrize(
    "path,value",
    [
        ("pubkey", _MISSING),
        ("pubkey", None),
        ("pubkey", "zz"),
        ("pubkey", "abc"),
        ("pubkey", 5),
        ("pubkey", ["00"]),
        ("dsse.signatures[0].sig", _MISSING),
        ("dsse.signatures[0].sig", None),
        ("dsse.signatures[0].sig", "zz"),
        ("dsse.signatures[0].sig", {}),
    ],
    ids=[
        "pubkey-missing",
        "pubkey-null",
        "pubkey-not-hex",
        "pubkey-odd-length",
        "pubkey-number",
        "pubkey-array",
        "sig-missing",
        "sig-null",
        "sig-not-hex",
        "sig-object",
    ],
)
def test_selfsig__fail__2_pubkey_and_sig_are_hex(scenario, path, value):
    """selfsig #2: pubkey and dsse.signatures[0].sig are present and hex. A file without
    them can still be read, so it passes format."""
    if value is _MISSING:
        scenario.unset("postreg0", path)
    else:
        scenario.set("postreg0", path, value)
    _fails_selfsig_only(scenario)


def test_selfsig__fail__3_signature_covers_the_body_bytes(scenario):
    """selfsig #3: sig verifies over the body bytes. A body altered after signing fails."""
    scenario.set("postreg0", "body.target.model_id", "SWAPPED", after_signing=True)
    _fails_selfsig_only(scenario)


def test_selfsig__fail__3_signature_covers_the_bytes_not_the_json(scenario):
    """selfsig #3: the signature covers the bytes as stored. The same JSON value spelled
    with other spacing is other bytes, and fails: nothing re-serializes the body."""
    scenario.edit_body_bytes("postreg0", lambda raw: raw.replace(b",", b", "), after_signing=True)
    _fails_selfsig_only(scenario)


def test_selfsig__fail__3_signature_by_pubkey(scenario):
    """selfsig #3: sig is by pubkey. A pubkey (with its own keyid) swapped in fails."""
    _, other_pub = keys.generate()

    def swap_key(envelope):
        envelope["pubkey"] = other_pub.hex()
        envelope["dsse"]["signatures"][0]["keyid"] = keys.keyid_for(other_pub)  # keep #4

    scenario.tamper("postreg0", swap_key)
    _fails_selfsig_only(scenario)


@pytest.mark.parametrize(
    "value",
    [_MISSING, None, "other", 5, {"a": 1}],
    ids=["missing", "null", "another-keys", "number", "object"],
)
def test_selfsig__fail__4_keyid_derives_from_pubkey(scenario, value):
    """selfsig #4: dsse.signatures[0].keyid == sha-256(pubkey). A valid signature with
    another key's keyid, or with none, fails."""
    path = "dsse.signatures[0].keyid"
    if value is _MISSING:
        scenario.unset("postreg0", path)
    elif value == "other":
        scenario.set("postreg0", path, keys.keyid_for(keys.generate()[1]))
    else:
        scenario.set("postreg0", path, value)
    _fails_selfsig_only(scenario)


def test_selfsig__fail__empty_no_manifest_passes_format(scenario):
    """selfsig (*): a file that fails format is not examined, so when no file passes format,
    selfsig has nothing to examine and fails, with its own reason."""
    for name in scenario.specs:
        scenario.set(name, "dsse.signatures", "x")
    report = scenario.verify()
    assert report["code"] == "asexec-verify/1 format=FAIL selfsig=FAIL"
    assert report["results"]["format"]["reason"] == "4/4 manifest(s) failed"
    assert report["results"]["selfsig"]["applicable"] == 0
    assert report["results"]["selfsig"]["reason"] == NONE_PASSES


def test_selfsig__fail__empty_no_manifests():
    """selfsig (*): with no manifest file at all, selfsig fails rather than passing unchecked."""
    report = verify_paths([], ["format", "selfsig"])
    assert report["code"] == "asexec-verify/1 format=FAIL selfsig=FAIL"
    assert report["results"]["selfsig"]["applicable"] == 0
    assert report["results"]["selfsig"]["reason"] == NONE_PASSES
