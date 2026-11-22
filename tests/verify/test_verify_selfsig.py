"""``selfsig`` (unchanged since its own key signed it): docs/VERIFICATION.md `### selfsig`.

Naming: see conftest.py. ``selfsig`` examines only files that pass ``format``
(``test_verify_format.py``), so every ``fail`` test here keeps ``format=PASS``: a missing or
non-hex ``pubkey``, a missing or non-base64 ``sig``, a missing ``keyid`` and the wrong number
of signatures do not stop verify reading the file, so they are selfsig's to fail.
"""

import base64
import copy
import json

import manifest_data as d
import pytest

from asexec import keys
from asexec.verifier import verify_paths

PASS = "asexec-verify/1 format=PASS selfsig=PASS"
FAIL = "asexec-verify/1 format=PASS selfsig=FAIL"
NONE_PASSES = "no manifest passes format"
_MISSING = object()


def _respell_spaced_upper(hex_str: str) -> str:
    """The same bytes as ``hex_str``, in uppercase with whitespace between byte pairs."""
    pairs = [hex_str[i : i + 2].upper() for i in range(0, len(hex_str), 2)]
    return " ".join(pairs[:4]) + "\n\t" + "".join(pairs[4:])


def _assert_fails_selfsig_only(scenario):
    report = scenario.verify()
    assert report["code"] == FAIL
    assert report["results"]["format"]["reason"] == "4/4 manifest(s) ok"
    assert report["results"]["selfsig"]["reason"] == "1/4 manifest(s) failed"
    return report


def test_selfsig__pass__all(scenario):
    """selfsig #1-#4: each file has one signature, its pubkey is hex and its sig strict base64
    of 64 bytes, the signature verifies over the PAE of its payloadType and body bytes by its
    pubkey, and each keyid derives from its pubkey."""
    report = scenario.verify()
    assert report["code"] == PASS
    assert report["ok"] is True
    assert report["results"]["selfsig"]["applicable"] == 4


def test_selfsig__pass__2_pubkey_hex_accepts_either_case_and_whitespace(scenario):
    """selfsig #2: pubkey's hex is what bytes.fromhex accepts (Conventions, Hex), case and
    spacing aside. The bytes are unchanged, so the signature still verifies. (sig is base64,
    which has one spelling: see the fail cases below.)"""
    scenario.tamper("postreg0", lambda env: env.update(pubkey=_respell_spaced_upper(env["pubkey"])))
    assert scenario.code() == PASS


def _add_second_signature(envelope, other):
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
        pytest.param(lambda env: _add_second_signature(env, None), id="two-the-same"),
        pytest.param(
            lambda env: _add_second_signature(env, {"keyid": "sha-256:00", "sig": d.ZERO_SIG}),
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
    _assert_fails_selfsig_only(scenario)


def _read_sig_bytes(scenario, name="postreg0"):
    return base64.b64decode(json.loads(scenario.read(name))["dsse"]["signatures"][0]["sig"])


def _make_sig_respelling(spelling):
    """An edit of postreg0's sig: ``spelling(sig as stored, its bytes)``."""

    def apply(envelope):
        entry = envelope["dsse"]["signatures"][0]
        entry["sig"] = spelling(entry["sig"], base64.b64decode(entry["sig"]))

    return apply


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
        ("dsse.signatures[0].sig", 5),
        ("dsse.signatures[0].sig", {}),
        ("dsse.signatures[0].sig", "zz!"),
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
        "sig-number",
        "sig-object",
        "sig-not-base64",
    ],
)
def test_selfsig__fail__2_pubkey_is_hex_and_sig_is_present(scenario, path, value):
    """selfsig #2: pubkey is present and hex, and dsse.signatures[0].sig is a present
    string of base64. A file without them can still be read, so it passes format."""
    if value is _MISSING:
        scenario.unset("postreg0", path)
    else:
        scenario.set("postreg0", path, value)
    _assert_fails_selfsig_only(scenario)


_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def _set_unused_bits(stored: str) -> str:
    """``stored`` (base64 of 64 bytes, so ending ``==``) with an unused bit of its last
    character set: the same bytes, spelled otherwise."""
    last = _ALPHABET.index(stored[-3])
    return stored[:-3] + _ALPHABET[last | 1] + "=="


@pytest.mark.parametrize(
    "spelling",
    [
        pytest.param(lambda s, raw: raw.hex(), id="hex-as-before"),
        pytest.param(lambda s, raw: s.rstrip("="), id="padding-dropped"),
        pytest.param(lambda s, raw: s + "=", id="padding-extra"),
        pytest.param(lambda s, raw: s[:40] + "\n" + s[40:], id="newline-inside"),
        pytest.param(lambda s, raw: s + " ", id="space-after"),
        pytest.param(lambda s, raw: s.replace("+", "-").replace("/", "_"), id="url-safe"),
        pytest.param(lambda s, raw: _set_unused_bits(s), id="unused-bits-set"),
        pytest.param(lambda s, raw: d.encode_b64(raw[:63]), id="63-bytes"),
        pytest.param(lambda s, raw: d.encode_b64(raw + b"\0"), id="65-bytes"),
        pytest.param(lambda s, raw: "", id="empty"),
    ],
)
def test_selfsig__fail__2_sig_is_strict_base64_of_64_bytes(scenario, spelling):
    """selfsig #2: dsse.signatures[0].sig is strict base64 (as dsse.payload is: the standard
    alphabet, padded, no whitespace, one spelling) of 64 bytes, an ed25519 signature's
    length. Hex, as asexec wrote before, another spelling of the same bytes, and a
    signature of another length fail; the file still passes format."""
    # The signature must use both of the characters URL-safe base64 replaces. It depends on
    # the payloadType, which each release commit sets, so vary the body until it does.
    for i in range(1000):
        stored = base64.b64encode(_read_sig_bytes(scenario)).decode()
        if "+" in stored and "/" in stored:
            break
        scenario.set("postreg0", "body.notes", f"postreg0, variant {i}")
    assert "+" in stored and "/" in stored and stored.endswith("==")
    assert _set_unused_bits(stored) != stored
    scenario.tamper("postreg0", _make_sig_respelling(spelling))
    _assert_fails_selfsig_only(scenario)


def test_selfsig__fail__3_signature_covers_the_body_bytes(scenario):
    """selfsig #3: sig verifies over the body bytes. A body altered after signing fails."""
    scenario.set("postreg0", "body.target.model_id", "SWAPPED", after_signing=True)
    _assert_fails_selfsig_only(scenario)


def test_selfsig__fail__3_signature_covers_the_bytes_not_the_json(scenario):
    """selfsig #3: the signature covers the bytes as stored. The same JSON value spelled
    with other spacing is other bytes, and fails: nothing re-serializes the body."""
    scenario.edit_body_bytes("postreg0", lambda raw: raw.replace(b",", b", "), after_signing=True)
    _assert_fails_selfsig_only(scenario)


def test_selfsig__fail__3_signature_by_pubkey(scenario):
    """selfsig #3: sig is by pubkey. A pubkey (with its own keyid) swapped in fails."""
    _, other_pub = keys.generate()

    def swap_key(envelope):
        envelope["pubkey"] = other_pub.hex()
        envelope["dsse"]["signatures"][0]["keyid"] = keys.derive_keyid(other_pub)  # keep #4

    scenario.tamper("postreg0", swap_key)
    _assert_fails_selfsig_only(scenario)


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
        scenario.set("postreg0", path, keys.derive_keyid(keys.generate()[1]))
    else:
        scenario.set("postreg0", path, value)
    _assert_fails_selfsig_only(scenario)


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
    report = verify_paths([], ["format", "selfsig"], None)
    assert report["code"] == "asexec-verify/1 format=FAIL selfsig=FAIL"
    assert report["results"]["selfsig"]["applicable"] == 0
    assert report["results"]["selfsig"]["reason"] == NONE_PASSES
