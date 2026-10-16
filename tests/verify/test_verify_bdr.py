"""``BDR`` (bedrock): docs/VERIFICATION.md `### BDR`. Naming: see conftest.py."""

import pytest

from asexec import keys
from asexec.verifier import verify_paths

PASS = "asexec-verify/1 BDR=PASS"
FAIL = "asexec-verify/1 BDR=FAIL"


def test_BDR__pass__all(scenario):
    """BDR #1-#3: well-formed file, valid signature, keyid derives from pubkey."""
    report = scenario.verify()
    assert report["code"] == PASS
    assert report["ok"] is True
    assert len(report["manifests"]) == 4


def _bad_signature_envelope(payload: str) -> str:
    return '{"payload": ' + payload + ', "signature": {"pubkey": "00", "sig": "00"}}'


MALFORMED_FILES = {
    "empty": "",
    "not-json": "{nope",
    "binary": b"\xff\xfe\x00",
    "array": "[1, 2]",
    "string": '"x"',
    "null": "null",
    "missing-payload": '{"signature": {}}',
    "missing-signature": '{"payload": {}}',
}


@pytest.mark.parametrize("raw", MALFORMED_FILES.values(), ids=MALFORMED_FILES.keys())
def test_BDR__fail__1_well_formed_file(scenario, raw):
    """BDR #1: the file is a JSON object, with payload and signature."""
    scenario.add_raw("bad", raw)
    assert scenario.code() == FAIL


def test_BDR__fail__1_no_duplicate_keys(scenario):
    """BDR #1: no duplicate JSON keys (otherwise the last would silently win)."""
    raw = scenario.read("prereg")
    dup = raw.replace('"phase": "prereg"', '"phase": "prereg", "phase": "postreg"', 1)
    assert dup != raw
    scenario.add_raw("dup", dup)
    report = scenario.verify()
    assert report["code"] == FAIL
    dup_path = next(m for m in report["manifests"] if m["path"].endswith("dup.json"))
    assert "duplicate" in dup_path["signature"]["errors"][0]


def test_BDR__fail__2_signature_covers_payload(scenario):
    """BDR #2: sig verifies over payload. A payload altered after signing fails."""

    def alter(envelope):
        envelope["payload"]["target"]["model_id"] = "SWAPPED"

    scenario.tamper("postreg0", alter)
    assert scenario.code() == FAIL


def test_BDR__fail__2_signature_by_pubkey(scenario):
    """BDR #2: sig is by signature.pubkey. A pubkey (with its own keyid) swapped in fails."""
    _, other_pub = keys.generate()

    def swap_key(envelope):
        envelope["signature"]["pubkey"] = other_pub.hex()
        envelope["signature"]["keyid"] = keys.keyid_for(other_pub)  # keep #3 satisfied

    scenario.tamper("postreg0", swap_key)
    assert scenario.code() == FAIL


@pytest.mark.parametrize("field", ["pubkey", "sig"])
def test_BDR__fail__2_pubkey_and_sig_are_hex(scenario, field):
    """BDR #2: signature.pubkey and signature.sig are hex."""
    scenario.tamper("postreg0", lambda envelope: envelope["signature"].update({field: "zz"}))
    assert scenario.code() == FAIL


def test_BDR__fail__3_keyid_derives_from_pubkey(scenario):
    """BDR #3: keyid == sha-256(pubkey). A valid signature with another key's keyid fails."""
    other_keyid = keys.keyid_for(keys.generate()[1])
    scenario.tamper("postreg0", lambda envelope: envelope["signature"].update(keyid=other_keyid))
    assert scenario.code() == FAIL


def test_BDR__fail__vacuous_no_manifests():
    """BDR (*): with no manifest to verify, BDR fails rather than passing vacuously."""
    report = verify_paths([], ["BDR"])
    assert report["code"] == FAIL
    assert report["results"]["BDR"]["reason"] == "no manifests to verify"
