"""``selfsig`` (unchanged since its own key signed it): docs/VERIFICATION.md `### selfsig`.

Naming: see conftest.py. ``selfsig`` examines only files that pass ``format``
(``test_verify_format.py``), so every ``fail`` test here keeps ``format=PASS``.
"""

from asexec import keys
from asexec.verifier import verify_paths

PASS = "asexec-verify/1 format=PASS selfsig=PASS"
FAIL = "asexec-verify/1 format=PASS selfsig=FAIL"
NONE_PASSES = "no manifest passes format"


def test_selfsig__pass__all(scenario):
    """selfsig #1-#2: each signature verifies over its payload, by its pubkey, and each keyid
    derives from its pubkey."""
    report = scenario.verify()
    assert report["code"] == PASS
    assert report["ok"] is True
    assert report["results"]["selfsig"]["applicable"] == 4


def test_selfsig__fail__1_signature_covers_payload(scenario):
    """selfsig #1: sig verifies over payload. A payload altered after signing fails."""

    def alter(envelope):
        envelope["payload"]["target"]["model_id"] = "SWAPPED"

    scenario.tamper("postreg0", alter)
    report = scenario.verify()
    assert report["code"] == FAIL
    assert report["results"]["selfsig"]["reason"] == "1/4 manifest(s) failed"


def test_selfsig__fail__1_signature_by_pubkey(scenario):
    """selfsig #1: sig is by signature.pubkey. A pubkey (with its own keyid) swapped in fails."""
    _, other_pub = keys.generate()

    def swap_key(envelope):
        envelope["signature"]["pubkey"] = other_pub.hex()
        envelope["signature"]["keyid"] = keys.keyid_for(other_pub)  # keep #2 satisfied

    scenario.tamper("postreg0", swap_key)
    assert scenario.code() == FAIL


def test_selfsig__fail__2_keyid_derives_from_pubkey(scenario):
    """selfsig #2: keyid == sha-256(pubkey). A valid signature with another key's keyid fails."""
    other_keyid = keys.keyid_for(keys.generate()[1])
    scenario.tamper("postreg0", lambda envelope: envelope["signature"].update(keyid=other_keyid))
    assert scenario.code() == FAIL


def test_selfsig__fail__empty_no_manifest_passes_format(scenario):
    """selfsig (*): a file that fails format is not examined, so when no file passes format,
    selfsig has nothing to examine and fails, with its own reason."""
    for name in scenario.specs:
        scenario.set(name, "signature.pubkey", "zz")
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
