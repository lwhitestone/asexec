"""``keyconsist`` (postregs signed by the prereg's key): docs/VERIFICATION.md `### keyconsist`.

Naming: see conftest.py.
"""

from asexec import keys

PASS = "asexec-verify/1 BDR=PASS keyconsist=PASS"
FAIL = "asexec-verify/1 BDR=PASS keyconsist=FAIL"


def test_keyconsist__pass__all(scenario):
    """keyconsist #1: every valid postreg referencing the prereg has the prereg's keyid."""
    report = scenario.verify("keyconsist")
    assert report["code"] == PASS
    assert report["commitments"][0]["key_consistent"] is True


def test_keyconsist__pass__1_invalid_signature_is_not_judged_here(scenario):
    """keyconsist #1: a postreg with an invalid signature is not judged here (it fails BDR)."""
    scenario.tamper(
        "postreg0", lambda envelope: envelope["payload"]["target"].update(model_id="SWAPPED")
    )
    assert scenario.code("keyconsist") == "asexec-verify/1 BDR=FAIL keyconsist=PASS"


def test_keyconsist__fail__1_valid_postreg_has_prereg_keyid(scenario):
    """keyconsist #1: a validly signed postreg by another key fails."""
    scenario.sign_with("postreg1", keys.generate())
    report = scenario.verify("keyconsist")
    assert report["code"] == FAIL
    assert report["commitments"][0]["key_consistent"] is False


def test_keyconsist__fail__vacuous_no_postreg_references_a_prereg(scenario):
    """keyconsist (*): a prereg no postreg references has no receipts to key-check."""
    for name in ("postreg0", "postreg1", "postreg2"):
        scenario.drop(name)
    report = scenario.verify("keyconsist")
    assert report["code"] == FAIL
    assert report["results"]["keyconsist"]["applicable"] == 0
