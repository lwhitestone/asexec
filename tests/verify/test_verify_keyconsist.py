"""``keyconsist`` (postregs signed by the prereg's key): docs/VERIFICATION.md `### keyconsist`.

Naming: see conftest.py.
"""

from asexec import keys

PASS = "asexec-verify/1 format=PASS keyconsist=PASS selfsig=PASS"
FAIL = "asexec-verify/1 format=PASS keyconsist=FAIL selfsig=PASS"
EMPTY = "requested but no validly signed postreg names a commitment"


def test_keyconsist__pass__all(scenario):
    """keyconsist #1: every valid postreg referencing the prereg has the prereg's keyid."""
    report = scenario.verify("keyconsist")
    assert report["code"] == PASS
    assert report["results"]["keyconsist"]["reason"] == "1/1 commitment(s) ok"
    assert report["commitments"][0]["rejected_postregs"] == []


def test_keyconsist__pass__1_invalid_signature_is_not_judged_here(scenario):
    """keyconsist #1: a postreg with an invalid signature is not judged here (it fails selfsig)."""
    scenario.tamper(
        "postreg0", lambda envelope: envelope["payload"]["target"].update(model_id="SWAPPED")
    )
    assert scenario.code("keyconsist") == "asexec-verify/1 format=PASS keyconsist=PASS selfsig=FAIL"


def test_keyconsist__pass__1_postreg_by_another_signer_of_the_same_ref(scenario):
    """keyconsist #1: a postreg by the signer of another commitment with the same ref
    belongs to that signer's commitment, so it is no failure of this one."""
    other = keys.generate()
    scenario.add_prereg("prereg_b")
    scenario.mutate("prereg_b", lambda body: body.update(notes="prereg"))  # the same body
    scenario.sign_with("prereg_b", other)
    scenario.sign_with("postreg2", other)
    scenario.link("postreg2", fulfills="prereg_b", prev=None)
    assert scenario.code("keyconsist") == PASS


def test_keyconsist__fail__1_valid_postreg_has_prereg_keyid(scenario):
    """keyconsist #1: a validly signed postreg by another key fails."""
    scenario.sign_with("postreg1", keys.generate())
    report = scenario.verify("keyconsist")
    assert report["code"] == FAIL
    assert report["results"]["keyconsist"]["reason"] == "1/1 commitment(s) failed"
    (rejected,) = report["commitments"][0]["rejected_postregs"]
    assert rejected["reason"] == "signed by a different key than the pre-registration"


def test_keyconsist__fail__1_valid_postreg_has_prereg_keyid__all_rejected(scenario):
    """keyconsist #1: with every postreg signed by another key, none counts, yet validly
    signed postregs name the commitment, so it is examined (not empty) and fails."""
    other = keys.generate()
    for name in ("postreg0", "postreg1", "postreg2"):
        scenario.sign_with(name, other)
    report = scenario.verify("keyconsist")
    assert report["code"] == FAIL
    assert report["results"]["keyconsist"]["applicable"] == 1


def test_keyconsist__fail__empty_only_invalid_signatures(scenario):
    """keyconsist (*): a commitment whose postregs all have invalid signatures has no key
    to check, so it is not examined: keyconsist fails rather than passing unchecked."""
    for name in ("postreg0", "postreg1", "postreg2"):
        scenario.tamper(
            name, lambda envelope: envelope["payload"]["target"].update(model_id="SWAPPED")
        )
    report = scenario.verify("keyconsist")
    assert len(report["commitments"][0]["rejected_postregs"]) == 3
    assert report["code"] == "asexec-verify/1 format=PASS keyconsist=FAIL selfsig=FAIL"
    assert report["results"]["keyconsist"]["applicable"] == 0
    assert report["results"]["keyconsist"]["reason"] == EMPTY


def test_keyconsist__fail__empty_no_postreg_references_a_prereg(scenario):
    """keyconsist (*): a prereg that no postreg names has nothing to key-check."""
    for name in ("postreg0", "postreg1", "postreg2"):
        scenario.drop(name)
    report = scenario.verify("keyconsist")
    assert report["code"] == FAIL
    assert report["results"]["keyconsist"]["applicable"] == 0
    assert report["results"]["keyconsist"]["reason"] == EMPTY


def test_keyconsist__fail__empty_prereg_fails_selfsig(scenario):
    """keyconsist (*): a prereg that fails selfsig is no commitment, so the validly signed
    postregs naming it, by its own key, name no commitment and nothing is key-checked."""
    scenario.tamper("prereg", lambda envelope: envelope["signature"].update(sig="00" * 64))
    report = scenario.verify("keyconsist")
    assert report["commitments"] == []
    assert report["code"] == "asexec-verify/1 format=PASS keyconsist=FAIL selfsig=FAIL"
    assert report["results"]["keyconsist"]["applicable"] == 0
    assert report["results"]["keyconsist"]["reason"] == EMPTY


def test_keyconsist__fail__empty_postreg_by_another_key_naming_a_rejected_prereg(scenario):
    """keyconsist (*): a postreg by another key naming a prereg that fails selfsig is not
    compared with that prereg's keyid, which nothing authenticated: it is no failure here,
    and nothing is key-checked."""
    scenario.tamper("prereg", lambda envelope: envelope["signature"].update(sig="00" * 64))
    scenario.sign_with("postreg2", keys.generate())
    report = scenario.verify("keyconsist")
    assert report["results"]["keyconsist"]["applicable"] == 0
    assert report["results"]["keyconsist"]["reason"] == EMPTY
