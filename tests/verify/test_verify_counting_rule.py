"""Counting rule: docs/VERIFICATION.md `## Counting rule`. Naming: see conftest.py.

A postreg counts toward a prereg iff #1 (phase postreg, fulfills == ref(prereg)),
#2 (BDR signature and keyid conditions) and #3 (same keyid as the prereg) hold. One that
references the prereg but fails #2 or #3 is *rejected* and listed with its reason.
Observed through the report: ``commitments[].receipts`` / ``rejected_receipts`` /
``state`` and ``notarization_only``.
"""

from asexec import keys
from asexec.verifier import verify_paths


def _commitment(report):
    (commitment,) = report["commitments"]
    return commitment


def test_counting_rule__pass__all(scenario):
    """Counting #1-#3 hold: every postreg counts, none is rejected, the commitment is fulfilled."""
    commitment = _commitment(scenario.verify())
    assert len(commitment["receipts"]) == 3
    assert commitment["rejected_receipts"] == []
    assert commitment["state"] == "fulfilled"


def test_counting_rule__fail__1_fulfills_equals_ref_of_prereg(scenario):
    """Counting #1: fulfills must equal ref(prereg). Otherwise it counts for nothing."""
    scenario.link("postreg0", fulfills="sha-256:" + "ab" * 32)
    report = scenario.verify()
    assert len(_commitment(report)["receipts"]) == 2
    assert _commitment(report)["rejected_receipts"] == []  # it does not reference the prereg
    assert [n["fulfills"] for n in report["notarization_only"]] == ["sha-256:" + "ab" * 32]


def test_counting_rule__fail__1_phase_is_postreg(scenario):
    """Counting #1: phase must be postreg."""
    scenario.mutate("postreg0", lambda body: body.update(phase="other"))
    commitment = _commitment(scenario.verify())
    assert len(commitment["receipts"]) == 2
    assert commitment["rejected_receipts"] == []


def test_counting_rule__fail__2_signature_is_valid(scenario):
    """Counting #2: an invalid signature is rejected, with its reason, and does not count."""
    scenario.tamper(
        "postreg0", lambda envelope: envelope["payload"]["target"].update(model_id="SWAPPED")
    )
    commitment = _commitment(scenario.verify())
    assert len(commitment["receipts"]) == 2
    (rejected,) = commitment["rejected_receipts"]
    assert rejected["reason"] == "invalid signature"


def test_counting_rule__fail__3_same_keyid_as_prereg(scenario):
    """Counting #3: a validly signed postreg by another key is rejected and does not count."""
    scenario.sign_with("postreg0", keys.generate())
    commitment = _commitment(scenario.verify())
    assert len(commitment["receipts"]) == 2
    (rejected,) = commitment["rejected_receipts"]
    assert rejected["reason"] == "signed by a different key than the pre-registration"


def test_counting_rule__rejected_postreg_never_counts_toward_fulfillment(scenario):
    """Counting (last paragraph): a commitment with only a rejected postreg is not fulfilled."""
    scenario.drop("postreg1")
    scenario.drop("postreg2")
    scenario.sign_with("postreg0", keys.generate())
    commitment = _commitment(scenario.verify())
    assert commitment["receipts"] == []
    assert commitment["state"] != "fulfilled"


def test_counting_rule__rejected_postreg_never_counts_toward_chain(scenario):
    """Counting (last paragraph): a rejected postreg is invisible to chain, even as a 2nd root."""
    scenario.add_postreg("intruder", transcript="transcript1.txt")  # a second root, other key
    scenario.sign_with("intruder", keys.generate())
    assert scenario.code("chain") == "asexec-verify/1 BDR=PASS chain=PASS"


# --- copies: a manifest is identified by its ref ------------------------------------ #


def test_counting_rule__copies_of_a_postreg_are_one_receipt(scenario):
    """Copies (same ref and keyid) count once, so they make no second root for chain."""
    scenario.add_raw("copy", scenario.read("postreg0"))
    report = scenario.verify("chain", "keyconsist")
    assert report["code"] == "asexec-verify/1 BDR=PASS chain=PASS keyconsist=PASS"
    assert len(_commitment(report)["receipts"]) == 3


def test_counting_rule__copies_of_a_prereg_are_one_commitment(scenario):
    scenario.add_raw("copy", scenario.read("prereg"))
    report = scenario.verify("chain")
    assert report["code"] == "asexec-verify/1 BDR=PASS chain=PASS"
    assert len(_commitment(report)["receipts"]) == 3


def test_counting_rule__copies_of_a_rejected_postreg_are_rejected_once(scenario):
    scenario.sign_with("postreg0", keys.generate())
    scenario.add_raw("copy", scenario.read("postreg0"))
    assert len(_commitment(scenario.verify())["rejected_receipts"]) == 1


def test_counting_rule__copies_of_a_notarization_only_postreg_are_listed_once(scenario):
    scenario.drop("prereg")
    scenario.add_raw("copy", scenario.read("postreg0"))
    assert len(scenario.verify()["notarization_only"]) == 3


def test_counting_rule__same_body_by_two_other_keys_is_two_rejections(scenario):
    """Copies must share the keyid too: each other signer is rejected in its own right."""
    scenario.sign_with("postreg0", keys.generate())
    first = scenario.read("postreg0")
    scenario.sign_with("postreg0", keys.generate())
    scenario.add_raw("first", first)
    (rejected_a, rejected_b) = _commitment(scenario.verify())["rejected_receipts"]
    assert rejected_a["ref"] == rejected_b["ref"]
    assert rejected_a["keyid"] != rejected_b["keyid"]


# --- a commitment is a prereg's ref and its signer ---------------------------------- #


def _second_signer(scenario):
    """The prereg's exact body signed by another key, with one postreg by that key."""
    other = keys.generate()
    scenario.add_prereg("prereg_b")
    scenario.mutate("prereg_b", lambda body: body.update(notes="prereg"))  # the same body
    scenario.sign_with("prereg_b", other)
    scenario.add_postreg("b_post", fulfills="prereg_b", transcript="transcript1.txt")
    scenario.sign_with("b_post", other)
    return other


def _summary(report):
    return sorted(
        (c["ref"], c["keyid"], len(c["receipts"]), len(c["rejected_receipts"]), c["state"])
        for c in report["commitments"]
    )


def test_counting_rule__same_body_by_two_keys_is_two_commitments(scenario):
    """Each signer's commitment counts only its own postregs; neither rejects the other's."""
    other = _second_signer(scenario)
    report = scenario.verify("chain", "keyconsist")
    assert report["code"] == "asexec-verify/1 BDR=PASS chain=PASS keyconsist=PASS"
    (ref_a, key_a, *_), (ref_b, key_b, *_) = _summary(report)
    assert ref_a == ref_b
    by_key = {c["keyid"]: c for c in report["commitments"]}
    assert len(by_key[keys.keyid_for(scenario.key[1])]["receipts"]) == 3
    assert len(by_key[keys.keyid_for(other[1])]["receipts"]) == 1
    assert all(c["rejected_receipts"] == [] for c in report["commitments"])


def test_counting_rule__commitments_do_not_depend_on_file_order(scenario):
    _second_signer(scenario)
    paths = scenario.write()
    forwards = verify_paths(paths, ["BDR", "chain", "keyconsist"], str(scenario.artifacts))
    backwards = verify_paths(paths[::-1], ["BDR", "chain", "keyconsist"], str(scenario.artifacts))
    assert forwards["code"] == backwards["code"]
    assert _summary(forwards) == _summary(backwards)


def test_counting_rule__postreg_by_neither_signer_is_rejected_under_both(scenario):
    _second_signer(scenario)
    scenario.sign_with("postreg2", keys.generate())
    report = scenario.verify("keyconsist")
    assert report["code"] == "asexec-verify/1 BDR=PASS keyconsist=FAIL"
    for commitment in report["commitments"]:
        (rejected,) = commitment["rejected_receipts"]
        assert rejected["reason"] == "signed by a different key than the pre-registration"


def test_counting_rule__invalid_signature_is_rejected_under_both(scenario):
    _second_signer(scenario)
    scenario.tamper(
        "postreg2", lambda envelope: envelope["payload"]["target"].update(model_id="SWAPPED")
    )
    for commitment in scenario.verify()["commitments"]:
        (rejected,) = commitment["rejected_receipts"]
        assert rejected["reason"] == "invalid signature"
