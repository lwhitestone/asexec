"""Counting rule: docs/VERIFICATION.md `## Counting rule`. Naming: see conftest.py.

A postreg counts toward a prereg iff #1 (phase postreg, fulfills == ref(prereg)),
#2 (BDR signature and keyid conditions) and #3 (same keyid as the prereg) hold. One that
references the prereg but fails #2 or #3 is *rejected* and listed with its reason.
Observed through the report: ``commitments[].receipts`` / ``rejected_receipts`` /
``state`` and ``notarization_only``.
"""

from asexec import keys


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
