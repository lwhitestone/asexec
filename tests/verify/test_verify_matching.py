"""Matching postregs to commitments: docs/VERIFICATION.md `## Matching postregs to commitments`.
Naming: see conftest.py.

A postreg counts toward a prereg iff #1 (phase postreg, fulfills == ref(prereg)),
#2 (the selfsig conditions), #3 (same keyid as the prereg) and #4 (the prereg meets the
selfsig conditions, so is a commitment) hold. One that names the prereg but counts toward
no commitment with its ref is *rejected* and listed with its reason. A prereg that passes
format but fails selfsig is a *rejected pre-registration*. Observed through the report:
``commitments[].counted_postregs`` / ``rejected_postregs`` / ``state``,
``rejected_preregs[]`` and ``notarization_only``.
"""

import json

import manifest_data as d
import pytest

from asexec import keys
from asexec.verifier import verify_paths


def _commitment(report):
    (commitment,) = report["commitments"]
    return commitment


def test_matching__pass__all(scenario):
    """Matching #1-#3 hold: every postreg counts, none is rejected, the commitment is fulfilled."""
    commitment = _commitment(scenario.verify())
    assert len(commitment["counted_postregs"]) == 3
    assert commitment["rejected_postregs"] == []
    assert commitment["state"] == "fulfilled"


def test_matching__fail__1_fulfills_equals_ref_of_prereg(scenario):
    """Matching #1: fulfills must equal ref(prereg). Otherwise it counts for nothing."""
    scenario.link("postreg0", fulfills="sha-256:" + "ab" * 32)
    report = scenario.verify()
    assert len(_commitment(report)["counted_postregs"]) == 2
    assert _commitment(report)["rejected_postregs"] == []  # it does not reference the prereg
    assert [n["fulfills"] for n in report["notarization_only"]] == ["sha-256:" + "ab" * 32]


def test_matching__fail__1_phase_is_postreg(scenario):
    """Matching #1: phase must be postreg."""
    scenario.mutate("postreg0", lambda body: body.update(phase="other"))
    commitment = _commitment(scenario.verify())
    assert len(commitment["counted_postregs"]) == 2
    assert commitment["rejected_postregs"] == []


def test_matching__fail__2_signature_is_valid(scenario):
    """Matching #2: an invalid signature is rejected, with its reason, and does not count."""
    scenario.tamper(
        "postreg0", lambda envelope: envelope["payload"]["target"].update(model_id="SWAPPED")
    )
    commitment = _commitment(scenario.verify())
    assert len(commitment["counted_postregs"]) == 2
    (rejected,) = commitment["rejected_postregs"]
    assert rejected["reason"] == "invalid signature"


def test_matching__fail__3_same_keyid_as_prereg(scenario):
    """Matching #3: a validly signed postreg by another key is rejected and does not count."""
    scenario.sign_with("postreg0", keys.generate())
    commitment = _commitment(scenario.verify())
    assert len(commitment["counted_postregs"]) == 2
    (rejected,) = commitment["rejected_postregs"]
    assert rejected["reason"] == "signed by a different key than the pre-registration"


def test_matching__rejected_postreg_never_counts_toward_fulfillment(scenario):
    """Matching (rejected): a commitment with only a rejected postreg is not fulfilled."""
    scenario.drop("postreg1")
    scenario.drop("postreg2")
    scenario.sign_with("postreg0", keys.generate())
    commitment = _commitment(scenario.verify())
    assert commitment["counted_postregs"] == []
    assert commitment["state"] != "fulfilled"


def test_matching__rejected_postreg_never_counts_toward_chain(scenario):
    """Matching (rejected): a rejected postreg is invisible to chain, even as a 2nd root."""
    scenario.add_postreg("intruder", transcript="transcript1.txt")  # a second root, other key
    scenario.sign_with("intruder", keys.generate())
    assert scenario.code("chain") == "asexec-verify/1 chain=PASS format=PASS selfsig=PASS"


# --- copies: a manifest is identified by its ref ------------------------------------ #


def test_matching__copies_of_a_postreg_are_one_postreg(scenario):
    """Copies (same ref and keyid) count once, so they make no second root for chain."""
    scenario.add_raw("copy", scenario.read("postreg0"))
    report = scenario.verify("chain", "keyconsist")
    assert report["code"] == "asexec-verify/1 chain=PASS format=PASS keyconsist=PASS selfsig=PASS"
    assert len(_commitment(report)["counted_postregs"]) == 3


def test_matching__copies_of_a_prereg_are_one_commitment(scenario):
    scenario.add_raw("copy", scenario.read("prereg"))
    report = scenario.verify("chain")
    assert report["code"] == "asexec-verify/1 chain=PASS format=PASS selfsig=PASS"
    assert len(_commitment(report)["counted_postregs"]) == 3


def test_matching__copies_of_a_rejected_postreg_are_rejected_once(scenario):
    scenario.sign_with("postreg0", keys.generate())
    scenario.add_raw("copy", scenario.read("postreg0"))
    assert len(_commitment(scenario.verify())["rejected_postregs"]) == 1


def test_matching__broken_copy_of_a_counted_postreg_is_also_rejected(scenario):
    """A copy whose signature does not verify is judged on its own: the same ref is listed
    as counted (the valid copy) and as rejected for invalid signature (the broken one)."""
    copy = json.loads(scenario.read("postreg0"))
    sig = copy["signature"]["sig"]
    copy["signature"]["sig"] = ("00" if sig[:2] != "00" else "11") + sig[2:]
    scenario.add_raw("copy", json.dumps(copy))
    report = scenario.verify()
    assert report["code"] == "asexec-verify/1 format=PASS selfsig=FAIL"
    commitment = _commitment(report)
    assert len(commitment["counted_postregs"]) == 3
    (rejected,) = commitment["rejected_postregs"]
    assert rejected["reason"] == "invalid signature"
    assert rejected["ref"] in {p["ref"] for p in commitment["counted_postregs"]}


def test_matching__copies_of_a_notarization_only_postreg_are_listed_once(scenario):
    scenario.drop("prereg")
    scenario.add_raw("copy", scenario.read("postreg0"))
    assert len(scenario.verify()["notarization_only"]) == 3


def test_matching__same_body_by_two_other_keys_is_two_rejections(scenario):
    """Copies must share the keyid too: each other signer is rejected in its own right."""
    scenario.sign_with("postreg0", keys.generate())
    first = scenario.read("postreg0")
    scenario.sign_with("postreg0", keys.generate())
    scenario.add_raw("first", first)
    (rejected_a, rejected_b) = _commitment(scenario.verify())["rejected_postregs"]
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
        (c["ref"], c["keyid"], len(c["counted_postregs"]), len(c["rejected_postregs"]), c["state"])
        for c in report["commitments"]
    )


def test_matching__same_body_by_two_keys_is_two_commitments(scenario):
    """Each signer's commitment counts only its own postregs; neither rejects the other's."""
    other = _second_signer(scenario)
    report = scenario.verify("chain", "keyconsist")
    assert report["code"] == "asexec-verify/1 chain=PASS format=PASS keyconsist=PASS selfsig=PASS"
    (ref_a, key_a, *_), (ref_b, key_b, *_) = _summary(report)
    assert ref_a == ref_b
    by_key = {c["keyid"]: c for c in report["commitments"]}
    assert len(by_key[keys.keyid_for(scenario.key[1])]["counted_postregs"]) == 3
    assert len(by_key[keys.keyid_for(other[1])]["counted_postregs"]) == 1
    assert all(c["rejected_postregs"] == [] for c in report["commitments"])


def test_matching__commitments_do_not_depend_on_file_order(scenario):
    _second_signer(scenario)
    paths = scenario.write()
    forwards = verify_paths(
        paths, ["chain", "format", "keyconsist", "selfsig"], str(scenario.artifacts)
    )
    backwards = verify_paths(
        paths[::-1], ["chain", "format", "keyconsist", "selfsig"], str(scenario.artifacts)
    )
    assert forwards["code"] == backwards["code"]
    assert _summary(forwards) == _summary(backwards)


def test_matching__postreg_by_neither_signer_is_rejected_under_both(scenario):
    _second_signer(scenario)
    scenario.sign_with("postreg2", keys.generate())
    report = scenario.verify("keyconsist")
    assert report["code"] == "asexec-verify/1 format=PASS keyconsist=FAIL selfsig=PASS"
    for commitment in report["commitments"]:
        (rejected,) = commitment["rejected_postregs"]
        assert rejected["reason"] == "signed by a different key than the pre-registration"


def test_matching__invalid_signature_is_rejected_under_both(scenario):
    _second_signer(scenario)
    scenario.tamper(
        "postreg2", lambda envelope: envelope["payload"]["target"].update(model_id="SWAPPED")
    )
    for commitment in scenario.verify()["commitments"]:
        (rejected,) = commitment["rejected_postregs"]
        assert rejected["reason"] == "invalid signature"


# --- a prereg that fails selfsig is no commitment (rejected pre-registration) -------- #

PREREG_INVALID = "the pre-registration's signature is invalid"
TESTS_LINKED = ("chain", "keyconsist")
OTHER_KEYID = keys.keyid_for(keys.generate()[1])  # a keyid no file here derives


def _break_sig(envelope):
    sig = envelope["signature"]["sig"]
    envelope["signature"]["sig"] = ("00" if sig[:2] != "00" else "11") + sig[2:]


def _broken_copy(scenario, name="prereg", keyid=None):
    """A copy of ``name`` that passes format and fails selfsig: its signature no longer
    verifies, or (``keyid`` given) it claims a keyid that does not derive from its pubkey."""
    copy = json.loads(scenario.read(name))
    if keyid is None:
        _break_sig(copy)
    else:
        copy["signature"]["keyid"] = keyid
    return json.dumps(copy)


@pytest.mark.parametrize(
    "break_prereg",
    [
        pytest.param(_break_sig, id="signature-does-not-verify"),
        pytest.param(
            lambda envelope: envelope["signature"].update(keyid=OTHER_KEYID),
            id="keyid-does-not-derive",
        ),
    ],
)
def test_matching__fail__4_prereg_meets_selfsig_conditions(scenario, break_prereg):
    """Matching #4: a prereg that passes format but fails selfsig is no commitment. It is
    listed as a rejected pre-registration, with its reason, and each valid postreg by the
    same key that names it is rejected under it, with the reason that the prereg's
    signature is invalid: none is counted, none is notarization-only, and chain and
    keyconsist, which examine commitments only, have nothing to examine."""
    scenario.tamper("prereg", break_prereg)
    report = scenario.verify(*TESTS_LINKED)
    assert report["code"] == "asexec-verify/1 chain=FAIL format=PASS keyconsist=FAIL selfsig=FAIL"
    assert report["results"]["selfsig"]["reason"] == "1/4 manifest(s) failed"
    assert report["commitments"] == []
    assert report["notarization_only"] == []
    (rejected,) = report["rejected_preregs"]
    prereg = json.loads(scenario.read("prereg"))
    assert rejected["ref"] == d.ref(prereg["payload"])
    assert rejected["keyid"] == prereg["signature"]["keyid"]
    assert rejected["reason"] == "invalid signature"
    postregs = [json.loads(scenario.read(f"postreg{i}")) for i in range(3)]
    assert [(r["ref"], r["keyid"], r["reason"]) for r in rejected["rejected_postregs"]] == [
        (d.ref(p["payload"]), p["signature"]["keyid"], PREREG_INVALID) for p in postregs
    ]
    assert report["results"]["chain"]["applicable"] == 0
    assert report["results"]["keyconsist"]["applicable"] == 0


def test_matching__prereg_with_body_changed_after_signing_is_rejected_and_named_by_none(
    scenario,
):
    """A prereg whose body changed after signing has a new ref, so the postregs naming the
    signed body name no provided prereg: they are notarization-only, and the rejected
    pre-registration lists none of them."""
    scenario.tamper(
        "prereg", lambda envelope: envelope["payload"]["target"].update(model_id="SWAPPED")
    )
    report = scenario.verify()
    assert report["code"] == "asexec-verify/1 format=PASS selfsig=FAIL"
    (rejected,) = report["rejected_preregs"]
    assert rejected["rejected_postregs"] == []
    assert len(report["notarization_only"]) == 3


def test_matching__valid_prereg_has_no_rejected_preregs(scenario):
    assert scenario.verify()["rejected_preregs"] == []


@pytest.mark.parametrize("same_keyid", [True, False], ids=["same-keyid", "other-keyid"])
def test_matching__postreg_counted_by_a_commitment_is_not_rejected_under_a_rejected_copy(
    scenario, same_keyid
):
    """Matching (a): beside a commitment, a copy of its prereg that fails selfsig (its
    signature broken, or another key's keyid claimed) is a rejected pre-registration of the
    same ref. A postreg that counts toward the commitment is not rejected under the copy, as
    it is not rejected under the ref's other commitments."""
    other_keyid = None if same_keyid else keys.keyid_for(keys.generate()[1])
    scenario.add_raw("copy", _broken_copy(scenario, keyid=other_keyid))
    report = scenario.verify(*TESTS_LINKED)
    assert report["code"] == "asexec-verify/1 chain=PASS format=PASS keyconsist=PASS selfsig=FAIL"
    commitment = _commitment(report)
    assert len(commitment["counted_postregs"]) == 3
    assert commitment["rejected_postregs"] == []
    assert commitment["state"] == "fulfilled"
    (rejected,) = report["rejected_preregs"]
    assert rejected["ref"] == commitment["ref"]
    assert rejected["keyid"] == (commitment["keyid"] if same_keyid else other_keyid)
    assert rejected["rejected_postregs"] == []


def test_matching__forged_copy_claiming_a_key_does_not_make_that_key_a_signer(scenario):
    """Matching (a): a copy of the prereg relabelled with key B's pubkey and keyid, B's
    signature never made, is a rejected pre-registration, not B's commitment. A valid
    postreg by B naming the ref is rejected under the real commitment as signed by a
    different key, so keyconsist fails, and is listed under the copy with the prereg's
    reason. The keyid nothing authenticated decides no verdict."""
    other = keys.generate()
    forged = json.loads(scenario.read("prereg"))
    forged["signature"]["pubkey"] = other[1].hex()
    forged["signature"]["keyid"] = keys.keyid_for(other[1])
    scenario.add_raw("forged", json.dumps(forged))
    scenario.sign_with("postreg2", other)
    report = scenario.verify(*TESTS_LINKED)
    assert report["code"] == "asexec-verify/1 chain=PASS format=PASS keyconsist=FAIL selfsig=FAIL"
    commitment = _commitment(report)
    assert commitment["keyid"] == keys.keyid_for(scenario.key[1])
    assert len(commitment["counted_postregs"]) == 2
    (by_b,) = commitment["rejected_postregs"]
    assert by_b["keyid"] == keys.keyid_for(other[1])
    assert by_b["reason"] == "signed by a different key than the pre-registration"
    (rejected,) = report["rejected_preregs"]
    assert rejected["keyid"] == keys.keyid_for(other[1])
    assert [(r["ref"], r["reason"]) for r in rejected["rejected_postregs"]] == [
        (by_b["ref"], PREREG_INVALID)
    ]


def test_matching__postreg_rejected_under_a_commitment_is_also_rejected_under_a_copy(scenario):
    """Matching: a postreg that counts toward no commitment of its ref is listed under each
    commitment and each rejected pre-registration of that ref, with the reason it fails
    there."""
    scenario.add_raw("copy", _broken_copy(scenario))
    scenario.sign_with("postreg2", keys.generate())
    report = scenario.verify()
    (under_commitment,) = _commitment(report)["rejected_postregs"]
    assert under_commitment["reason"] == "signed by a different key than the pre-registration"
    (rejected,) = report["rejected_preregs"]
    (under_copy,) = rejected["rejected_postregs"]
    assert under_copy == {**under_commitment, "reason": PREREG_INVALID}


def test_matching__postreg_naming_only_rejected_preregs_is_rejected_under_each(scenario):
    """Matching (b): with no commitment of its ref, a postreg naming it is listed under each
    rejected pre-registration of the ref, whatever its own signature, and is not
    notarization-only."""
    scenario.tamper("prereg", _break_sig)
    scenario.add_raw("other", _broken_copy(scenario, keyid=keys.keyid_for(keys.generate()[1])))
    scenario.tamper(
        "postreg0", lambda envelope: envelope["payload"]["target"].update(model_id="SWAPPED")
    )
    report = scenario.verify(*TESTS_LINKED)
    assert report["code"] == "asexec-verify/1 chain=FAIL format=PASS keyconsist=FAIL selfsig=FAIL"
    assert report["commitments"] == [] and report["notarization_only"] == []
    first, second = report["rejected_preregs"]
    assert first["ref"] == second["ref"] and first["keyid"] != second["keyid"]
    for rejected in (first, second):
        assert len(rejected["rejected_postregs"]) == 3
        assert {r["reason"] for r in rejected["rejected_postregs"]} == {PREREG_INVALID}


def test_matching__copies_of_a_rejected_prereg_are_listed_once(scenario):
    """Matching (c): copies of a rejected pre-registration with the same ref and keyid are
    listed once, however many are provided and however each is broken, and their postregs
    are listed once under it."""
    scenario.tamper("prereg", _break_sig)
    scenario.add_raw("copy", scenario.read("prereg"))
    other_break = json.loads(scenario.read("prereg"))
    other_break["signature"]["sig"] = "22" * 64
    scenario.add_raw("copy2", json.dumps(other_break))
    (rejected,) = scenario.verify()["rejected_preregs"]
    assert len(rejected["rejected_postregs"]) == 3


def test_matching__rejected_preregs_do_not_depend_on_file_order(scenario):
    scenario.add_raw("copy", _broken_copy(scenario, keyid=keys.keyid_for(keys.generate()[1])))
    scenario.sign_with("postreg2", keys.generate())
    paths = scenario.write()
    tests = ["chain", "format", "keyconsist", "selfsig"]
    forwards = verify_paths(paths, tests, str(scenario.artifacts))
    backwards = verify_paths(paths[::-1], tests, str(scenario.artifacts))
    assert forwards["code"] == backwards["code"]
    assert _summary(forwards) == _summary(backwards)
    assert forwards["rejected_preregs"] == backwards["rejected_preregs"]
