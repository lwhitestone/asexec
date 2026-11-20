"""``chain`` (postreg chain linearity): docs/VERIFICATION.md `### chain`. Naming: see conftest.py.

The scenario's chain is postreg0 <- postreg1 <- postreg2.
"""

import pytest

from asexec import keys

PASS = "asexec-verify/1 chain=PASS format=PASS selfsig=PASS"
FAIL = "asexec-verify/1 chain=FAIL format=PASS selfsig=PASS"
EMPTY = "requested but no commitment has counted postregs to chain-check"
BOGUS_REF = "sha-256:" + "cd" * 32


def test_chain__pass__all(scenario):
    """chain #1-#3: one root, every other prev_hash is a counted postreg, no forks."""
    report = scenario.verify("chain")
    assert report["code"] == PASS
    assert report["commitments"][0]["chain_ok"] is True


def test_chain__pass__single_postreg(scenario):
    """chain #1: a chain of one postreg (just the root) is linear."""
    scenario.drop("postreg1")
    scenario.drop("postreg2")
    assert scenario.code("chain") == PASS


def test_chain__pass__1_null_prev_hash_is_absent(scenario):
    """chain #1: a null prev_hash is absent, so a root may carry one."""
    scenario.set("postreg0", "payload.prev_hash", None)
    assert scenario.code("chain") == PASS


def test_chain__fail__1_exactly_one_root__two_roots(scenario):
    """chain #1: exactly one counted postreg has no prev_hash. Two roots fail."""
    scenario.link("postreg1", prev=None)  # a second root; postreg2 still points at postreg1
    assert scenario.code("chain") == FAIL


def test_chain__fail__1_exactly_one_root__no_root(scenario):
    """chain #1: no root fails. (Unavoidably also breaks #2: the head's prev is missing.)"""
    scenario.link("postreg0", prev=BOGUS_REF)
    assert scenario.code("chain") == FAIL


def test_chain__fail__2_prev_hash_is_a_counted_postreg__missing_link(scenario):
    """chain #2: a prev_hash pointing at a postreg that was not provided is a gap."""
    scenario.drop("postreg1")
    assert scenario.code("chain") == FAIL


def test_chain__fail__2_prev_hash_is_a_counted_postreg__other_commitment(scenario):
    """chain #2: the link must be a counted postreg of the SAME prereg."""
    scenario.add_prereg("other")
    scenario.add_postreg("other_postreg", fulfills="other")
    scenario.link("postreg2", prev="other_postreg")
    assert scenario.code("chain") == FAIL


@pytest.mark.parametrize(
    "junk",
    [
        pytest.param(["a"], id="list"),
        pytest.param({"a": 1}, id="object"),
        pytest.param(7, id="number"),
        pytest.param(0, id="falsy-number"),
        pytest.param([], id="falsy-list"),
    ],
)
def test_chain__fail__2_prev_hash_is_a_counted_postreg__not_a_string(scenario, junk):
    """chain #2: a non-string prev_hash links to nothing. It is a gap, never a root."""
    scenario.set("postreg1", "payload.prev_hash", junk)
    assert scenario.code("chain") == FAIL


def test_chain__fail__2_prev_hash_is_a_counted_postreg__empty_string(scenario):
    """chain #2: an empty-string prev_hash is present, so it is a link (to nothing), not a
    root. (On the root it unavoidably also breaks #1: no root is left.)"""
    scenario.set("postreg0", "payload.prev_hash", "")
    assert scenario.code("chain") == FAIL


def test_chain__fail__3_no_prev_hash_shared__fork(scenario):
    """chain #3: no ref is the prev_hash of more than one counted postreg."""
    scenario.add_postreg("postreg1b", prev="postreg0", transcript="transcript1.txt")
    assert scenario.code("chain") == FAIL


def test_chain__fail__empty_no_counted_postreg(scenario):
    """chain (*): a prereg with no counted postreg has nothing to chain-check."""
    for name in ("postreg0", "postreg1", "postreg2"):
        scenario.drop(name)
    report = scenario.verify("chain")
    assert report["code"] == FAIL
    assert report["results"]["chain"]["applicable"] == 0
    assert report["results"]["chain"]["reason"] == EMPTY


def test_chain__fail__empty_only_rejected_postregs(scenario):
    """chain (*): a prereg whose postregs are all rejected (signed by another key) has no
    counted postreg, so there is nothing to chain-check."""
    other = keys.generate()
    for name in ("postreg0", "postreg1", "postreg2"):
        scenario.sign_with(name, other)
    report = scenario.verify("chain")
    assert len(report["commitments"][0]["rejected_postregs"]) == 3
    assert report["code"] == FAIL
    assert report["results"]["chain"]["applicable"] == 0
    assert report["results"]["chain"]["reason"] == EMPTY


def test_chain__fail__empty_prereg_fails_selfsig(scenario):
    """chain (*): a prereg that fails selfsig is no commitment, so its chain of validly
    signed postregs, which is linear, has nothing to be counted toward and is not
    examined."""
    scenario.tamper("prereg", lambda envelope: envelope["signature"].update(sig="00" * 64))
    report = scenario.verify("chain")
    assert report["commitments"] == []
    assert report["code"] == "asexec-verify/1 chain=FAIL format=PASS selfsig=FAIL"
    assert report["results"]["chain"]["applicable"] == 0
    assert report["results"]["chain"]["reason"] == EMPTY
