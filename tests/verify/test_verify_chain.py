"""``chain`` (postreg chain linearity): docs/VERIFICATION.md `### chain`. Naming: see conftest.py.

The scenario's chain is postreg0 <- postreg1 <- postreg2.
"""

import pytest

PASS = "asexec-verify/1 BDR=PASS chain=PASS"
FAIL = "asexec-verify/1 BDR=PASS chain=FAIL"
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


def test_chain__fail__3_no_prev_hash_shared__fork(scenario):
    """chain #3: no ref is the prev_hash of more than one counted postreg."""
    scenario.add_postreg("postreg1b", prev="postreg0", transcript="transcript1.txt")
    assert scenario.code("chain") == FAIL


def test_chain__fail__vacuous_no_counted_postreg(scenario):
    """chain (*): a prereg with no counted postreg has nothing to chain-check."""
    for name in ("postreg0", "postreg1", "postreg2"):
        scenario.drop(name)
    report = scenario.verify("chain")
    assert report["code"] == FAIL
    assert report["results"]["chain"]["applicable"] == 0
