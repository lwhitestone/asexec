"""Offline drand quicknet verification, using a baked real round (no network)."""
from asexec import drand

# Real quicknet round 1000 (fetched once; verification is offline).
ROUND = 1000
SIG = ("b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125"
       "e342b73a8dd2bacbe47e4b6b63ed5e39")
RAND = "fe290beca10872ef2fb164d2aa4442de4566183ec51c56ff3cd603d930e54fdd"


def test_verify_real_round_offline():
    assert drand.verify_round(ROUND, SIG, RAND) is True


def test_reject_tampered_round():
    assert drand.verify_round(ROUND + 1, SIG, RAND) is False


def test_reject_wrong_randomness():
    assert drand.verify_round(ROUND, SIG, "00" * 32) is False


def test_reject_garbage_signature():
    assert drand.verify_round(ROUND, "ab" * 48, RAND) is False


def test_round_time_roundtrip():
    t = drand.time_of_round(ROUND)
    assert drand.round_at_time(t) == ROUND
    # quicknet genesis + (round-1)*period
    assert t == 1692803367 + (ROUND - 1) * 3
