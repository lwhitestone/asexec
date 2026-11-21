"""Offline drand quicknet verification, using a baked real round (no network)."""

import io
import json

import pytest

from asexec import drand
from asexec.errors import NetworkError
from asexec.models import FloorInput

# Real quicknet round 1000 (fetched once; verification is offline).
ROUND = 1000
SIG = (
    "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125"
    "e342b73a8dd2bacbe47e4b6b63ed5e39"
)
RAND = "fe290beca10872ef2fb164d2aa4442de4566183ec51c56ff3cd603d930e54fdd"
CHAIN = drand.QUICKNET_HASH  # every verify-path helper takes the chain explicitly


def test_verify_real_round_offline():
    assert drand.verify_round(ROUND, SIG, RAND, chain_hash=CHAIN) is True


def test_reject_tampered_round():
    assert drand.verify_round(ROUND + 1, SIG, RAND, chain_hash=CHAIN) is False


def test_reject_wrong_randomness():
    assert drand.verify_round(ROUND, SIG, "00" * 32, chain_hash=CHAIN) is False


def test_reject_garbage_signature():
    # randomness=None skips the sha256(sig) check so the BLS decompress/pairing
    # path itself is what rejects the signature (costs ~1s).
    assert drand.verify_round(ROUND, "ab" * 48, None, chain_hash=CHAIN) is False


def test_reject_undecodable_signature_point():
    # 0xff.. is not a valid compressed G1 point; decompress must fail closed.
    assert drand.verify_round(ROUND, "ff" * 48, None, chain_hash=CHAIN) is False


def test_reject_unknown_chain():
    assert drand.verify_round(ROUND, SIG, RAND, chain_hash="00" * 32) is False


def test_round_time_roundtrip():
    round_time = drand.time_of_round(ROUND, CHAIN)
    assert drand.round_at_time(round_time, CHAIN) == ROUND
    # quicknet genesis + (round-1)*period
    assert round_time == 1692803367 + (ROUND - 1) * 3


def test_pinned_chains_are_quicknet_with_its_genesis_and_period():
    """The pinned chains, written out: a floor's time (floor, order) is the chain's genesis
    plus (round - 1) periods, so changing either moves every floor's time, and changing the
    key fails every floor. One chain, quicknet, the default."""
    quicknet = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
    assert drand.QUICKNET_HASH == drand.SIGNING_CHAIN == quicknet
    assert drand.CHAINS == {
        quicknet: {
            "beacon_id": "quicknet",
            "public_key": (
                "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c"
                "8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb"
                "5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a"
            ),
            "genesis_time": 1692803367,
            "period": 3,
            "scheme": "bls-unchained-g1-rfc9380",
        }
    }
    assert drand.time_of_round(1000, CHAIN) == 1692806364  # 2023-08-23T15:59:24Z


# --- verified_floor: a round fetched earlier, verified at signing ----------------- #
def test_verified_floor_of_a_saved_round_is_the_floor_fetch_floor_writes():
    """A round as drand's HTTP API returns it ({round, randomness, signature}), verified
    offline, is the anchor.floor record --floor writes for the same round."""
    saved = {"round": ROUND, "randomness": RAND, "signature": SIG}
    assert drand.verified_floor(saved, CHAIN) == drand.floor_record({"chain_hash": CHAIN, **saved})
    assert drand.verified_floor(saved, CHAIN) == {
        "floor_type": "drand",
        "chain_hash": drand.QUICKNET_HASH,
        "round": ROUND,
        "signature": SIG,
        "randomness": RAND,
    }


@pytest.mark.parametrize(
    "over",
    [
        {"round": ROUND + 1},
        {"round": 2**70},
        {"round": -1},
        {"randomness": "00" * 32},
        {"signature": "ab" * 48},
        {"signature": SIG.upper()},
        {"round": "1000"},
    ],
    ids=["another-round", "round-too-large", "round-negative", "randomness", "signature",
         "signature-uppercase", "round-a-string"],
)  # fmt: skip
def test_verified_floor_refuses_a_round_that_does_not_verify(over):
    """Signing refuses a round that fails the floor conditions: a ValueError, never a floor."""
    with pytest.raises(ValueError):
        drand.verified_floor({"round": ROUND, "randomness": RAND, "signature": SIG, **over}, CHAIN)


# --- verify_floor ------------------------------------------------------------ #
def _floor(**over):
    """A parsed floor: its shape is FloorInput's job (covered by tests/verify/)."""
    floor = {"floor_type": "drand", "chain_hash": drand.QUICKNET_HASH, "round": ROUND,
         "signature": SIG, "randomness": RAND}  # fmt: skip
    floor.update(over)
    return FloorInput.model_validate(floor)


def test_verify_floor_accepts_real_round():
    res = drand.verify_floor(_floor())
    assert res == {
        "status": "verified",
        "floor_type": "drand",
        "round": ROUND,
        "created_no_earlier_than": drand.time_of_round(ROUND, CHAIN),
    }


def test_verify_floor_tampered_round_is_invalid():
    assert drand.verify_floor(_floor(round=ROUND + 1))["status"] == "invalid"


# --- fetch_round / fetch_floor (urlopen mocked) ------------------------------- #
class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()


def _payload(round_no=ROUND):
    return _Resp(json.dumps({"round": round_no, "randomness": RAND, "signature": SIG}).encode())


def test_fetch_round_builds_url_and_maps_fields(monkeypatch):
    seen = []

    def fake(url, timeout):
        seen.append((url, timeout))
        return _payload()

    monkeypatch.setattr(drand.urllib.request, "urlopen", fake)
    got = drand.fetch_round(ROUND, chain_hash=CHAIN)
    assert seen == [(f"https://api.drand.sh/{drand.QUICKNET_HASH}/public/{ROUND}", 10)]
    assert got == {
        "beacon": "quicknet",
        "chain_hash": drand.QUICKNET_HASH,
        "round": ROUND,
        "randomness": RAND,
        "signature": SIG,
    }


def test_fetch_round_default_is_latest(monkeypatch):
    urls = []
    monkeypatch.setattr(
        drand.urllib.request, "urlopen", lambda url, timeout: urls.append(url) or _payload()
    )
    drand.fetch_round(chain_hash=CHAIN)
    assert urls[0].endswith("/public/latest")


def test_fetch_round_falls_back_to_next_mirror(monkeypatch):
    urls = []

    def fake(url, timeout):
        urls.append(url)
        if len(urls) == 1:
            raise OSError("down")
        return _payload()

    monkeypatch.setattr(drand.urllib.request, "urlopen", fake)
    assert drand.fetch_round(ROUND, chain_hash=CHAIN)["round"] == ROUND
    assert urls[0].startswith("https://api.drand.sh/")
    assert urls[1].startswith("https://api2.drand.sh/")


def test_fetch_round_all_mirrors_fail_raises_network_error(monkeypatch):
    def fake(url, timeout):
        raise OSError("down")

    monkeypatch.setattr(drand.urllib.request, "urlopen", fake)
    with pytest.raises(NetworkError, match="any mirror"):
        drand.fetch_round(ROUND, chain_hash=CHAIN)


def test_fetch_round_malformed_body_is_network_error(monkeypatch):
    monkeypatch.setattr(
        drand.urllib.request, "urlopen", lambda url, timeout: _Resp(b'{"round": 1}')
    )
    with pytest.raises(NetworkError):
        drand.fetch_round(ROUND, chain_hash=CHAIN)


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param({"signature": "not-hex"}, id="signature-not-hex"),
        pytest.param({"signature": 5}, id="signature-not-string"),
        pytest.param({"randomness": "zz"}, id="randomness-not-hex"),
    ],
)
def test_fetch_round_malformed_round_falls_back_to_next_mirror(monkeypatch, bad):
    """A mirror's malformed round is never signed into a floor: the next mirror is tried."""
    bodies = [{"round": ROUND, "randomness": RAND, "signature": SIG, **bad}]
    bodies.append({"round": ROUND, "randomness": RAND, "signature": SIG})
    monkeypatch.setattr(
        drand.urllib.request,
        "urlopen",
        lambda url, timeout: _Resp(json.dumps(bodies.pop(0)).encode()),
    )
    assert drand.fetch_floor(CHAIN) == _floor().model_dump()


def test_fetch_floor_every_mirror_malformed_is_network_error(monkeypatch):
    body = json.dumps({"round": ROUND, "randomness": RAND, "signature": "not-hex"}).encode()
    monkeypatch.setattr(drand.urllib.request, "urlopen", lambda url, timeout: _Resp(body))
    with pytest.raises(NetworkError, match="any mirror"):
        drand.fetch_floor(CHAIN)


def test_fetch_floor_returns_floor_record(monkeypatch):
    monkeypatch.setattr(drand.urllib.request, "urlopen", lambda url, timeout: _payload())
    assert drand.fetch_floor(CHAIN) == _floor().model_dump()
