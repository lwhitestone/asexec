"""Offline drand quicknet verification, using a baked real round (no network)."""

import io
import json

import pytest

from asexec import drand
from asexec.errors import NetworkError

# Real quicknet round 1000 (fetched once; verification is offline).
ROUND = 1000
SIG = (
    "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125"
    "e342b73a8dd2bacbe47e4b6b63ed5e39"
)
RAND = "fe290beca10872ef2fb164d2aa4442de4566183ec51c56ff3cd603d930e54fdd"


def test_verify_real_round_offline():
    assert drand.verify_round(ROUND, SIG, RAND) is True


def test_reject_tampered_round():
    assert drand.verify_round(ROUND + 1, SIG, RAND) is False


def test_reject_wrong_randomness():
    assert drand.verify_round(ROUND, SIG, "00" * 32) is False


def test_reject_garbage_signature():
    # randomness=None skips the sha256(sig) check so the BLS decompress/pairing
    # path itself is what rejects the signature (costs ~1s).
    assert drand.verify_round(ROUND, "ab" * 48, None) is False


def test_reject_undecodable_signature_point():
    # 0xff.. is not a valid compressed G1 point; decompress must fail closed.
    assert drand.verify_round(ROUND, "ff" * 48, None) is False


def test_reject_unknown_chain():
    assert drand.verify_round(ROUND, SIG, RAND, chain_hash="00" * 32) is False


def test_round_time_roundtrip():
    round_time = drand.time_of_round(ROUND)
    assert drand.round_at_time(round_time) == ROUND
    # quicknet genesis + (round-1)*period
    assert round_time == 1692803367 + (ROUND - 1) * 3


# --- verify_floor ------------------------------------------------------------ #
def _floor(**over):
    floor = {"floor_type": "drand", "chain_hash": drand.QUICKNET_HASH, "round": ROUND,
         "signature": SIG, "randomness": RAND}  # fmt: skip
    floor.update(over)
    return floor


def test_verify_floor_accepts_real_round():
    res = drand.verify_floor(_floor())
    assert res == {
        "status": "verified",
        "floor_type": "drand",
        "round": ROUND,
        "created_no_earlier_than": drand.time_of_round(ROUND),
    }


def test_verify_floor_tampered_round_is_invalid():
    assert drand.verify_floor(_floor(round=ROUND + 1))["status"] == "invalid"


def test_verify_floor_missing_fields_is_invalid_not_crash():
    floor = _floor()
    del floor["signature"]
    res = drand.verify_floor(floor)
    assert res["status"] == "invalid" and "error" in res


@pytest.mark.parametrize("floor", [{}, {"floor_type": "other"}])
def test_verify_floor_unsupported_type(floor):
    assert drand.verify_floor(floor)["status"] == "unsupported"


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
    got = drand.fetch_round(ROUND)
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
    drand.fetch_round()
    assert urls[0].endswith("/public/latest")


def test_fetch_round_falls_back_to_next_mirror(monkeypatch):
    urls = []

    def fake(url, timeout):
        urls.append(url)
        if len(urls) == 1:
            raise OSError("down")
        return _payload()

    monkeypatch.setattr(drand.urllib.request, "urlopen", fake)
    assert drand.fetch_round(ROUND)["round"] == ROUND
    assert urls[0].startswith("https://api.drand.sh/")
    assert urls[1].startswith("https://api2.drand.sh/")


def test_fetch_round_all_mirrors_fail_raises_network_error(monkeypatch):
    def fake(url, timeout):
        raise OSError("down")

    monkeypatch.setattr(drand.urllib.request, "urlopen", fake)
    with pytest.raises(NetworkError, match="any mirror"):
        drand.fetch_round(ROUND)


def test_fetch_round_malformed_body_is_network_error(monkeypatch):
    monkeypatch.setattr(
        drand.urllib.request, "urlopen", lambda url, timeout: _Resp(b'{"round": 1}')
    )
    with pytest.raises(NetworkError):
        drand.fetch_round(ROUND)


def test_fetch_floor_returns_floor_record(monkeypatch):
    monkeypatch.setattr(drand.urllib.request, "urlopen", lambda url, timeout: _payload())
    assert drand.fetch_floor() == _floor()
