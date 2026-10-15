"""Roughtime ceiling verification, exercised offline by a wire-accurate synthetic
server (a real live-server capture is a deferred follow-up)."""

import hashlib
import struct

import pytest

from asexec import keys, roughtime
from asexec.errors import VerificationError


# --------------------------------------------------------------------------- #
# message framing round-trip
# --------------------------------------------------------------------------- #
def test_message_roundtrip(wire):
    fields = {"NONC": b"\x00" * 32, "VER": wire.u32(1), "ZZZZ": b"\x11" * 8}
    parsed = roughtime.parse_message(roughtime.build_message(fields))
    assert parsed == fields


def test_parse_rejects_truncated():
    with pytest.raises(VerificationError):
        roughtime.parse_message(b"\x02\x00\x00\x00")  # claims 2 tags, no data


def test_parse_rejects_duplicate_tags():
    # two "SIG" tags: hand-craft a message that bypasses build_message's sort.
    body = (
        struct.pack("<I", 2)  # n = 2
        + struct.pack("<I", 4)  # offset of value 0
        + b"SIG\x00"
        + b"SIG\x00"  # duplicate tags
        + b"\x00" * 8
    )  # two 4-byte values
    with pytest.raises(VerificationError):
        roughtime.parse_message(body)


def test_wrong_width_uint_field_rejected(make_server):
    # a MIDP that is 4 bytes instead of 8 must be rejected, not reinterpreted.
    nonce = hashlib.sha256(b"body").digest()
    lt_pub, sign_response = make_server()
    resp = sign_response(nonce)
    msg = roughtime.parse_message(resp)
    srep = roughtime.parse_message(msg["SREP"])
    srep["MIDP"] = struct.pack("<I", 123)  # 4 bytes, wrong width
    msg["SREP"] = roughtime.build_message(srep)
    # (SREP signature now won't match either, but width is checked regardless)
    with pytest.raises(VerificationError):
        roughtime.verify_response(roughtime.build_message(msg), nonce, lt_pub)


# --------------------------------------------------------------------------- #
# a REAL captured int08h-Roughtime response (verifies fully offline, like the
# baked drand round). Reconciles the wire format against a live public server.
# --------------------------------------------------------------------------- #
_INT08H_NONCE = "6564f717ef7baf43794c6296e42dac022ed83bcbbf77963bc230c62053457cad"
_INT08H_RESPONSE = (
    "06000000400000006000000060000000c40000005c010000534947004e4f4e43504154485352"
    "455043455254494e4458b4bca5b250f5e3c7be2bb85912aefb2500358bd0d9cdeaa789b87817"
    "1b4c181a11d0ec344a174d13c3b603d8d5ae237cf5d95d32300b7cdd92f5073c33fcd0066564"
    "f717ef7baf43794c6296e42dac022ed83bcbbf77963bc230c62053457cad0300000004000000"
    "0c000000524144494d494450524f4f54404b4c00f8884e3336570600912ff350b65bc6a45d93"
    "d671c495fc0a7be9f243bb4aa57ba30e11167288610808fc7c6078814bbecfd1a7f659d79fc9"
    "727094a805d4cac969c70e582ec7ffec02000000400000005349470044454c45d3a580b04660"
    "60fd40f98a84dd96af2dd3080938bb66ac49c20a10aa03d28bb9d039d3679732a7dbb2b03111"
    "a7a00943e28ba03bc557fe05612d68549d3f5f010300000020000000280000005055424b4d49"
    "4e544d415854ea05845251075c0038ed6fb8f0ed58a272f5f4762db7ec3e5ec49a86ea2b0cbc"
    "0000000000000000ffffffffffffffff00000000"
)


def test_real_int08h_capture_verifies_offline():
    # Verifies against the PINNED int08h long-term key with no network.
    pinned = roughtime.SERVERS["int08h-Roughtime"]["pubkey"]
    info = roughtime.verify_response(
        bytes.fromhex(_INT08H_RESPONSE), bytes.fromhex(_INT08H_NONCE), pinned
    )
    # int08h issues a wide-open delegation and a real ~2026 midpoint.
    assert info["midpoint"] > 1_700_000_000
    assert info["radius"] >= 0


def test_real_int08h_capture_rejects_wrong_nonce():
    pinned = roughtime.SERVERS["int08h-Roughtime"]["pubkey"]
    with pytest.raises(VerificationError):
        roughtime.verify_response(bytes.fromhex(_INT08H_RESPONSE), b"\x00" * 32, pinned)


def test_real_int08h_capture_rejects_wrong_pin():
    _priv, other_pub = keys.generate()
    with pytest.raises(VerificationError):
        roughtime.verify_response(
            bytes.fromhex(_INT08H_RESPONSE), bytes.fromhex(_INT08H_NONCE), other_pub
        )


# --------------------------------------------------------------------------- #
# verify_response — the real protocol path
# --------------------------------------------------------------------------- #
def test_single_leaf_verifies(make_server):
    nonce = hashlib.sha256(b"body").digest()
    lt_pub, sign_response = make_server()
    resp = sign_response(nonce)
    info = roughtime.verify_response(resp, nonce, lt_pub)
    assert info["midpoint"] == pytest.approx(1_700_000_000.0)
    assert info["radius"] == pytest.approx(1.0)


def test_merkle_path_verifies(make_server, wire):
    # nonce at index 1 of a 2-leaf tree; sibling is the other leaf's hash.
    nonce = hashlib.sha256(b"ours").digest()
    other = wire.leaf(hashlib.sha256(b"other").digest())
    root = wire.node(other, wire.leaf(nonce))
    lt_pub, sign_response = make_server()
    resp = sign_response(nonce, index=1, path=other, root=root)
    info = roughtime.verify_response(resp, nonce, lt_pub)
    assert info["midpoint"] == pytest.approx(1_700_000_000.0)


def test_wrong_long_term_key_rejected(make_server):
    nonce = hashlib.sha256(b"body").digest()
    _lt_pub, sign_response = make_server()
    _other_priv, other_pub = keys.generate()
    with pytest.raises(VerificationError):
        roughtime.verify_response(sign_response(nonce), nonce, other_pub)


def test_tampered_signature_rejected(make_server):
    nonce = hashlib.sha256(b"body").digest()
    lt_pub, sign_response = make_server()
    msg = roughtime.parse_message(sign_response(nonce))
    bad = bytearray(msg["SIG"])
    bad[0] ^= 0xFF  # corrupt the delegated-key signature over SREP
    msg["SIG"] = bytes(bad)
    with pytest.raises(VerificationError):
        roughtime.verify_response(roughtime.build_message(msg), nonce, lt_pub)


def test_midpoint_outside_validity_window_rejected(make_server):
    nonce = hashlib.sha256(b"body").digest()
    # online key only valid far in the future; the attested midpoint predates it.
    lt_pub, sign_response = make_server(
        midpoint_us=1_700_000_000_000_000, mint=1_900_000_000_000_000, maxt=2_000_000_000_000_000
    )
    with pytest.raises(VerificationError):
        roughtime.verify_response(sign_response(nonce), nonce, lt_pub)


def test_wrong_nonce_does_not_root(make_server):
    nonce = hashlib.sha256(b"body").digest()
    lt_pub, sign_response = make_server()
    resp = sign_response(nonce)
    other = hashlib.sha256(b"different").digest()
    with pytest.raises(VerificationError):
        roughtime.verify_response(resp, other, lt_pub)


# --------------------------------------------------------------------------- #
# verify_ceiling — envelope record + nonce binding + pinned-key resolution
# --------------------------------------------------------------------------- #
def test_verify_ceiling_ok(make_server, ceiling_for):
    nonce_hex = hashlib.sha256(b"m").hexdigest()
    lt_pub, sign_response = make_server()
    ceiling = ceiling_for(nonce_hex, "synthetic", lt_pub, sign_response)
    res = roughtime.verify_ceiling(
        ceiling, "sha-256:" + nonce_hex, servers={"synthetic": {"pubkey": lt_pub}}
    )
    assert res["status"] == "verified"
    assert res["midpoint"] == pytest.approx(1_700_000_000.0)


def test_verify_ceiling_nonce_must_bind(make_server, ceiling_for):
    nonce_hex = hashlib.sha256(b"m").hexdigest()
    lt_pub, sign_response = make_server()
    ceiling = ceiling_for(nonce_hex, "synthetic", lt_pub, sign_response)
    res = roughtime.verify_ceiling(
        ceiling, "sha-256:" + "aa" * 32, servers={"synthetic": {"pubkey": lt_pub}}
    )
    assert res["status"] == "invalid"
    assert "does not bind" in res["error"]


def test_verify_ceiling_unpinned_witness(make_server, ceiling_for):
    nonce_hex = hashlib.sha256(b"m").hexdigest()
    lt_pub, sign_response = make_server()
    ceiling = ceiling_for(nonce_hex, "synthetic", lt_pub, sign_response)
    res = roughtime.verify_ceiling(ceiling, "sha-256:" + nonce_hex, servers={})
    assert res["status"] == "unpinned"


def test_verify_ceiling_pubkey_must_match_pin(make_server, ceiling_for):
    nonce_hex = hashlib.sha256(b"m").hexdigest()
    lt_pub, sign_response = make_server()
    ceiling = ceiling_for(nonce_hex, "synthetic", lt_pub, sign_response)
    _other_priv, other_pub = keys.generate()
    res = roughtime.verify_ceiling(
        ceiling, "sha-256:" + nonce_hex, servers={"synthetic": {"pubkey": other_pub}}
    )
    assert res["status"] == "invalid"
    assert "does not match the pinned key" in res["error"]


# --------------------------------------------------------------------------- #
# sign-time client: request construction + fetch_ceiling (socket mocked)
# --------------------------------------------------------------------------- #
def test_build_request_is_padded_and_carries_nonce_and_version(wire):
    nonce = b"\x07" * 32
    req = roughtime.build_request(nonce)
    assert len(req) >= roughtime._REQUEST_MIN_LEN
    msg = roughtime.parse_message(req)
    assert msg["NONC"] == nonce
    assert msg["VER"] == wire.u32(1)


class _FakeSocket:
    """Stands in for a UDP socket; ``reply`` is bytes to return or an Exception."""

    instances: list = []

    def __init__(self, reply):
        self.reply = reply
        self.sent = []
        self.closed = False
        self.timeout = None
        _FakeSocket.instances.append(self)

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendto(self, data, addr):
        self.sent.append((data, addr))

    def recvfrom(self, bufsize):
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply, ("x", 0)

    def close(self):
        self.closed = True


def _patch_sockets(monkeypatch, replies):
    _FakeSocket.instances = []
    it = iter(replies)
    monkeypatch.setattr(roughtime.socket, "socket", lambda *args, **kwargs: _FakeSocket(next(it)))


def _servers(lt_pub, count=1):
    return {
        f"s{index}": {"host": f"h{index}.example", "port": 2000 + index, "pubkey": lt_pub}
        for index in range(count)
    }


def test_fetch_ceiling_happy_path(monkeypatch, make_server):
    lt_pub, sign_response = make_server()
    nonce = b"\x09" * 32
    _patch_sockets(monkeypatch, [sign_response(nonce)])
    got = roughtime.fetch_ceiling("sha-256:" + nonce.hex(), _servers(lt_pub), timeout=2.5)
    assert got["ceiling_type"] == "roughtime" and got["witness_id"] == "s0"
    assert got["nonce"] == nonce.hex() and got["pubkey"] == lt_pub.hex()
    sock = _FakeSocket.instances[0]
    assert sock.closed and sock.timeout == 2.5
    ((sent, addr),) = sock.sent
    assert addr == ("h0.example", 2000)
    assert roughtime.parse_message(sent)["NONC"] == nonce
    # the returned record round-trips through the offline verifier
    monkeypatch.setitem(roughtime.SERVERS, "s0", {"pubkey": lt_pub})
    assert roughtime.verify_ceiling(got, "sha-256:" + nonce.hex())["status"] == "verified"


def test_fetch_ceiling_strips_udp_framing(monkeypatch, make_server, wire):
    lt_pub, sign_response = make_server()
    nonce = b"\x0a" * 32
    resp = sign_response(nonce)
    framed = b"ROUGHTIM" + wire.u32(len(resp)) + resp
    _patch_sockets(monkeypatch, [framed])
    got = roughtime.fetch_ceiling("sha-256:" + nonce.hex(), _servers(lt_pub))
    assert got["response"] == resp.hex()


def test_fetch_ceiling_falls_through_timeout_and_bad_response(monkeypatch, make_server):
    lt_pub, sign_response = make_server()
    nonce = b"\x0b" * 32
    _patch_sockets(monkeypatch, [TimeoutError("timed out"), b"garbage", sign_response(nonce)])
    got = roughtime.fetch_ceiling("sha-256:" + nonce.hex(), _servers(lt_pub, 3))
    assert got["witness_id"] == "s2"
    assert all(sock.closed for sock in _FakeSocket.instances)


def test_fetch_ceiling_rejects_response_for_other_nonce(monkeypatch, make_server):
    from asexec.errors import NetworkError

    lt_pub, sign_response = make_server()
    _patch_sockets(monkeypatch, [sign_response(b"\x01" * 32)])
    with pytest.raises(NetworkError, match="verifiable"):
        roughtime.fetch_ceiling("sha-256:" + "02" * 32, _servers(lt_pub))


def test_fetch_ceiling_wrong_pinned_key_is_network_error(monkeypatch, make_server):
    from asexec.errors import NetworkError

    _, sign_response = make_server()
    other_pub = keys.generate()[1]
    nonce = b"\x0c" * 32
    _patch_sockets(monkeypatch, [sign_response(nonce)])
    with pytest.raises(NetworkError):
        roughtime.fetch_ceiling("sha-256:" + nonce.hex(), _servers(other_pub))


def test_fetch_ceiling_no_servers_configured():
    from asexec.errors import NetworkError

    with pytest.raises(NetworkError, match="no Roughtime servers"):
        roughtime.fetch_ceiling("sha-256:" + "00" * 32, {})
