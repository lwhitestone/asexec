"""Roughtime ceiling verification, exercised offline by a wire-accurate synthetic
server (a real live-server capture is a deferred follow-up)."""
import hashlib
import struct

import pytest

from asexec import keys, manifest, roughtime, verifier
from asexec.errors import VerificationError


# --------------------------------------------------------------------------- #
# a synthetic Roughtime server, built to roughtime.py's documented wire spec
# --------------------------------------------------------------------------- #
def _u32(n):
    return struct.pack("<I", n)


def _u64(n):
    return struct.pack("<Q", n)


def _leaf(nonce):
    return hashlib.sha512(b"\x00" + nonce).digest()


def _node(left, right):
    return hashlib.sha512(b"\x01" + left + right).digest()


def make_server(midpoint_us=1_700_000_000_000_000, radius_us=1_000_000,
                mint=0, maxt=2_000_000_000_000_000):
    """Return (long_term_pub, sign_response) for a synthetic Roughtime server."""
    lt_priv, lt_pub = keys.generate()
    on_priv, on_pub = keys.generate()

    dele = roughtime.build_message({"MINT": _u64(mint), "MAXT": _u64(maxt), "PUBK": on_pub})
    cert = roughtime.build_message({
        "DELE": dele,
        "SIG": keys.sign(lt_priv, roughtime.DELEGATION_CONTEXT + dele),
    })

    def sign_response(nonce, index=0, path=b"", root=None):
        if root is None:
            root = _leaf(nonce)
        srep = roughtime.build_message({"RADI": _u32(radius_us), "MIDP": _u64(midpoint_us),
                                        "ROOT": root})
        sig = keys.sign(on_priv, roughtime.RESPONSE_CONTEXT + srep)
        return roughtime.build_message({
            "SIG": sig, "NONC": nonce, "PATH": path, "INDX": _u32(index),
            "SREP": srep, "CERT": cert,
        })

    return lt_pub, sign_response


# --------------------------------------------------------------------------- #
# message framing round-trip
# --------------------------------------------------------------------------- #
def test_message_roundtrip():
    fields = {"NONC": b"\x00" * 32, "VER": _u32(1), "ZZZZ": b"\x11" * 8}
    parsed = roughtime.parse_message(roughtime.build_message(fields))
    assert parsed == fields


def test_parse_rejects_truncated():
    with pytest.raises(VerificationError):
        roughtime.parse_message(b"\x02\x00\x00\x00")  # claims 2 tags, no data


def test_parse_rejects_duplicate_tags():
    # two "SIG" tags: hand-craft a message that bypasses build_message's sort.
    body = (struct.pack("<I", 2)                  # n = 2
            + struct.pack("<I", 4)                # offset of value 0
            + b"SIG\x00" + b"SIG\x00"             # duplicate tags
            + b"\x00" * 8)                        # two 4-byte values
    with pytest.raises(VerificationError):
        roughtime.parse_message(body)


def test_wrong_width_uint_field_rejected():
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
    info = roughtime.verify_response(bytes.fromhex(_INT08H_RESPONSE),
                                     bytes.fromhex(_INT08H_NONCE), pinned)
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
        roughtime.verify_response(bytes.fromhex(_INT08H_RESPONSE),
                                  bytes.fromhex(_INT08H_NONCE), other_pub)


# --------------------------------------------------------------------------- #
# verify_response — the real protocol path
# --------------------------------------------------------------------------- #
def test_single_leaf_verifies():
    nonce = hashlib.sha256(b"body").digest()
    lt_pub, sign_response = make_server()
    resp = sign_response(nonce)
    info = roughtime.verify_response(resp, nonce, lt_pub)
    assert info["midpoint"] == pytest.approx(1_700_000_000.0)
    assert info["radius"] == pytest.approx(1.0)


def test_merkle_path_verifies():
    # nonce at index 1 of a 2-leaf tree; sibling is the other leaf's hash.
    nonce = hashlib.sha256(b"ours").digest()
    other = _leaf(hashlib.sha256(b"other").digest())
    root = _node(other, _leaf(nonce))
    lt_pub, sign_response = make_server()
    resp = sign_response(nonce, index=1, path=other, root=root)
    info = roughtime.verify_response(resp, nonce, lt_pub)
    assert info["midpoint"] == pytest.approx(1_700_000_000.0)


def test_wrong_long_term_key_rejected():
    nonce = hashlib.sha256(b"body").digest()
    _lt_pub, sign_response = make_server()
    _other_priv, other_pub = keys.generate()
    with pytest.raises(VerificationError):
        roughtime.verify_response(sign_response(nonce), nonce, other_pub)


def test_tampered_signature_rejected():
    nonce = hashlib.sha256(b"body").digest()
    lt_pub, sign_response = make_server()
    msg = roughtime.parse_message(sign_response(nonce))
    bad = bytearray(msg["SIG"])
    bad[0] ^= 0xFF  # corrupt the delegated-key signature over SREP
    msg["SIG"] = bytes(bad)
    with pytest.raises(VerificationError):
        roughtime.verify_response(roughtime.build_message(msg), nonce, lt_pub)


def test_midpoint_outside_validity_window_rejected():
    nonce = hashlib.sha256(b"body").digest()
    # online key only valid far in the future; the attested midpoint predates it.
    lt_pub, sign_response = make_server(midpoint_us=1_700_000_000_000_000,
                                        mint=1_900_000_000_000_000,
                                        maxt=2_000_000_000_000_000)
    with pytest.raises(VerificationError):
        roughtime.verify_response(sign_response(nonce), nonce, lt_pub)


def test_wrong_nonce_does_not_root():
    nonce = hashlib.sha256(b"body").digest()
    lt_pub, sign_response = make_server()
    resp = sign_response(nonce)
    other = hashlib.sha256(b"different").digest()
    with pytest.raises(VerificationError):
        roughtime.verify_response(resp, other, lt_pub)


# --------------------------------------------------------------------------- #
# verify_ceiling — envelope record + nonce binding + pinned-key resolution
# --------------------------------------------------------------------------- #
def _ceiling_for(nonce_hex, witness_id, lt_pub, sign_response):
    resp = sign_response(bytes.fromhex(nonce_hex))
    return {
        "ceiling_type": "roughtime", "witness_id": witness_id,
        "pubkey": lt_pub.hex(), "nonce": nonce_hex,
        "midpoint": 1_700_000_000.0, "radius": 1.0, "response": resp.hex(),
    }


def test_verify_ceiling_ok():
    nonce_hex = hashlib.sha256(b"m").hexdigest()
    lt_pub, sign_response = make_server()
    ceiling = _ceiling_for(nonce_hex, "synthetic", lt_pub, sign_response)
    res = roughtime.verify_ceiling(ceiling, "sha-256:" + nonce_hex,
                                   servers={"synthetic": {"pubkey": lt_pub}})
    assert res["status"] == "verified"
    assert res["midpoint"] == pytest.approx(1_700_000_000.0)


def test_verify_ceiling_nonce_must_bind():
    nonce_hex = hashlib.sha256(b"m").hexdigest()
    lt_pub, sign_response = make_server()
    ceiling = _ceiling_for(nonce_hex, "synthetic", lt_pub, sign_response)
    res = roughtime.verify_ceiling(ceiling, "sha-256:" + "aa" * 32,
                                   servers={"synthetic": {"pubkey": lt_pub}})
    assert res["status"] == "invalid"
    assert "does not bind" in res["error"]


def test_verify_ceiling_unpinned_witness():
    nonce_hex = hashlib.sha256(b"m").hexdigest()
    lt_pub, sign_response = make_server()
    ceiling = _ceiling_for(nonce_hex, "synthetic", lt_pub, sign_response)
    res = roughtime.verify_ceiling(ceiling, "sha-256:" + nonce_hex, servers={})
    assert res["status"] == "unpinned"


def test_verify_ceiling_pubkey_must_match_pin():
    nonce_hex = hashlib.sha256(b"m").hexdigest()
    lt_pub, sign_response = make_server()
    ceiling = _ceiling_for(nonce_hex, "synthetic", lt_pub, sign_response)
    _other_priv, other_pub = keys.generate()
    res = roughtime.verify_ceiling(ceiling, "sha-256:" + nonce_hex,
                                   servers={"synthetic": {"pubkey": other_pub}})
    assert res["status"] == "invalid"
    assert "does not match the pinned key" in res["error"]


# --------------------------------------------------------------------------- #
# integration: a ceiling attached to a real manifest, through verify_paths
# --------------------------------------------------------------------------- #
def test_ceiling_through_verify_paths(make_commitment, monkeypatch):
    c = make_commitment(n_receipts=0)
    mani = manifest.load(c["prereg"])
    body = manifest.get_body(mani)
    nonce_hex = manifest.ref(body).split(":", 1)[-1]

    lt_pub, sign_response = make_server()
    monkeypatch.setitem(roughtime.SERVERS, "synthetic", {"pubkey": lt_pub})
    manifest.attach_ceiling(mani, _ceiling_for(nonce_hex, "synthetic", lt_pub, sign_response))
    manifest.save(mani, c["prereg"])

    rep = verifier.verify_paths([c["prereg"]], ["bedrock", "ceiling"])
    assert rep["results"]["ceiling"]["result"] == "PASS"
    assert rep["code"] == "asexec-verify/1 bedrock=PASS ceiling=PASS"
    assert rep["ceiling_trust"] and "trusting synthetic" in rep["ceiling_trust"][0]
