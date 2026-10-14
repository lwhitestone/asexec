import hashlib
import struct
from types import SimpleNamespace

import pytest

from asexec import hashing, keys, manifest, roughtime


@pytest.fixture
def keypair():
    priv, pub = keys.generate()
    return priv, pub


@pytest.fixture
def make_commitment(tmp_path):
    """Factory: build a signed prereg (+ optional postregs) over real artifacts.

    Returns a dict with paths and the signing keypair. No drand (offline).
    """

    def _make(due="2099-01-01T00:00:00Z", n_receipts=1, priv=None, pub=None):
        if priv is None:
            priv, pub = keys.generate()
        art = tmp_path / "artifacts"
        (art / "harness").mkdir(parents=True, exist_ok=True)
        (art / "harness" / "eval.py").write_text("def run():\n    return 42\n")
        target = {"kind": "api", "provider": "anthropic", "model_id": "m", "endpoint": ""}

        subj = hashing.build_subject([str(art / "harness")])
        pre_body = manifest.build_prereg(
            target, due=due, declaration="all runs in full", subject=subj
        )
        pre = manifest.sign(pre_body, priv, pub)
        pre_path = tmp_path / "prereg.json"
        manifest.save(pre, str(pre_path))
        pre_ref = manifest.ref(pre_body)

        receipt_paths = []
        prev = None
        for index in range(n_receipts):
            tpath = art / f"transcript{index}.txt"
            tpath.write_text(f"run {index}: score=0.{index}\n")
            rsubj = hashing.build_subject([str(tpath), str(art / "harness")])
            rbody = manifest.build_postreg(
                target, due=due, fulfills=pre_ref, subject=rsubj, prev_hash=prev
            )
            receipt = manifest.sign(rbody, priv, pub)
            rp = tmp_path / f"receipt{index}.json"
            manifest.save(receipt, str(rp))
            receipt_paths.append(str(rp))
            prev = manifest.ref(rbody)

        return {
            "tmp": tmp_path,
            "artifacts": str(art),
            "prereg": str(pre_path),
            "prereg_ref": pre_ref,
            "receipts": receipt_paths,
            "priv": priv,
            "pub": pub,
        }

    return _make


# --------------------------------------------------------------------------- #
# synthetic Roughtime server, built to roughtime.py's documented wire spec
# --------------------------------------------------------------------------- #
@pytest.fixture
def wire():
    """Small Roughtime wire-format helpers (little-endian ints, Merkle hashing)."""
    return SimpleNamespace(
        u32=lambda value: struct.pack("<I", value),
        u64=lambda value: struct.pack("<Q", value),
        leaf=lambda nonce: hashlib.sha512(b"\x00" + nonce).digest(),
        node=lambda left, right: hashlib.sha512(b"\x01" + left + right).digest(),
    )


@pytest.fixture
def make_server(wire):
    """Factory: ``make_server(...) -> (long_term_pub, sign_response)``."""

    def _make(
        midpoint_us=1_700_000_000_000_000,
        radius_us=1_000_000,
        mint=0,
        maxt=2_000_000_000_000_000,
    ):
        lt_priv, lt_pub = keys.generate()
        on_priv, on_pub = keys.generate()

        dele = roughtime.build_message(
            {"MINT": wire.u64(mint), "MAXT": wire.u64(maxt), "PUBK": on_pub}
        )
        cert = roughtime.build_message(
            {
                "DELE": dele,
                "SIG": keys.sign(lt_priv, roughtime.DELEGATION_CONTEXT + dele),
            }
        )

        def sign_response(nonce, index=0, path=b"", root=None):
            if root is None:
                root = wire.leaf(nonce)
            srep = roughtime.build_message(
                {"RADI": wire.u32(radius_us), "MIDP": wire.u64(midpoint_us), "ROOT": root}
            )
            sig = keys.sign(on_priv, roughtime.RESPONSE_CONTEXT + srep)
            return roughtime.build_message(
                {
                    "SIG": sig,
                    "NONC": nonce,
                    "PATH": path,
                    "INDX": wire.u32(index),
                    "SREP": srep,
                    "CERT": cert,
                }
            )

        return lt_pub, sign_response

    return _make


@pytest.fixture
def ceiling_for():
    """Factory: an envelope ceiling record for ``nonce_hex`` from a synthetic server."""

    def _ceiling_for(nonce_hex, witness_id, lt_pub, sign_response):
        resp = sign_response(bytes.fromhex(nonce_hex))
        return {
            "ceiling_type": "roughtime",
            "witness_id": witness_id,
            "pubkey": lt_pub.hex(),
            "nonce": nonce_hex,
            "midpoint": 1_700_000_000.0,
            "radius": 1.0,
            "response": resp.hex(),
        }

    return _ceiling_for
