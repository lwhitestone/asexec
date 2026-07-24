import os

import pytest

from asexec import hashing, keys, manifest


@pytest.fixture
def keypair():
    priv, pub = keys.generate()
    return priv, pub


def _window(closes):
    return {"closes": closes, "declares": "all runs in full"}


@pytest.fixture
def make_commitment(tmp_path):
    """Factory: build a signed prereg (+ optional receipts) over real artifacts.

    Returns a dict with paths and the signing keypair. No drand (offline).
    """
    def _make(closes="2099-01-01T00:00:00Z", n_receipts=1, priv=None, pub=None):
        if priv is None:
            priv, pub = keys.generate()
        art = tmp_path / "artifacts"
        (art / "harness").mkdir(parents=True, exist_ok=True)
        (art / "harness" / "eval.py").write_text("def run():\n    return 42\n")
        target = {"kind": "api", "provider": "anthropic", "model_id": "m", "endpoint": ""}

        subj = hashing.build_subject([str(art / "harness")])
        pre_body = manifest.build_preregistration(target, _window(closes), subject=subj)
        pre = manifest.sign(pre_body, priv, pub)
        pre_path = tmp_path / "prereg.json"
        manifest.save(pre, str(pre_path))
        pre_ref = manifest.ref(pre_body)

        receipt_paths = []
        prev = None
        for i in range(n_receipts):
            tpath = art / f"transcript{i}.txt"
            tpath.write_text(f"run {i}: score=0.{i}\n")
            rsubj = hashing.build_subject([str(tpath), str(art / "harness")])
            rbody = manifest.build_receipt(target, _window(closes), fulfills=pre_ref,
                                           subject=rsubj, prev_hash=prev)
            r = manifest.sign(rbody, priv, pub)
            rp = tmp_path / f"receipt{i}.json"
            manifest.save(r, str(rp))
            receipt_paths.append(str(rp))
            prev = manifest.ref(rbody)

        return {
            "tmp": tmp_path, "artifacts": str(art),
            "prereg": str(pre_path), "prereg_ref": pre_ref,
            "receipts": receipt_paths, "priv": priv, "pub": pub,
        }

    return _make
