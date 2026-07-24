"""Canonical/PAE, hashing, and keys."""
import json

import pytest

from asexec import hashing, keys
from asexec.canonical import canonical_bytes, pae, signing_input
from asexec.errors import HashAlgError


def test_canonical_is_key_order_independent():
    a = {"b": 1, "a": 2, "c": [3, {"y": 1, "x": 2}]}
    b = {"c": [3, {"x": 2, "y": 1}], "a": 2, "b": 1}
    assert canonical_bytes(a) == canonical_bytes(b)


def test_canonical_compact_utf8():
    assert canonical_bytes({"k": "café"}) == b'{"k":"caf\xc3\xa9"}'


def test_pae_is_unambiguous():
    # length-prefixing prevents "abc"+"" from colliding with "ab"+"c"
    assert pae(b"t", b"abc") != pae(b"t", b"ab") + b"c"
    assert pae(b"application/vnd.asexec+json", b"{}").startswith(b"asexec-PAE/v1 ")


def test_signing_input_changes_with_payload():
    assert signing_input({"a": 1}) != signing_input({"a": 2})


def test_hash_bytes_and_file(tmp_path):
    p = tmp_path / "f.txt"
    p.write_bytes(b"hello")
    assert hashing.hash_file(str(p)) == hashing.hash_bytes(b"hello")


def test_dir_hash_deterministic_and_sensitive(tmp_path):
    d = tmp_path / "d"
    (d / "sub").mkdir(parents=True)
    (d / "a.txt").write_text("A")
    (d / "sub" / "b.txt").write_text("B")
    h1 = hashing.hash_dir(str(d))
    h2 = hashing.hash_dir(str(d))
    assert h1 == h2
    (d / "sub" / "b.txt").write_text("B!")  # content change -> hash change
    assert hashing.hash_dir(str(d)) != h1


def test_build_subject_marks_dirs(tmp_path):
    (tmp_path / "dir").mkdir()
    (tmp_path / "dir" / "x").write_text("x")
    f = tmp_path / "file.txt"
    f.write_text("y")
    subj = hashing.build_subject([str(tmp_path / "dir"), str(f)])
    names = {s["name"] for s in subj}
    assert "dir/" in names and "file.txt" in names
    assert all("sha-256" in s["digest"] for s in subj)


def test_unknown_hash_alg_raises():
    with pytest.raises(HashAlgError):
        hashing.hash_bytes(b"x", "md5")


def test_keyid_stable_and_sign_verify():
    priv, pub = keys.generate()
    assert keys.keyid_for(pub) == keys.keyid_for(pub)
    sig = keys.sign(priv, b"msg")
    assert keys.verify(pub, b"msg", sig)
    assert not keys.verify(pub, b"tampered", sig)


def test_key_save_load_roundtrip_and_perms(tmp_path):
    priv, pub = keys.generate()
    kp = tmp_path / "k.key"
    kid = keys.save(priv, str(kp))
    import os
    assert oct(os.stat(kp).st_mode)[-3:] == "600"
    p2, pub2 = keys.load_signing_key(str(kp))
    assert p2 == priv and pub2 == pub and keys.keyid_for(pub2) == kid
    assert json.loads((tmp_path / "k.key.pub").read_text())["keyid"] == kid
