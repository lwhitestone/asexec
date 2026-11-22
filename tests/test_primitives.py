"""Canonical/PAE, hashing, and keys."""

import hashlib
import json
import os

import pytest

from asexec import hashing, keys
from asexec.canonical import (
    build_signing_input,
    decode_base64,
    encode_base64,
    encode_pae,
    serialize_canonical,
)
from asexec.errors import HashAlgError, ManifestError


def test_canonical_is_key_order_independent():
    left = {"b": 1, "a": 2, "c": [3, {"y": 1, "x": 2}]}
    right = {"c": [3, {"x": 2, "y": 1}], "a": 2, "b": 1}
    assert serialize_canonical(left) == serialize_canonical(right)


def test_canonical_compact_utf8():
    assert serialize_canonical({"k": "café"}) == b'{"k":"caf\xc3\xa9"}'


def test_pae_is_unambiguous():
    # length-prefixing prevents "abc"+"" from colliding with "ab"+"c"
    assert encode_pae(b"v", b"t", b"abc") != encode_pae(b"v", b"t", b"ab") + b"c"
    assert encode_pae(b"DSSEv1", b"t", b"{}") == b"DSSEv1 1 t 2 {}"


def test_signing_input_changes_with_the_body_bytes():
    assert build_signing_input(b'{"a":1}') != build_signing_input(b'{"a":2}')
    assert build_signing_input(b'{"a":1}') != build_signing_input(
        b'{"a": 1}'
    )  # the bytes, not the JSON


@pytest.mark.parametrize("data", [b"", b"A", b"AB", b"ABC", bytes(range(256))])
def test_strict_base64_round_trips(data):
    assert decode_base64(encode_base64(data)) == data


@pytest.mark.parametrize(
    "text",
    ["QQ", "QQ=", "QQ===", "QR==", "QQ==\n", "Q Q==", "-_8=", "_w==", "QQ==QQ==", "é", "Q\x00=="],
)
def test_strict_base64_has_one_spelling_per_byte_string(text):
    with pytest.raises(ValueError):
        decode_base64(text)


def test_hash_file(tmp_path):
    path = tmp_path / "f.txt"
    path.write_bytes(b"hello")
    assert hashing.hash_file(str(path), "sha-256") == hashlib.sha256(b"hello").hexdigest()


def _write_files(root, *names):
    for name in names:
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(name)


def _hash_text(text):
    return hashlib.sha256(text.encode()).hexdigest()


def test_directory_hashing_is_gone():
    # Subjects are files only: nothing hashes a directory any more.
    assert not hasattr(hashing, "hash_dir")
    assert not hasattr(hashing, "digest_path")


def test_build_subject_names_each_file_by_its_normalized_relative_path(tmp_path, monkeypatch):
    # The name is the path as given, relative to the current directory, normalized and
    # "/"-separated: two files with the same basename stay distinct.
    monkeypatch.chdir(tmp_path)
    _write_files(tmp_path, "a/run.py", "b/run.py", "c.txt")
    subject = hashing.build_subject(["a/run.py", "./b//run.py", "c.txt"], "sha-256")
    assert subject == [
        {"name": "a/run.py", "hash_alg": "sha-256", "digest": {"sha-256": _hash_text("a/run.py")}},
        {"name": "b/run.py", "hash_alg": "sha-256", "digest": {"sha-256": _hash_text("b/run.py")}},
        {"name": "c.txt", "hash_alg": "sha-256", "digest": {"sha-256": _hash_text("c.txt")}},
    ]


def test_build_subject_hashes_a_symlink_through_to_its_target(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    _write_files(tmp_path, "real.txt")
    try:
        (tmp_path / "link.txt").symlink_to(tmp_path / "real.txt")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this platform")
    (entry,) = hashing.build_subject(["link.txt"], "sha-256")
    assert entry == {
        "name": "link.txt",
        "hash_alg": "sha-256",
        "digest": {"sha-256": _hash_text("real.txt")},
    }


@pytest.mark.parametrize(
    "paths,message",
    [
        (["d"], "is a directory"),
        (["d/"], "is a directory"),
        (["."], "is a directory"),
        (["{abs}"], "absolute"),
        (["../x.txt"], "'..'"),
        (["d/../c.txt"], "'..'"),
        (["c.txt", "./c.txt"], "twice"),
        (["c.txt", "c.txt"], "twice"),
    ],
    ids=[
        "dir",
        "dir-slash",
        "dot",
        "absolute",
        "dotdot",
        "dotdot-inside",
        "same-name",
        "same-path",
    ],
)
def test_build_subject_refuses_what_content_would_fail(tmp_path, monkeypatch, paths, message):
    monkeypatch.chdir(tmp_path)
    _write_files(tmp_path, "c.txt", "d/x.txt")
    paths = [p.format(abs=tmp_path / "c.txt") for p in paths]
    with pytest.raises(ManifestError, match=message):
        hashing.build_subject(paths, "sha-256")


@pytest.mark.skipif(os.sep != "/", reason="a backslash is a separator on Windows")
def test_build_subject_refuses_a_backslash_in_a_name(tmp_path, monkeypatch):
    # A legal filename character here, a separator on Windows: one name, two files.
    monkeypatch.chdir(tmp_path)
    _write_files(tmp_path, "a\\b.txt")
    with pytest.raises(ManifestError, match="backslash"):
        hashing.build_subject(["a\\b.txt"], "sha-256")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="os.mkfifo is POSIX-only")
def test_build_subject_refuses_what_is_not_a_regular_file(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    os.mkfifo(tmp_path / "pipe")
    with pytest.raises(ManifestError, match="not a regular file"):
        hashing.build_subject(["pipe"], "sha-256")


def test_build_subject_of_a_missing_file_raises_os_error(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(FileNotFoundError):
        hashing.build_subject(["absent.txt"], "sha-256")


def test_unknown_hash_alg_raises(tmp_path):
    path = tmp_path / "f.txt"
    path.write_bytes(b"x")
    with pytest.raises(HashAlgError):
        hashing.hash_file(str(path), "md5")


def test_keyid_stable_and_sign_verify():
    priv, pub = keys.generate()
    assert keys.derive_keyid(pub) == keys.derive_keyid(pub)
    sig = keys.sign(priv, b"msg")
    assert keys.verify(pub, b"msg", sig)
    assert not keys.verify(pub, b"tampered", sig)


def test_key_save_load_roundtrip_and_perms(tmp_path):
    priv, pub = keys.generate()
    kp = tmp_path / "k.key"

    kid = keys.save(priv, str(kp))

    # Skip 0600 enforcement on Windows (it's a Unix-only guarantee)
    import os

    if os.name != "nt":
        assert os.stat(kp).st_mode & 0o777 == 0o600

    p2, pub2 = keys.load_signing_key(str(kp))
    assert p2 == priv
    assert pub2 == pub
    assert keys.derive_keyid(pub2) == kid
    assert json.loads((tmp_path / "k.key.pub").read_text())["keyid"] == kid
