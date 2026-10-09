"""CLI behavior: fail-loud paths, argument validation, exit codes (all offline)."""

import json
import os
import stat

import pytest

from asexec import cli, drand, keys, manifest, roughtime
from asexec.errors import NetworkError

REF = "sha-256:" + "ab" * 32


def run(*argv):
    return cli.main([str(a) for a in argv])


@pytest.fixture
def key(tmp_path):
    path = tmp_path / "lab.key"
    assert run("keygen", "--out", path) == 0
    return str(path)


@pytest.fixture
def prereg(tmp_path, key):
    out = tmp_path / "pre.json"
    assert run("prereg", "--key", key, "--target", "t", "--out", out) == 0
    return str(out)


# --- keygen (finding 10) --------------------------------------------------- #
def test_keygen_creates_0600_key_and_pub(tmp_path):
    out = tmp_path / "k.key"
    assert run("keygen", "--out", out) == 0
    assert stat.S_IMODE(os.stat(out).st_mode) == 0o600
    assert (tmp_path / "k.key.pub").exists()


def test_keygen_refuses_to_overwrite_existing_key(tmp_path, key):
    before = open(key).read()
    with pytest.raises(SystemExit) as e:
        run("keygen", "--out", key)
    assert "--force" in str(e.value)
    assert open(key).read() == before  # untouched


def test_keygen_refuses_when_only_pub_exists(tmp_path):
    out = tmp_path / "k.key"
    (tmp_path / "k.key.pub").write_text("precious")
    with pytest.raises(SystemExit):
        run("keygen", "--out", out)
    assert not out.exists()  # no partial write
    assert (tmp_path / "k.key.pub").read_text() == "precious"


def test_keygen_force_overwrites(tmp_path, key):
    old = json.load(open(key))["keyid"]
    assert run("keygen", "--out", key, "--force") == 0
    assert json.load(open(key))["keyid"] != old
    assert stat.S_IMODE(os.stat(key).st_mode) == 0o600
    assert json.load(open(key + ".pub"))["keyid"] == json.load(open(key))["keyid"]


def test_keys_save_does_not_follow_into_existing_file(tmp_path):
    priv, _ = keys.generate()
    p = str(tmp_path / "x.key")
    keys.save(priv, p)
    with pytest.raises(FileExistsError):
        keys.save(priv, p)


# --- --due (finding 8) ----------------------------------------------------- #
@pytest.mark.parametrize("due", ["2026-08-30T00:00:00", "2026-08-30", "2026-08-30 12:00"])
def test_prereg_rejects_timezone_less_due(tmp_path, key, due):
    out = tmp_path / "p.json"
    with pytest.raises(SystemExit) as e:
        run("prereg", "--key", key, "--target", "t", "--due", due, "--out", out)
    assert "offset" in str(e.value) or "timezone" in str(e.value)
    assert not out.exists()


def test_prereg_rejects_garbage_due(tmp_path, key):
    with pytest.raises(SystemExit):
        run("prereg", "--key", key, "--target", "t", "--due", "soon", "--out", tmp_path / "p")


@pytest.mark.parametrize("due", ["2026-08-30T00:00:00Z", "2026-08-30T00:00:00+02:00"])
def test_prereg_accepts_explicit_offset_due(tmp_path, key, due):
    out = tmp_path / "p.json"
    assert run("prereg", "--key", key, "--target", "t", "--due", due, "--out", out) == 0
    assert manifest.get_body(manifest.load(str(out)))["due"] == due  # stored verbatim


def test_postreg_rejects_timezone_less_due_override(tmp_path, key, prereg):
    with pytest.raises(SystemExit):
        run(
            "postreg", "--key", key, "--fulfills", prereg, "--due", "2030-01-01T00:00:00",
            "--out", tmp_path / "po.json",
        )  # fmt: skip


# --- --floor / --ceiling (finding 11) -------------------------------------- #
def _boom(*_a, **_k):
    raise NetworkError("offline")


def test_floor_fetch_failure_fails_and_writes_nothing(tmp_path, key, monkeypatch):
    monkeypatch.setattr(drand, "fetch_floor", _boom)
    out = tmp_path / "p.json"
    with pytest.raises(SystemExit) as e:
        run("prereg", "--key", key, "--target", "t", "--floor", "--out", out)
    assert "--best-effort" in str(e.value)
    assert not out.exists()


def test_ceiling_fetch_failure_fails_and_writes_nothing(tmp_path, key, monkeypatch):
    monkeypatch.setattr(roughtime, "fetch_ceiling", _boom)
    out = tmp_path / "p.json"
    with pytest.raises(SystemExit) as e:
        run("prereg", "--key", key, "--target", "t", "--ceiling", "--out", out)
    assert "--best-effort" in str(e.value)
    assert not out.exists()


def test_best_effort_floor_warns_and_signs(tmp_path, key, monkeypatch, capsys):
    monkeypatch.setattr(drand, "fetch_floor", _boom)
    out = tmp_path / "p.json"
    code = run("prereg", "--key", key, "--target", "t", "--floor", "--best-effort", "--out", out)
    assert code == 0
    assert "warning" in capsys.readouterr().err
    assert "anchor" not in manifest.get_body(manifest.load(str(out)))


def test_best_effort_ceiling_warns_and_signs(tmp_path, key, monkeypatch, capsys):
    monkeypatch.setattr(roughtime, "fetch_ceiling", _boom)
    out = tmp_path / "p.json"
    code = run("prereg", "--key", key, "--target", "t", "--ceiling", "--best-effort", "--out", out)
    assert code == 0
    assert "warning" in capsys.readouterr().err
    assert "ceiling" not in manifest.load(str(out))


def test_postreg_floor_failure_fails_by_default(tmp_path, key, prereg, monkeypatch):
    monkeypatch.setattr(drand, "fetch_floor", _boom)
    with pytest.raises(SystemExit):
        run("postreg", "--key", key, "--fulfills", prereg, "--floor", "--out", tmp_path / "o")


# --- --fulfills / --prev (finding 12) -------------------------------------- #
def test_fulfills_typo_is_an_error(tmp_path, key):
    out = tmp_path / "po.json"
    with pytest.raises(SystemExit) as e:
        run("postreg", "--key", key, "--target", "t", "--fulfills", "preg.json", "--out", out)
    assert "preg.json" in str(e.value)
    assert not out.exists()


@pytest.mark.parametrize("bad", ["sha-256:abc", "sha-256:" + "AB" * 32, "sha256:" + "ab" * 32])
def test_fulfills_malformed_ref_is_an_error(tmp_path, key, bad):
    with pytest.raises(SystemExit):
        run("postreg", "--key", key, "--target", "t", "--fulfills", bad, "--out", tmp_path / "o")


def test_fulfills_well_formed_literal_ref_accepted(tmp_path, key):
    out = tmp_path / "po.json"
    assert run("postreg", "--key", key, "--target", "t", "--fulfills", REF, "--out", out) == 0
    assert manifest.get_body(manifest.load(str(out)))["fulfills"] == REF


def test_fulfills_existing_file_resolves_to_its_ref(tmp_path, key, prereg):
    out = tmp_path / "po.json"
    assert run("postreg", "--key", key, "--fulfills", prereg, "--out", out) == 0
    expected = manifest.ref(manifest.get_body(manifest.load(prereg)))
    assert manifest.get_body(manifest.load(str(out)))["fulfills"] == expected


def test_prev_typo_is_an_error(tmp_path, key, prereg):
    with pytest.raises(SystemExit):
        run("postreg", "--key", key, "--fulfills", prereg, "--prev", "nope.json",
            "--out", tmp_path / "o")  # fmt: skip


def test_fulfills_non_manifest_file_is_a_clean_error(tmp_path, key):
    junk = tmp_path / "junk.json"
    junk.write_text("{nope")
    with pytest.raises(SystemExit):
        run("postreg", "--key", key, "--target", "t", "--fulfills", junk, "--out", tmp_path / "o")


# --- verify exit codes ----------------------------------------------------- #
def test_verify_exit_codes_and_malformed_file(tmp_path, key, prereg, capsys):
    assert run("verify", prereg, "--tests", "BDR") == 0
    assert "asexec-verify/1 BDR=PASS" in capsys.readouterr().out
    bad = tmp_path / "bad.json"
    bad.write_text("{nope")
    assert run("verify", prereg, bad, "--tests", "BDR") == 2
    out = capsys.readouterr().out
    assert "asexec-verify/1 BDR=FAIL" in out and "malformed" in out


def test_verify_renders_rejected_receipt_and_invalid_due(tmp_path, key, capsys):
    out = tmp_path / "pre.json"
    run("prereg", "--key", key, "--target", "t", "--out", out)
    body = manifest.get_body(manifest.load(str(out)))
    body["due"] = "someday"
    priv, pub = keys.load_signing_key(key)
    manifest.save(manifest.sign(body, priv, pub), str(out))
    run("verify", out, "--tests", "BDR")
    assert "INVALID-DUE" in capsys.readouterr().out


def test_verify_requires_BDR(prereg):
    with pytest.raises(SystemExit):
        run("verify", prereg, "--tests", "chain")
