"""CLI behavior: fail-loud paths, argument validation, exit codes (all offline)."""

import json
import os
import runpy
import stat
import sys

import pytest

from asexec import cli, drand, identity, keys, manifest, roughtime
from asexec.errors import NetworkError

REF = "sha-256:" + "ab" * 32


def run(*argv):
    return cli.main([str(arg) for arg in argv])


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
    if os.name != "nt":  # 0600 is a Unix-only guarantee
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
    if os.name != "nt":
        assert stat.S_IMODE(os.stat(key).st_mode) == 0o600
    assert json.load(open(key + ".pub"))["keyid"] == json.load(open(key))["keyid"]


def test_keys_save_does_not_follow_into_existing_file(tmp_path):
    priv, _ = keys.generate()
    key_path = str(tmp_path / "x.key")
    keys.save(priv, key_path)
    with pytest.raises(FileExistsError):
        keys.save(priv, key_path)


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


# --- verify printer ---------------------------------------------------------- #
FLOOR = {
    "floor_type": "drand",
    "chain_hash": drand.QUICKNET_HASH,
    "round": 1000,
    "signature": (
        "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125"
        "e342b73a8dd2bacbe47e4b6b63ed5e39"
    ),
    "randomness": "fe290beca10872ef2fb164d2aa4442de4566183ec51c56ff3cd603d930e54fdd",
}


def _resign(path, key, mutate):
    mani = manifest.load(path)
    body = manifest.get_body(mani)
    mutate(body)
    priv, pub = keys.load_signing_key(key)
    manifest.save(manifest.sign(body, priv, pub), path)


def test_verify_prints_verified_floor(tmp_path, key, prereg, capsys):
    _resign(prereg, key, lambda body: body.update(anchor={"floor": FLOOR}))
    assert run("verify", prereg, "--tests", "BDR,floor") == 0
    out = capsys.readouterr().out
    assert "drand freshness floor round 1000 (created no earlier than 1692" in out
    assert "BDR=PASS floor=PASS" in out


def test_verify_prints_failed_floor_without_timestamp(tmp_path, key, prereg, capsys):
    _resign(prereg, key, lambda body: body.update(anchor={"floor": {**FLOOR, "round": 1001}}))
    assert run("verify", prereg, "--tests", "BDR,floor") == 2
    out = capsys.readouterr().out
    assert "drand freshness floor round 1001" in out
    assert "created no earlier than" not in out
    assert "floor=FAIL" in out


def test_verify_prints_ceiling_and_trust_section(
    tmp_path, key, prereg, capsys, monkeypatch, make_server, ceiling_for
):
    mani = manifest.load(prereg)
    nonce_hex = manifest.ref(manifest.get_body(mani)).split(":", 1)[-1]
    lt_pub, sign_response = make_server()
    monkeypatch.setitem(roughtime.SERVERS, "synthetic", {"pubkey": lt_pub})
    manifest.attach_ceiling(mani, ceiling_for(nonce_hex, "synthetic", lt_pub, sign_response))
    manifest.save(mani, prereg)

    assert run("verify", prereg, "--tests", "BDR,ceiling") == 0
    out = capsys.readouterr().out
    assert "ceiling witness (created no later than" in out and "witness synthetic" in out
    assert "=== ceiling trust (what you are accepting) ===" in out
    assert "trusting synthetic" in out


def test_verify_prints_invalid_ceiling_error(tmp_path, key, prereg, capsys):
    mani = manifest.load(prereg)
    manifest.attach_ceiling(mani, {"ceiling_type": "roughtime", "witness_id": "nobody"})
    manifest.save(mani, prereg)
    run("verify", prereg, "--tests", "BDR,ceiling")
    out = capsys.readouterr().out
    assert cli.NO in out and "ceiling witness (" in out
    assert "ceiling trust" not in out


def test_verify_prints_content_mismatch(tmp_path, key, capsys):
    art = tmp_path / "art"
    art.mkdir()
    (art / "a.txt").write_text("one")
    out = tmp_path / "pre.json"
    assert run("prereg", "--key", key, "--target", "t", "--subject", art / "a.txt",
               "--out", out) == 0  # fmt: skip
    (art / "a.txt").write_text("two")
    capsys.readouterr()
    code = run("verify", out, "--tests", "BDR,content", "--artifacts", art)
    text = capsys.readouterr().out
    assert code == 2
    assert "content hashes mismatch" in text
    assert "a.txt: digest mismatch" in text


def test_verify_prints_content_ok(tmp_path, key, capsys):
    art = tmp_path / "art"
    art.mkdir()
    (art / "a.txt").write_text("one")
    out = tmp_path / "pre.json"
    run("prereg", "--key", key, "--target", "t", "--subject", art / "a.txt", "--out", out)
    capsys.readouterr()
    assert run("verify", out, "--tests", "BDR,content", "--artifacts", art) == 0
    assert "content hashes ok" in capsys.readouterr().out


def test_verify_prints_notarization_only(tmp_path, key, prereg, capsys):
    post = tmp_path / "po.json"
    assert run("postreg", "--key", key, "--target", "t", "--fulfills", REF, "--out", post) == 0
    capsys.readouterr()
    run("verify", post, "--tests", "BDR")
    out = capsys.readouterr().out
    assert "=== notarization-only" in out
    assert f"(fulfills {REF})" in out
    assert "(no pre-registrations among the provided manifests)" in out


# --- identity ---------------------------------------------------------------- #
def test_identity_emit_writes_wellknown(tmp_path, key, capsys):
    out = tmp_path / "asexec.json"
    assert run("identity", "emit", "--key", key, "--domain", "lab.example", "--out", out) == 0
    doc = json.load(open(out))
    assert doc["domain"] == "lab.example"
    assert doc["keys"][0]["keyid"] == json.load(open(key))["keyid"]
    text = capsys.readouterr().out
    assert "publish at: https://<your-domain>/.well-known/asexec.json" in text


@pytest.mark.parametrize("bound,code", [(True, 0), (False, 2)])
def test_identity_match_exit_codes(tmp_path, key, capsys, monkeypatch, bound, code):
    seen = {}

    def fake(domain, keyid=None, pubkey_hex=None, timeout=10):
        seen.update(domain=domain, keyid=keyid, pubkey=pubkey_hex)
        return {"bound": bound, "listed_count": 1, "caveat": "point-in-time: x"}

    monkeypatch.setattr(identity, "match_binding", fake)
    assert run("identity", "match", "--domain", "lab.example", "--key", key) == code
    assert seen["keyid"] == json.load(open(key))["keyid"]  # derived from --key
    out = capsys.readouterr().out
    assert ("IS asserted" if bound else "is NOT asserted") in out
    assert "caveat: point-in-time" in out


def test_identity_match_passes_explicit_keyid_and_pubkey(monkeypatch):
    seen = {}
    monkeypatch.setattr(
        identity,
        "match_binding",
        lambda domain, keyid=None, pubkey_hex=None, timeout=10: (
            seen.update(keyid=keyid, pubkey=pubkey_hex)
            or {"bound": True, "listed_count": 0, "caveat": ""}
        ),
    )
    assert run("identity", "match", "--domain", "d", "--keyid", "kid", "--pubkey", "ab") == 0
    assert seen == {"keyid": "kid", "pubkey": "ab"}


def test_identity_without_subcommand_is_usage_error():
    with pytest.raises(SystemExit):
        run("identity")


# --- entry points ------------------------------------------------------------ #
def test_python_dash_m_entry_point_exits_with_main_code(monkeypatch, prereg):
    monkeypatch.setattr(sys, "argv", ["asexec", "verify", prereg, "--tests", "BDR"])
    with pytest.raises(SystemExit) as e:
        runpy.run_module("asexec", run_name="__main__")
    assert e.value.code == 0


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as e:
        run("--version")
    assert e.value.code == 0
    assert capsys.readouterr().out.startswith("asexec ")
