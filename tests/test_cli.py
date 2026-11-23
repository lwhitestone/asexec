"""CLI behavior: fail-loud paths, argument validation, exit codes (all offline).

End-to-end tests: each drives ``cli.main``, and the ``verify`` tests build their input with
``asexec prereg``/``postreg`` and the production writer on purpose, to check the whole round
trip. Verify's contract is tested on raw data in ``tests/verify/``.
"""

import base64
import hashlib
import io
import json
import os
import re
import runpy
import stat
import subprocess
import sys
import threading
import time

import manifest_data as d
import pytest

import asexec
from asexec import cli, drand, identity, keys, manifest, roughtime
from asexec.canonical import build_signing_input, serialize_canonical
from asexec.constants import MANIFEST_PAYLOAD_TYPE
from asexec.errors import NetworkError

pytestmark = pytest.mark.end_to_end

REF = "sha-256:" + "ab" * 32


def run(*argv):
    return cli.main([str(arg) for arg in argv])


def _read_body(path):
    """The decoded body of the manifest file at ``path``."""
    return manifest.read_body(manifest.load(str(path)))[1]


def _read_ref(path):
    """The ref of the manifest file at ``path``: the digest of its stored body bytes."""
    return manifest.derive_ref(manifest.read_body(manifest.load(str(path)))[0])


def _edit_body_after_signing(path, edit):
    """Edit the body of the file at ``path`` and store it again, keeping the old signature."""
    mani = manifest.load(str(path))
    body = manifest.read_body(mani)[1]
    edit(body)
    mani["dsse"]["payload"] = base64.b64encode(serialize_canonical(body)).decode()
    manifest.save(mani, str(path))


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
def test_prereg_rejects_timezone_less_due(tmp_path, key, due, capsys):
    out = tmp_path / "p.json"
    with pytest.raises(SystemExit) as e:
        run("prereg", "--key", key, "--target", "t", "--due", due, "--out", out)
    assert e.value.code == cli.EXIT_USAGE
    assert "offset" in capsys.readouterr().err
    assert not out.exists()


def test_prereg_rejects_garbage_due(tmp_path, key):
    with pytest.raises(SystemExit) as e:
        run("prereg", "--key", key, "--target", "t", "--due", "soon", "--out", tmp_path / "p")
    assert e.value.code == cli.EXIT_USAGE


@pytest.mark.parametrize("due", ["2026-08-30T00:00:00Z", "2026-08-30T00:00:00+02:00"])
def test_prereg_accepts_explicit_offset_due(tmp_path, key, due):
    out = tmp_path / "p.json"
    assert run("prereg", "--key", key, "--target", "t", "--due", due, "--out", out) == 0
    assert _read_body(out)["due"] == due  # stored verbatim


def test_postreg_rejects_timezone_less_due_override(tmp_path, key, prereg):
    with pytest.raises(SystemExit) as e:
        run(
            "postreg", "--key", key, "--fulfills", prereg, "--due", "2030-01-01T00:00:00",
            "--out", tmp_path / "po.json",
        )  # fmt: skip
    assert e.value.code == cli.EXIT_USAGE


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
    assert "anchor" not in _read_body(out)


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
    assert _read_body(out)["fulfills"] == REF


def test_fulfills_existing_file_resolves_to_its_ref(tmp_path, key, prereg):
    out = tmp_path / "po.json"
    assert run("postreg", "--key", key, "--fulfills", prereg, "--out", out) == 0
    assert _read_body(out)["fulfills"] == _read_ref(prereg)


def test_prev_typo_is_an_error(tmp_path, key, prereg):
    with pytest.raises(SystemExit):
        run("postreg", "--key", key, "--fulfills", prereg, "--prev", "nope.json",
            "--out", tmp_path / "o")  # fmt: skip


def test_fulfills_non_manifest_file_is_a_clean_error(tmp_path, key):
    junk = tmp_path / "junk.json"
    junk.write_text("{nope")
    with pytest.raises(SystemExit):
        run("postreg", "--key", key, "--target", "t", "--fulfills", junk, "--out", tmp_path / "o")


def _sign_stored_bytes(path, key, raw):
    """Write ``path`` as a file around the body bytes ``raw``, validly signed by ``key``:
    what another writer could store, spaced or ordered as it likes."""
    priv, pub = keys.load_signing_key(key)
    mani = {
        "dsse": {
            "payloadType": MANIFEST_PAYLOAD_TYPE,
            "payload": base64.b64encode(raw).decode(),
            "signatures": [
                {
                    "keyid": keys.derive_keyid(pub),
                    "sig": base64.b64encode(keys.sign(priv, build_signing_input(raw))).decode(),
                }
            ],
        },
        "pubkey": pub.hex(),
    }
    manifest.save(mani, str(path))


def test_postreg_inherits_target_due_and_declaration_from_the_prereg_body(tmp_path, key):
    pre, post = tmp_path / "pre.json", tmp_path / "post.json"
    assert run("prereg", "--key", key, "--target", "t", "--due", "2099-01-01T00:00:00Z",
               "--declaration", "all of it", "--out", pre) == 0  # fmt: skip
    assert run("postreg", "--key", key, "--fulfills", pre, "--out", post) == 0
    body = _read_body(post)
    assert (body["target"], body["due"], body["declaration"]) == (
        "t",
        "2099-01-01T00:00:00Z",
        "all of it",
    )
    assert body["fulfills"] == _read_ref(pre)


def test_fulfills_is_the_digest_of_the_prereg_bytes_as_stored(tmp_path, key, capsys):
    """--fulfills names the prereg by the digest of its stored body bytes, which another
    writer may have spaced and ordered otherwise: nothing re-serializes them."""
    pre, post = tmp_path / "pre.json", tmp_path / "post.json"
    raw = b'{ "target": {"model": "m"},  "phase": "prereg",\n "due": "2099-01-01T00:00:00Z" }'
    _sign_stored_bytes(pre, key, raw)
    assert run("postreg", "--key", key, "--fulfills", pre, "--out", post) == 0
    body = _read_body(post)
    assert body["fulfills"] == "sha-256:" + hashlib.sha256(raw).hexdigest()
    assert (body["target"], body["due"]) == ({"model": "m"}, "2099-01-01T00:00:00Z")
    capsys.readouterr()
    assert run("verify", pre, post, "--tests", "format,selfsig,keyconsist") == 0
    assert "  [FULFILLED] prereg " in capsys.readouterr().out


@pytest.mark.parametrize(
    "edit",
    [
        lambda mani: mani["dsse"].update(payload=mani["dsse"]["payload"] + "="),
        lambda mani: mani["dsse"].update(payload=base64.b64encode(b"[1]").decode()),
        lambda mani: mani.pop("dsse"),
    ],
    ids=["not-base64", "body-not-object", "no-dsse"],
)
def test_fulfills_file_with_no_readable_body_is_a_clean_error(tmp_path, key, prereg, edit):
    mani = json.loads(open(prereg).read())
    edit(mani)
    open(prereg, "w").write(json.dumps(mani))
    with pytest.raises(SystemExit) as e:
        run("postreg", "--key", key, "--fulfills", prereg, "--out", tmp_path / "o")
    assert "is not a readable manifest" in str(e.value)
    assert not (tmp_path / "o").exists()


def test_postreg_inheriting_a_string_with_no_utf8_form_is_a_clean_error(tmp_path, key, capsys):
    """A prereg body may hold a lone surrogate escape (valid JSON, validly signed). A postreg
    inheriting it can't be stored as UTF-8, so the writer refuses it: an error, exit 1."""
    pre = tmp_path / "pre.json"
    _sign_stored_bytes(pre, key, b'{"phase":"prereg","target":"t","declaration":"\\ud800"}')
    assert run("postreg", "--key", key, "--fulfills", pre, "--out", tmp_path / "o") == 1
    assert "no UTF-8 form" in capsys.readouterr().err
    assert not (tmp_path / "o").exists()


# Every character str.splitlines breaks a line at, then others a terminal acts on.
_BREAKERS = ["\n", "\r", "\r\n", "\v", "\f", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"]
_CONTROLS = [
    *_BREAKERS,
    "\x00",
    "\t",
    "\x08",
    "\x1b[2K",
    "\x7f",
    "\x9b",
    "\u202e",
    "\u2066",
    "\u200f",
]
_FAKE_CODE = "asexec-verify/1 format=PASS order=PASS selfsig=PASS"


def _assert_nothing_forged(text, control):
    assert not [ln for ln in text.splitlines() if ln.startswith(_FAKE_CODE)]
    if control not in ("\n", "\r\n"):  # "\n" is what ends each of the report's own lines
        assert control not in text
    assert control.encode("unicode_escape").decode() + _FAKE_CODE in text


@pytest.mark.parametrize(
    "where,control",
    [
        (where, control)
        for where in ("keyid", "phase", "due", "item-id", "fulfills", "entry-name", "filename")
        for control in _CONTROLS
        if (where, control) != ("filename", "\x00")  # no file name holds a NUL
    ],
    ids=ascii,
)
def test_verify_escapes_control_characters_in_what_a_manifest_says(
    tmp_path, key, capsys, where, control
):
    """No string of a manifest, or a file name, can start a line of the report or act on the
    terminal: the code is the one line that starts asexec-verify/."""
    evil = f"x{control}{_FAKE_CODE}"
    path = tmp_path / "m.json"
    body = manifest.build_prereg("t")
    if where == "phase":
        body["phase"] = evil
    elif where == "due":
        body["due"] = evil
    elif where == "item-id":
        body["items"] = [{"id": evil}]
    elif where == "fulfills":
        body.update(phase="postreg", fulfills=evil)
    elif where == "entry-name":
        body["subject"] = [{"name": evil, "hash_alg": "sha-256", "digest": {"sha-256": "00"}}]
    signed = manifest.sign(body, *keys.load_signing_key(key))
    if where == "keyid":
        signed["dsse"]["signatures"][0]["keyid"] = evil
    if where == "filename":
        # the fake code holds a slash, so it can only be a directory and a file in it
        path = tmp_path / f"x{control}asexec-verify" / "1 format=PASS order=PASS selfsig=PASS"
        path.parent.mkdir()
    manifest.save(signed, str(path))
    (tmp_path / "art").mkdir()
    capsys.readouterr()
    run("verify", path, "--tests", "format,selfsig,content", "--artifacts", tmp_path / "art")
    out = capsys.readouterr().out
    _assert_nothing_forged(out, control)
    (code,) = [ln for ln in out.splitlines() if ln.startswith("asexec-verify/")]
    assert code.startswith("asexec-verify/1 content=")


@pytest.mark.parametrize("control", ["\n", "\r", "\u2028"], ids=ascii)
def test_verify_escapes_a_rejected_preregs_claimed_keyid(tmp_path, key, capsys, control):
    path = tmp_path / "m.json"
    signed = manifest.sign(manifest.build_prereg("t"), *keys.load_signing_key(key))
    signed["dsse"]["signatures"][0]["keyid"] = f"x{control}{_FAKE_CODE}"
    manifest.save(signed, str(path))
    capsys.readouterr()
    assert run("verify", path, "--tests", "format,selfsig") == 2
    out = capsys.readouterr().out
    (shown,) = [ln for ln in out.split("\n") if ln.startswith("    keyid        : ")]
    assert control not in shown and _FAKE_CODE in shown


@pytest.mark.parametrize("separator", ["\n", "\r", "\x1b", "\u2028"], ids=ascii)
def test_prereg_refuses_a_due_that_would_print_more_than_a_line(tmp_path, key, capsys, separator):
    """The grammar's separators are T and a space, so prereg's own due line holds nothing else."""
    due = f"2030-01-01{separator}00:00:00+00:00"
    capsys.readouterr()
    with pytest.raises(SystemExit) as e:
        run("prereg", "--key", key, "--target", "t", "--due", due, "--out", tmp_path / "o")
    assert e.value.code == cli.EXIT_USAGE
    assert separator not in capsys.readouterr().err.strip().splitlines()[-1]


_NOT_UTF8 = "x\udcff"  # a byte that is not UTF-8, as argv decodes it
_LONE = "x\\ud800"  # a lone surrogate, spelled as JSON spells it


@pytest.mark.parametrize(
    "cmd,flag,value",
    [
        ("prereg", "--target", _NOT_UTF8),
        ("prereg", "--declaration", _NOT_UTF8),
        ("prereg", "--notes", _NOT_UTF8),
        ("postreg", "--target", _NOT_UTF8),
        ("postreg", "--declaration", _NOT_UTF8),
        ("postreg", "--notes", _NOT_UTF8),
        ("postreg", "--item-id", _NOT_UTF8),
        ("prereg", "--plan", '{"name":"p","label":"' + _NOT_UTF8 + '"}'),
        ("prereg", "--plan", '{"name":"p","label":"' + _LONE + '"}'),
        ("prereg", "--items", '[{"id":"' + _LONE + '"}]'),
        ("postreg", "--evidence", '[{"name":"e","uri":"' + _LONE + '"}]'),
        ("postreg", "--repro-recipe", '{"seed":"' + _LONE + '"}'),
        ("postreg", "--repro-recipe", '{"' + _LONE + '":1}'),
    ],
)
def test_a_value_with_no_utf8_form_is_a_usage_error(tmp_path, capsys, cmd, flag, value):
    """No body can hold it, so the argument is wrong whatever the files hold: 64, before the
    key is read. Not exit 1, and a key is not silently respelled."""
    out = tmp_path / "out.json"
    link = [] if flag == "--target" else ["--target", "t"]
    if cmd == "postreg":
        link += ["--fulfills", REF]
    with pytest.raises(SystemExit) as e:
        run(cmd, "--key", tmp_path / "no-such-key", *link, flag, value, "--out", out)
    assert e.value.code == cli.EXIT_USAGE
    err = capsys.readouterr().err
    assert f"error: argument {flag}: " in err and "no UTF-8 form" in err
    assert not out.exists()


@pytest.mark.parametrize("flag", ["--keyid", "--pubkey"])
def test_identity_match_refuses_a_value_with_no_utf8_form(monkeypatch, capsys, flag):
    monkeypatch.setattr(cli.identity, "fetch_wellknown", lambda *a, **k: pytest.fail("fetched"))
    with pytest.raises(SystemExit) as e:
        run("identity", "match", "--domain", "lab.example", flag, _NOT_UTF8)
    assert e.value.code == cli.EXIT_USAGE
    assert "no UTF-8 form" in capsys.readouterr().err


def test_verify_shows_lone_surrogates_escaped(tmp_path, key, capsys):
    """Verify reads a body holding lone surrogate escapes as signed, and the report shows
    each one escaped, as \\udXXX, rather than failing to print it."""
    pre, post = tmp_path / "pre.json", tmp_path / "post.json"
    _sign_stored_bytes(pre, key, b'{"phase":"prereg","target":"t","due":"\\ud800"}')
    _sign_stored_bytes(
        post,
        key,
        b'{"phase":"postreg","target":"t","fulfills":"\\udfff",'
        b'"subject":[{"name":"\\ud801","hash_alg":"sha-256","digest":{"sha-256":"00"}}]}',
    )
    (tmp_path / "art").mkdir()
    capsys.readouterr()
    assert run("verify", pre, post, "--tests", "format,selfsig,content",
               "--artifacts", tmp_path / "art") == 2  # fmt: skip
    out = capsys.readouterr().out
    assert "    due          : \\ud800\n" in out
    assert "(fulfills \\udfff)" in out
    assert f"        {cli.NO} \\ud801: artifact not found" in out
    assert "asexec-verify/1 content=FAIL format=PASS selfsig=PASS" in out


# --- verify exit codes ----------------------------------------------------- #
def test_verify_exit_codes_and_malformed_file(tmp_path, key, prereg, capsys):
    assert run("verify", prereg, "--tests", "format,selfsig") == 0
    assert "asexec-verify/1 format=PASS selfsig=PASS" in capsys.readouterr().out
    bad = tmp_path / "bad.json"
    bad.write_text("{nope")
    assert run("verify", prereg, bad, "--tests", "format,selfsig") == 2
    out = capsys.readouterr().out
    assert "asexec-verify/1 format=FAIL selfsig=PASS" in out
    assert f"    {cli.NO} format: malformed: " in out  # the reason, under the file it is about


def test_verify_marks_each_file_by_format_and_selfsig(tmp_path, key, prereg, capsys):
    """The manifests block: ✓ only for a file that passes format and selfsig, and a
    malformed file's reason, attributed to format, only under that file."""
    tampered = tmp_path / "tampered.json"
    assert run("postreg", "--key", key, "--fulfills", prereg, "--out", tampered) == 0
    # changed after signing: selfsig fails
    _edit_body_after_signing(tampered, lambda body: body.update(target="something else"))
    other_keyid = tmp_path / "other-keyid.json"  # valid signature, another key's keyid
    mani = json.loads(open(prereg).read())
    mani["dsse"]["signatures"][0]["keyid"] = keys.derive_keyid(keys.generate()[1])
    other_keyid.write_text(json.dumps(mani))
    truncated = tmp_path / "truncated.json"
    truncated.write_text(open(prereg).read()[:120])
    capsys.readouterr()
    files = [prereg, tampered, other_keyid, truncated]
    assert run("verify", *files, "--tests", "format,selfsig") == 2
    out = capsys.readouterr().out
    lines = out.split("=== manifests ===\n")[1].split("\n\n")[0].splitlines()
    marks = [line for line in lines if not line.startswith(" ") and line]
    assert [line[0] for line in marks] == [cli.OK, cli.NO, cli.NO, cli.NO]
    assert [line.split()[1] for line in marks] == [str(f) for f in files]
    reasons = [i for i, line in enumerate(lines) if line.startswith(f"    {cli.NO} format: ")]
    (reason,) = reasons
    assert lines[reason].startswith(f"    {cli.NO} format: malformed: ")
    assert lines[reason - 1] == marks[3]  # under the truncated file, and only there
    assert "asexec-verify/1 format=FAIL selfsig=FAIL" in out


@pytest.mark.parametrize(
    "payload_type,reason",
    [
        (
            "application/vnd.asexec.v2+json",
            "payloadType names a format newer than this release: upgrade asexec to read it",
        ),
        (
            "application/vnd.asexec.0.3.0b1+json",  # a beta no release will read
            "payloadType names an asexec beta format, and betas are not supported",
        ),
    ],
    ids=["newer", "beta"],
)
def test_verify_version_skew_reads_as_format_not_signature(
    tmp_path, key, prereg, capsys, payload_type, reason
):
    """A postreg of a format this release does not read, beside a good prereg: its reason
    is shown under it, attributed to format, and selfsig still passes for the prereg. The
    postreg joins no commitment, so the prereg has no counted postreg (no-due, as it has no
    due)."""
    post = tmp_path / "post.json"
    assert run("postreg", "--key", key, "--fulfills", prereg, "--out", post) == 0
    mani = json.loads(post.read_text())
    mani["dsse"]["payloadType"] = payload_type
    post.write_text(json.dumps(mani))
    capsys.readouterr()
    assert run("verify", prereg, post, "--tests", "format,selfsig") == 2
    out = capsys.readouterr().out
    lines = out.split("=== commitments ===")[0].splitlines()
    i = lines.index(f"{cli.NO} {post}  [None]  keyid=None")  # a body it can't read: no phase
    assert lines[i + 1] == f"    {cli.NO} format: {reason}"
    assert lines[1].startswith(f"{cli.OK} {prereg}  [prereg]")
    assert "  [NO-DUE] prereg " in out
    assert "  ✗ format=FAIL  (1/2 manifest(s) failed)" in out
    assert "  ✓ selfsig=PASS  (1/1 manifest(s) ok)" in out
    assert "asexec-verify/1 format=FAIL selfsig=PASS" in out


def test_verify_renders_rejected_postreg_and_invalid_due(tmp_path, key, capsys):
    out = tmp_path / "pre.json"
    run("prereg", "--key", key, "--target", "t", "--out", out)
    body = _read_body(out)
    body["due"] = "someday"
    priv, pub = keys.load_signing_key(key)
    manifest.save(manifest.sign(body, priv, pub), str(out))
    run("verify", out, "--tests", "format,selfsig")
    assert "INVALID-DUE" in capsys.readouterr().out


@pytest.mark.parametrize("due,shown", [("", '""'), (0, "0"), (None, "(none declared)")])
def test_verify_shows_a_present_due_as_it_is(tmp_path, key, capsys, due, shown):
    """A due that is present but holds no timestamp is shown, not "(none declared)"."""
    out = tmp_path / "pre.json"
    run("prereg", "--key", key, "--target", "t", "--out", out)
    body = _read_body(out)
    body["due"] = due
    priv, pub = keys.load_signing_key(key)
    manifest.save(manifest.sign(body, priv, pub), str(out))
    run("verify", out, "--tests", "format,selfsig")
    text = capsys.readouterr().out
    assert f"    due          : {shown}\n" in text
    assert ("INVALID-DUE" in text) is (due is not None)


@pytest.mark.parametrize(
    "tests",
    ["chain", "format,chain", "selfsig", "format,selfsig,nope", ",", "BDR", "BDR,format,selfsig"],
    ids=["no-required", "no-selfsig", "no-format", "unknown", "none", "BDR", "BDR-beside-both"],
)
def test_verify_bad_tests_is_a_usage_error(prereg, tests, capsys):
    with pytest.raises(SystemExit) as e:
        run("verify", prereg, "--tests", tests)
    assert e.value.code == cli.EXIT_USAGE
    out, err = capsys.readouterr()
    assert "asexec-verify/1" not in out  # nothing ran
    if "BDR" in tests:  # split into format and selfsig (#26), not kept as an alias
        assert "unknown test(s): BDR;" in err


@pytest.mark.parametrize(
    "tests,missing",
    [("chain", "'format', 'selfsig'"), ("format,chain", "'selfsig'"), ("selfsig", "'format'")],
)
def test_verify_tests_without_a_required_test_names_what_is_missing(prereg, tests, missing, capsys):
    with pytest.raises(SystemExit) as e:
        run("verify", prereg, "--tests", tests)
    assert e.value.code == cli.EXIT_USAGE
    assert f"missing required test(s) {missing}" in capsys.readouterr().err


def test_verify_help_names_both_required_tests(capsys):
    with pytest.raises(SystemExit) as e:
        run("verify", "--help")
    assert e.value.code == 0
    text = " ".join(capsys.readouterr().out.split())  # argparse wraps the help
    assert "MUST include 'format' and 'selfsig'" in text
    assert (
        "available: ceiling, chain, complete, content, floor, format, keyconsist, order, "
        "selfsig, timely" in text
    )


@pytest.mark.parametrize(
    "argv",
    [
        ("verify",),
        ("verify", "x.json"),
        ("nope",),
        ("identity",),
        ("keygen", "--bogus"),
        ("prereg", "--key", "k"),
        ("prereg", "--key", "k", "--target", ""),
        ("prereg", "--key", "k", "--target", "t", "--target-file", "t.json"),
        ("prereg", "--key", "k", "--target", "t", "--declaration", "d", "--declaration-file", "d"),
        ("prereg", "--key", "k", "--target", "t", "--notes", "n", "--notes-file", "n"),
        ("postreg", "--key", "k", "--fulfills", REF, "--target", "t", "--target-file", "t"),
        ("postreg", "--key", "k", "--fulfills", REF, "--repro-recipe", "{nope"),
        ("identity", "match", "--domain", "d"),
        ("identity", "match", "--domain", "d", "--keyid", "kid", "--key", "k"),
        ("identity", "match", "--domain", "d", "--keyid", "kid", "--pubkey", "ab"),
    ],
    ids=[
        "no-args",
        "no-tests",
        "unknown-command",
        "no-subcommand",
        "unknown-option",
        "prereg-no-target",
        "prereg-empty-target",
        "target-and-target-file",
        "declaration-and-file",
        "notes-and-file",
        "postreg-target-and-target-file",
        "repro-recipe-not-json",
        "match-no-key",
        "match-keyid-and-key",
        "match-keyid-and-pubkey",
    ],
)
def test_usage_errors_exit_EXIT_USAGE_not_the_FAIL_status(argv, capsys):
    """argparse's own exit status is 2, which verify uses for FAIL; usage errors get 64.
    Every check that needs only the arguments is a usage error: nothing is read or run."""
    with pytest.raises(SystemExit) as e:
        run(*argv)
    assert e.value.code == cli.EXIT_USAGE != cli.EXIT_FAIL
    assert capsys.readouterr().err.startswith("usage: ")


_PREREG = ("prereg", "--key", "k.key", "--target", "t")
_POSTREG = ("postreg", "--key", "k.key", "--fulfills", REF)
_MATCH = ("identity", "match", "--domain", "d")
# Every option whose empty value cannot be meant, with a command it is valid in. An empty
# value must not be read as "absent" (inherited, dropped, or the default).
EMPTY_VALUES = [
    (("keygen",), "--out"),
    *((_PREREG, flag) for flag in (
        "--key", "--declaration", "--declaration-file", "--subject", "--notes",
        "--notes-file", "--plan", "--plan-file", "--items", "--items-file", "--floor-round",
        "--floor-round-file", "--out",
    )),
    (("prereg", "--key", "k.key"), "--target-file"),
    *((_POSTREG, flag) for flag in (
        "--target", "--target-file", "--declaration", "--declaration-file", "--subject",
        "--prev", "--repro-recipe", "--notes", "--notes-file", "--item-id", "--evidence",
        "--evidence-file", "--floor-round", "--floor-round-file", "--out",
    )),
    (("postreg", "--key", "k.key"), "--fulfills"),
    (("postreg", "--fulfills", REF), "--key"),
    (("verify", "pre.json"), "--artifacts"),
    (("identity", "emit", "--key", "k.key"), "--domain"),
    (("identity", "emit", "--key", "k.key"), "--out"),
    (("identity", "emit"), "--key"),
    (("identity", "match", "--keyid", "kid"), "--domain"),
    (_MATCH, "--keyid"),
    (_MATCH, "--pubkey"),
    (_MATCH, "--key"),
]  # fmt: skip


@pytest.mark.parametrize(
    "base,flag", EMPTY_VALUES, ids=[f"{base[0]}-{base[-1]}-{flag}" for base, flag in EMPTY_VALUES]
)
def test_an_empty_value_is_a_usage_error(tmp_path, monkeypatch, base, flag, capsys):
    """An empty value is no value: a usage error (64) with the usage line, and nothing runs.
    Before, ``postreg --target ""`` inherited the prereg's target, ``--notes-file ""`` was
    dropped, and ``identity match --keyid ""`` fetched."""
    monkeypatch.chdir(tmp_path)
    if base[0] == "verify":
        base = (*base, "--tests", "format,selfsig")
    with pytest.raises(SystemExit) as e:
        run(*base, flag, "")
    assert e.value.code == cli.EXIT_USAGE
    err = capsys.readouterr().err
    assert err.startswith("usage: ")
    assert err.endswith(f": error: argument {flag}: must not be empty\n")


@pytest.mark.parametrize(
    "argv",
    [
        ("verify", "", "--tests", "format,selfsig"),
        ("verify", "pre.json", "", "--tests", "format,selfsig"),
        ("prereg", "--key", "k.key", "--target", "t", "--subject", "a.txt", ""),
    ],
    ids=["verify-path", "verify-second-path", "subject-second-file"],
)
def test_an_empty_path_in_a_list_is_a_usage_error(tmp_path, monkeypatch, argv, capsys):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as e:
        run(*argv)
    assert e.value.code == cli.EXIT_USAGE
    err = capsys.readouterr().err
    assert err.startswith("usage: ") and err.endswith(": must not be empty\n")


@pytest.mark.parametrize(
    "value,message",
    [
        ("[1]", "--repro-recipe must be a JSON object"),
        ('"seed"', "--repro-recipe must be a JSON object"),
        ("5", "--repro-recipe must be a JSON object"),
        ("null", "--repro-recipe must be a JSON object"),
        ('{"seed": 1, "seed": 2}', "duplicate JSON key 'seed'"),
        ('{"seed": ' + "1" * 5000 + "}", "not valid JSON: Exceeds the limit (4300 digits)"),
        ("[" * 100 + "]" * 100, "nested more than 63 deep"),
    ],
    ids=["list", "string", "number", "null", "duplicate-key", "long-integer", "deep"],
)
def test_repro_recipe_not_an_object_is_a_usage_error(tmp_path, key, value, message, capsys):
    out = tmp_path / "out.json"
    with pytest.raises(SystemExit) as e:
        run(*_POSTREG[:2], key, *_POSTREG[3:], "--repro-recipe", value, "--out", out)
    assert e.value.code == cli.EXIT_USAGE
    err = capsys.readouterr().err
    assert err.startswith("usage: ") and f"error: argument --repro-recipe: {message}" in err
    assert not out.exists()


@pytest.mark.parametrize("cmd", ["emit", "match"])
@pytest.mark.parametrize("domain", ["lab example", "lab.example\n", "\tlab.example", "a\x1bb"])
def test_identity_domain_with_whitespace_or_control_characters_is_a_usage_error(
    tmp_path, monkeypatch, key, cmd, domain, capsys
):
    """A domain name has no whitespace or control character: such a --domain is a usage
    error, not a fetch of another URL or an error message split over two lines."""
    monkeypatch.chdir(tmp_path)
    given = ("--key", key) if cmd == "emit" else ("--keyid", "kid")
    with pytest.raises(SystemExit) as e:
        run("identity", cmd, *given, "--domain", domain)
    assert e.value.code == cli.EXIT_USAGE
    err = capsys.readouterr().err
    assert err.startswith("usage: ") and "argument --domain: " in err


@pytest.mark.parametrize(
    "flag,value",
    [
        ("--plan", '{"name": ' + "1" * 5000 + "}"),
        ("--items", "[" + "1" * 5000 + "]"),
        ("--evidence", "[" + "1" * 5000 + "]"),
        ("--floor-round", '{"round": ' + "1" * 5000 + "}"),
    ],
)
def test_an_inline_integer_past_the_digit_limit_is_not_valid_json(
    tmp_path, key, flag, value, capsys
):
    """Python reads no integer of more than 4,300 digits: such a value is not valid JSON here,
    and says so, as any other unreadable value does."""
    cmd = "postreg" if flag == "--evidence" else "prereg"
    link = ["--target", "t"] if cmd == "prereg" else ["--target", "t", "--fulfills", REF]
    with pytest.raises(SystemExit) as e:
        run(cmd, "--key", key, *link, flag, value, "--out", tmp_path / "out.json")
    assert e.value.code == cli.EXIT_USAGE
    err = capsys.readouterr().err
    assert err.startswith("usage: ")
    assert f"error: argument {flag}: not valid JSON: Exceeds the limit (4300 digits)" in err


@pytest.mark.parametrize(
    "flag,value",
    [
        ("--plan", '{"name": ' + "[" * 70 + "]" * 70 + "}"),
        ("--items", "[" * 70 + "]" * 70),
        ("--evidence", "[" * 100_000 + "]" * 100_000),
        ("--floor-round", "[" * 100_000 + "]" * 100_000),
    ],
)
def test_an_inline_value_nested_too_deep_is_a_usage_error(tmp_path, key, flag, value, capsys):
    """An inline JSON value is held to the manifest file's JSON rules: no duplicate key, and
    nested at most 64 deep (so no parser reaches its recursion limit)."""
    cmd = "postreg" if flag == "--evidence" else "prereg"
    link = ["--target", "t"] if cmd == "prereg" else ["--target", "t", "--fulfills", REF]
    with pytest.raises(SystemExit) as e:
        run(cmd, "--key", key, *link, flag, value, "--out", tmp_path / "out.json")
    assert e.value.code == cli.EXIT_USAGE
    err = capsys.readouterr().err
    assert err.startswith("usage: ")
    assert f"error: argument {flag}: nested more than 64 deep" in err


@pytest.mark.parametrize(
    "argv",
    [
        ("prereg", "--key", "{tmp}/absent.key", "--target", "t"),
        ("prereg", "--key", "{tmp}/bad.key", "--target", "t"),
        ("prereg", "--key", "{key}", "--target", "t", "--subject", "absent"),
        ("prereg", "--key", "{key}", "--target", "t", "--subject", "d"),
        ("prereg", "--key", "{key}", "--target", "t", "--subject", "{tmp}/c.txt"),
        ("prereg", "--key", "{key}", "--target", "t", "--subject", "../c.txt"),
        ("prereg", "--key", "{key}", "--target", "t", "--subject", "c.txt", "./c.txt"),
        ("postreg", "--key", "{key}", "--target", "t", "--fulfills", REF, "--subject", "d"),
        ("identity", "emit", "--key", "{tmp}/absent.key"),
    ],
    ids=[
        "missing-key-file",
        "invalid-key-file",
        "missing-subject",
        "subject-directory",
        "subject-absolute",
        "subject-dotdot",
        "subject-twice",
        "postreg-subject-directory",
        "emit-missing-key",
    ],
)
def test_errors_exit_EXIT_ERROR_with_a_message_not_a_traceback(
    tmp_path, key, argv, capsys, monkeypatch
):
    """Valid arguments that name an input the command cannot use: exit 1, one line. A
    subject is one file, named by its path relative to the current directory."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "d").mkdir()
    (tmp_path / "c.txt").write_text("c")
    (tmp_path / "bad.key").write_text('{"alg": "ed25519", "private_key": "zz"}')
    argv = [a.format(tmp=tmp_path, key=key) for a in argv]
    assert run(*argv, "--out", tmp_path / "out.json") == cli.EXIT_ERROR
    err = capsys.readouterr().err
    assert err.startswith("error: ") and "Traceback" not in err
    assert not (tmp_path / "out.json").exists()


def test_identity_match_failed_fetch_exits_EXIT_ERROR(monkeypatch, capsys):
    monkeypatch.setattr(identity, "fetch_wellknown", _boom)
    assert run("identity", "match", "--domain", "d", "--keyid", "kid") == cli.EXIT_ERROR
    assert capsys.readouterr().err == "error: offline\n"


def _get_error_line(capsys, *argv) -> str:
    """Run ``argv``, which must exit 1 with exactly one line on stderr, ``error: ...`` (from
    ``main``, or a ``SystemExit`` message, which Python prints the same way), and return it."""
    try:
        code = run(*argv)
        err = capsys.readouterr().err
    except SystemExit as e:
        assert isinstance(e.code, str), e.code  # a message: Python prints it, exit 1
        code, err = cli.EXIT_ERROR, capsys.readouterr().err + e.code + "\n"
    assert code == cli.EXIT_ERROR
    assert "Traceback" not in err
    (line,) = err.splitlines()
    assert line.startswith("error: ")
    return line


_JSON_FILE_FLAGS = [
    ("prereg", "--target-file"),
    ("prereg", "--declaration-file"),
    ("prereg", "--notes-file"),
    ("prereg", "--plan-file"),
    ("prereg", "--items-file"),
    ("prereg", "--floor-round-file"),
    ("postreg", "--target-file"),
    ("postreg", "--declaration-file"),
    ("postreg", "--notes-file"),
    ("postreg", "--evidence-file"),
]


def _build_args_with_file(cmd, flag, key, path, out):
    """``cmd`` signing with ``flag path``, every other argument valid."""
    target = [] if flag == "--target-file" else ["--target", "t"]
    link = [] if cmd == "prereg" else ["--fulfills", REF]
    return (cmd, "--key", key, *target, *link, flag, path, "--out", out)


@pytest.mark.parametrize("cmd,flag", _JSON_FILE_FLAGS)
@pytest.mark.parametrize(
    "content,message",
    [
        (b"\xff\xfe{}", "must contain valid JSON: it is not UTF-8 text"),
        ('"caf\xe9"'.encode("latin-1"), "must contain valid JSON: it is not UTF-8 text"),
        ('{"a": 1}'.encode("utf-16"), "must contain valid JSON: it is not UTF-8 text"),
        (b'\xef\xbb\xbf{"a": 1}', "must contain valid JSON: Unexpected UTF-8 BOM"),
        (b"[" + b"1" * 5000 + b"]", "must contain valid JSON: Exceeds the limit (4300 digits)"),
        (b"[" * 100_000 + b"]" * 100_000, ": nested more than 6"),
        (b'{"a": 1, "a": 2}', ": duplicate JSON key 'a'"),
        (b"{nope", "must contain valid JSON: Expecting property name"),
    ],
    ids=["not-utf8", "latin-1", "utf-16", "bom", "long-integer", "deep", "duplicate-key",
         "not-json"],
)  # fmt: skip
def test_a_json_file_that_breaks_the_json_rules_is_one_error_line(
    tmp_path, key, cmd, flag, content, message, capsys
):
    """Every --…-file is held to a manifest file's JSON rules: UTF-8 JSON text (RFC 8259), no
    duplicate key, at most 64 deep. What a file holds is not an argument: exit 1, one
    ``error:`` line naming the file, never a traceback, and nothing written. Before, a
    non-UTF-8 file printed a UnicodeDecodeError traceback, deep nesting a RecursionError,
    and --target-file, --declaration-file and --notes-file took a repeated key."""
    path, out = tmp_path / "value.json", tmp_path / "out.json"
    path.write_bytes(content)
    line = _get_error_line(capsys, *_build_args_with_file(cmd, flag, key, path, out))
    assert line.startswith(f"error: {str(path)!r}") and message in line
    assert not out.exists()


@pytest.mark.parametrize("cmd,flag", _JSON_FILE_FLAGS)
def test_a_json_file_that_is_a_directory_is_one_error_line(tmp_path, key, cmd, flag, capsys):
    path, out = tmp_path / "value", tmp_path / "out.json"
    path.mkdir()
    line = _get_error_line(capsys, *_build_args_with_file(cmd, flag, key, path, out))
    assert line == f"error: {flag} is a directory: {str(path)!r}"
    assert not out.exists()


@pytest.mark.parametrize("cmd,flag", _JSON_FILE_FLAGS)
def test_a_json_file_may_be_a_pipe(tmp_path, monkeypatch, key, cmd, flag):
    """A --…-file is read whatever it is, a directory aside: a pipe (``--floor-round-file <(curl
    …)``, as README shows, or /dev/stdin) is read to its end like a file."""
    value = {
        "--plan-file": {"name": "plan.md"},
        "--items-file": [{"id": "R1"}],
        "--evidence-file": [{"name": "plan.md"}],
        "--floor-round-file": SAVED_ROUND,
    }.get(flag, {"from": "a pipe"})
    monkeypatch.chdir(tmp_path)
    (tmp_path / "plan.md").write_text("plan\n")
    path, out = tmp_path / "pipe", tmp_path / "out.json"
    os.mkfifo(path)
    writer = threading.Thread(target=lambda: path.write_text(json.dumps(value)), daemon=True)
    writer.start()
    try:
        assert run(*_build_args_with_file(cmd, flag, key, path, out)) == 0
    finally:
        writer.join(timeout=10)
    assert out.exists()


def test_a_json_file_may_be_a_character_device(tmp_path, key, capsys):
    """A character device is read too (here /dev/null, which holds no JSON)."""
    if not os.path.exists(os.devnull):
        pytest.skip("no null device")
    out = tmp_path / "out.json"
    line = _get_error_line(
        capsys, *_build_args_with_file("prereg", "--notes-file", key, os.devnull, out)
    )
    assert line == (
        f"error: {os.devnull!r} must contain valid JSON: Expecting value: line 1 column 1 (char 0)"
    )


@pytest.mark.parametrize("cmd", ["prereg", "postreg"])
@pytest.mark.parametrize("flag", ["--target-file", "--declaration-file", "--notes-file"])
@pytest.mark.parametrize(
    "content", ['""', "[]", '["t"]', "5", "true", "null", "{}"],
    ids=["empty-string", "empty-list", "list", "number", "bool", "null", "empty-object"],
)  # fmt: skip
def test_a_free_form_file_holds_a_non_empty_object_or_string(
    tmp_path, key, cmd, flag, content, capsys
):
    """--target-file, --declaration-file and --notes-file hold what the field is: a JSON
    object or a string, not empty. Anything else is the file's content: exit 1, one line
    that says what the file must hold (before: pydantic's text, or a value silently dropped
    or inherited)."""
    path, out = tmp_path / "value.json", tmp_path / "out.json"
    path.write_text(content)
    line = _get_error_line(capsys, *_build_args_with_file(cmd, flag, key, path, out))
    assert line.startswith(
        f"error: {flag} {str(path)!r} must hold a non-empty JSON object or string"
    )
    assert not out.exists()


@pytest.mark.parametrize("content", ['"a target"', '{"model": "m"}'])
def test_a_free_form_file_holding_a_string_or_object_is_signed_as_it_is(tmp_path, key, content):
    path, out = tmp_path / "value.json", tmp_path / "out.json"
    path.write_text(content)
    assert run(*_build_args_with_file("prereg", "--notes-file", key, path, out)) == 0
    assert _read_body(out)["notes"] == json.loads(content)


def _make_nested(depth):
    """A JSON object ``depth`` deep (the outermost object is 1)."""
    value = {}
    for _ in range(depth - 1):
        value = {"a": value}
    return value


@pytest.mark.parametrize("cmd", ["prereg", "postreg"])
@pytest.mark.parametrize("flag", ["--target-file", "--declaration-file", "--notes-file"])
def test_a_free_form_file_is_at_most_63_deep_so_its_body_is_at_most_64(
    tmp_path, key, cmd, flag, capsys
):
    """The value sits one level down in the body, which format #2 holds to 64 deep: a free-form
    file is read to 63, and a 64-deep one is the file's content, exit 1, one line. At 63 the
    body is signed and passes format."""
    path, out = tmp_path / "value.json", tmp_path / "out.json"
    path.write_text(json.dumps(_make_nested(64)))
    line = _get_error_line(capsys, *_build_args_with_file(cmd, flag, key, path, out))
    assert line == (
        f"error: {str(path)!r}: nested more than 63 deep (its value sits one level down in a "
        "body, which is at most 64)"
    )
    assert not out.exists()
    path.write_text(json.dumps(_make_nested(63)))
    assert run(*_build_args_with_file(cmd, flag, key, path, out)) == 0
    capsys.readouterr()
    assert run("verify", out, "--tests", "format,selfsig") == 0


def test_an_inline_repro_recipe_is_at_most_63_deep(tmp_path, key, capsys):
    """--repro-recipe sits one level down in the body too: 64 deep is a usage error (before,
    it parsed and signing then refused the body, exit 1); 63 deep is signed."""
    out = tmp_path / "out.json"
    argv = ("postreg", "--key", key, "--fulfills", REF, "--target", "t", "--out", out)
    with pytest.raises(SystemExit) as e:
        run(*argv, "--repro-recipe", json.dumps(_make_nested(64)))
    assert e.value.code == cli.EXIT_USAGE
    err = capsys.readouterr().err
    assert err.startswith("usage: ") and "argument --repro-recipe: nested more than 63 deep" in err
    assert run(*argv, "--repro-recipe", json.dumps(_make_nested(63))) == 0


@pytest.mark.parametrize(
    "content,why",
    [
        ("[" * 100_000 + "]" * 100_000, "nested more than 64 deep"),
        ('{"alg": "ed25519", "alg": "ed25519"}', "duplicate JSON key 'alg'"),
    ],
    ids=["deep", "duplicate-key"],
)
def test_a_key_file_that_breaks_the_json_rules_is_one_error_line(tmp_path, content, why, capsys):
    """A key file is held to a manifest file's JSON rules, so it reads the same on every
    Python version (3.12 and 3.13 hit their recursion limit on deep nesting; 3.14 does not)."""
    path = tmp_path / "bad.key"
    path.write_text(content)
    line = _get_error_line(capsys, "prereg", "--key", path, "--target", "t",
                       "--out", tmp_path / "out.json")  # fmt: skip
    assert line == f"error: key file {str(path)!r} is not valid JSON: {why}"


# A --fulfills file postreg cannot read: no ref or target this release can take from it.
def _relabel(payload_type):
    return lambda mani: mani["dsse"].update(payloadType=payload_type)


def _flip_sig(mani):
    sig = mani["dsse"]["signatures"][0]["sig"]
    mani["dsse"]["signatures"][0]["sig"] = ("B" if sig[0] == "A" else "A") + sig[1:]


@pytest.mark.parametrize(
    "edit,message",
    [
        (_relabel("application/vnd.asexec.v2+json"),
         "is not a readable manifest: payloadType names a format newer than this release"),
        (_relabel("application/vnd.asexec.0.3.0b1+json"),
         "is not a readable manifest: payloadType names an asexec beta format"),
        (lambda mani: mani["dsse"].pop("payloadType"),
         "is not a readable manifest: malformed: dsse.payloadType: Field required"),
    ],
    ids=["newer-format", "beta-format", "no-payload-type"],
)  # fmt: skip
def test_postreg_refuses_to_fulfil_a_prereg_it_cannot_read(
    tmp_path, key, prereg, edit, message, capsys
):
    """--fulfills names a prereg file read as verify reads it: one that fails format (of an
    unknown or beta format, or malformed) has no ref or target this release can take, so it is
    refused: exit 1, one line, nothing written. Before, a file of another format was signed
    against under this release's rules."""
    mani = json.loads(open(prereg).read())
    edit(mani)
    open(prereg, "w").write(json.dumps(mani))
    out = tmp_path / "out.json"
    line = _get_error_line(capsys, "postreg", "--key", key, "--fulfills", prereg, "--out", out)
    assert line.startswith(f"error: --fulfills {prereg!r} {message}")
    assert not out.exists()


@pytest.mark.parametrize(
    "edit",
    [
        _flip_sig,
        lambda mani: mani["dsse"]["signatures"][0].update(keyid="sha-256:" + "00" * 32),
        lambda mani: mani["dsse"]["signatures"].append(mani["dsse"]["signatures"][0]),
    ],
    ids=["bad-signature", "keyid-not-derived", "two-signatures"],
)
def test_postreg_fulfils_a_prereg_that_fails_selfsig_as_before(tmp_path, key, prereg, edit):
    """A prereg file that passes format but fails selfsig is still fulfilled: its ref and
    target are read as for any other."""
    mani = json.loads(open(prereg).read())
    edit(mani)
    open(prereg, "w").write(json.dumps(mani))
    out = tmp_path / "out.json"
    assert run("postreg", "--key", key, "--fulfills", prereg, "--out", out) == 0
    assert _read_body(out)["fulfills"] == _read_ref(prereg) and _read_body(out)["target"] == "t"


@pytest.mark.parametrize(
    "target",
    [None, "", [], ["t"], 5, {}],
    ids=["absent", "empty-string", "empty-list", "list", "number", "empty-object"],
)
def test_postreg_inheriting_no_usable_target_is_one_error_line(tmp_path, key, target, capsys):
    """A validly signed prereg whose body has no target a postreg can inherit (absent, or not
    a non-empty string or object): exit 1, one line naming the fix. Before: KeyError."""
    pre, out = tmp_path / "pre.json", tmp_path / "out.json"
    body = {"phase": "prereg", "predicateType": "https://asexec.org/manifest/v1"}
    if target is not None:
        body["target"] = target
    _sign_stored_bytes(pre, key, json.dumps(body).encode())
    line = _get_error_line(capsys, "postreg", "--key", key, "--fulfills", pre, "--out", out)
    assert line == (
        f"error: --fulfills {str(pre)!r} has no target to inherit (a non-empty string or JSON "
        "object); give --target or --target-file"
    )
    assert not out.exists()
    # with a target of its own, the postreg is signed
    assert run("postreg", "--key", key, "--fulfills", pre, "--target", "t", "--out", out) == 0


_NAME_NUL = "a\x00b"
_NAME_SURROGATE = "\ud800"


@pytest.mark.parametrize(
    "cmd,flag,value",
    [
        ("prereg", "--plan", {"name": _NAME_NUL}),
        ("prereg", "--plan", {"name": _NAME_SURROGATE}),
        ("postreg", "--evidence", [{"name": _NAME_NUL}]),
        ("postreg", "--evidence", [{"name": _NAME_SURROGATE}]),
    ],
    ids=["plan-nul", "plan-surrogate", "evidence-nul", "evidence-surrogate"],
)
@pytest.mark.parametrize("how", ["inline", "file"])
def test_a_name_no_file_can_have_is_refused(tmp_path, key, cmd, flag, value, how, capsys):
    """A --plan or --evidence name holding a NUL (no path has one) or a lone surrogate (no
    UTF-8 form, so no body can hold it) names no file: inline, a usage error (64); from a
    file, exit 1, one line. Before: ValueError or UnicodeEncodeError tracebacks."""
    link = ["--target", "t"] if cmd == "prereg" else ["--target", "t", "--fulfills", REF]
    out = tmp_path / "out.json"
    text = json.dumps(value)  # ensure_ascii: \u0000 and \ud800 escapes, read back as given
    if how == "inline":
        with pytest.raises(SystemExit) as e:
            run(cmd, "--key", key, *link, flag, text, "--out", out)
        assert e.value.code == cli.EXIT_USAGE
        err = capsys.readouterr().err
        assert err.startswith("usage: ") and "names no file: it has a" in err
    else:
        path = tmp_path / "value.json"
        path.write_text(text)
        line = _get_error_line(capsys, cmd, "--key", key, *link, f"{flag}-file", path, "--out", out)
        assert "names no file: it has a" in line
    assert not out.exists()


@pytest.mark.parametrize(
    "name,why",
    [
        (_NAME_NUL, "a NUL character"),
        (_NAME_SURROGATE, "a character with no UTF-8 form"),
        ("\udcff", "a character with no UTF-8 form"),  # a non-UTF-8 byte, as argv decodes it
    ],
    ids=["nul", "surrogate", "non-utf8-byte"],
)
def test_a_subject_no_manifest_can_name_is_refused(tmp_path, key, monkeypatch, name, why, capsys):
    monkeypatch.chdir(tmp_path)
    if name == "\udcff":
        (tmp_path / os.fsdecode(b"\xff")).write_text("x")  # the file exists
    line = _get_error_line(capsys, "prereg", "--key", key, "--target", "t", "--subject", name,
                       "--out", tmp_path / "out.json")  # fmt: skip
    assert line == f"error: {name!r} names no file a manifest can hold: it has {why}"


@pytest.mark.parametrize(
    "case",
    ["not-found", "directory", "bad-json", "free-form", "fulfills", "key-file"],
)
def test_a_path_with_a_newline_stays_on_one_error_line(tmp_path, key, case, capsys):
    """Every error naming a path shows it quoted (its repr), so a newline in it can't split the
    error line or forge another."""
    path = tmp_path / "a\nb.json"
    out = tmp_path / "out.json"
    argv = ("prereg", "--key", key, "--target", "t", "--notes-file", path, "--out", out)
    if case == "directory":
        path.mkdir()
    elif case == "bad-json":
        path.write_text("{nope")
    elif case == "free-form":
        path.write_text("[]")
    elif case == "fulfills":
        path.write_text("{nope")
        argv = ("postreg", "--key", key, "--fulfills", path, "--out", out)
    elif case == "key-file":
        path.write_text("{nope")
        argv = ("prereg", "--key", path, "--target", "t", "--out", out)
    line = _get_error_line(capsys, *argv)
    assert repr(str(path)) in line


@pytest.mark.parametrize(
    "body,why",
    [
        (b"[" * 100_000 + b"]" * 100_000, "nested more than 64 deep"),
        (b'{"keys": [], "keys": []}', "duplicate JSON key 'keys'"),
        (b"not json", "Expecting value"),
        (b'\xff{"keys": []}', "not JSON text in UTF-8, UTF-16 or UTF-32"),
    ],
    ids=["deep", "duplicate-key", "not-json", "not-utf8"],
)
def test_identity_match_reads_the_document_under_the_json_rules(monkeypatch, body, why, capsys):
    """The fetched document is held to a manifest file's JSON rules, so it reads the same on
    every Python version (a deep one passed on 3.14 and failed on 3.12): exit 1, one line."""
    monkeypatch.setattr(identity.urllib.request, "urlopen", lambda url, timeout: _Resp(body))
    line = _get_error_line(capsys, "identity", "match", "--domain", "lab.example", "--keyid", "kid")
    assert line.startswith(
        "error: https://lab.example/.well-known/asexec.json is not an asexec identity document: "
    )
    assert why in line


@pytest.mark.parametrize(
    "encode",
    [
        lambda text: b"\xef\xbb\xbf" + text.encode("utf-8"),
        lambda text: text.encode("utf-16"),
        lambda text: text.encode("utf-16-le"),
        lambda text: text.encode("utf-32"),
    ],
    ids=["utf-8-bom", "utf-16", "utf-16-le", "utf-32"],
)
def test_identity_match_reads_a_document_in_any_json_encoding(key, monkeypatch, encode, capsys):
    """A document in UTF-16 or UTF-32, or UTF-8 with a byte order mark, is read as the base read
    it (``json.load`` of bytes detects the encoding), and the key is matched."""
    doc = json.dumps({"keys": [{"keyid": json.load(open(key))["keyid"]}]})
    monkeypatch.setattr(identity.urllib.request, "urlopen", lambda url, timeout: _Resp(encode(doc)))
    assert run("identity", "match", "--domain", "lab.example", "--key", key) == 0
    assert "IS asserted by lab.example" in capsys.readouterr().out


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()


@pytest.mark.parametrize(
    "doc,why",
    [
        ([], "not a JSON object"),
        ("keys", "not a JSON object"),
        (5, "not a JSON object"),
        ({"keys": 5}, "'keys' is not an array of objects"),
        ({"keys": {"keyid": "kid"}}, "'keys' is not an array of objects"),
        ({"keys": ["kid"]}, "'keys' is not an array of objects"),
    ],
    ids=["list", "string", "number", "keys-number", "keys-object", "keys-of-strings"],
)
def test_identity_match_on_a_document_that_is_not_an_identity_document(
    monkeypatch, doc, why, capsys
):
    """A domain's .well-known/asexec.json that is not an object holding an array of key
    objects: exit 1, one line (before: AttributeError or TypeError tracebacks)."""
    monkeypatch.setattr(identity, "fetch_wellknown", lambda domain, timeout=10: doc)
    line = _get_error_line(capsys, "identity", "match", "--domain", "lab.example", "--keyid", "kid")
    assert line == (
        "error: https://lab.example/.well-known/asexec.json is not an asexec identity "
        f"document: {why}"
    )


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
    body = _read_body(path)
    mutate(body)
    priv, pub = keys.load_signing_key(key)
    manifest.save(manifest.sign(body, priv, pub), path)


def test_verify_prints_verified_floor(tmp_path, key, prereg, capsys):
    _resign(prereg, key, lambda body: body.update(anchor={"floor": FLOOR}))
    assert run("verify", prereg, "--tests", "format,selfsig,floor") == 0
    out = capsys.readouterr().out
    assert "drand freshness floor round 1000 (created no earlier than 1692" in out
    assert "floor=PASS format=PASS selfsig=PASS" in out


def test_verify_prints_failed_floor_without_timestamp(tmp_path, key, prereg, capsys):
    _resign(prereg, key, lambda body: body.update(anchor={"floor": {**FLOOR, "round": 1001}}))
    assert run("verify", prereg, "--tests", "format,selfsig,floor") == 2
    out = capsys.readouterr().out
    assert "drand freshness floor round 1001" in out
    assert "created no earlier than" not in out
    assert "floor=FAIL" in out


def test_verify_prints_ceiling_and_trust_section(
    tmp_path, key, prereg, capsys, monkeypatch, make_server, ceiling_for
):
    mani = manifest.load(prereg)
    nonce_hex = d.derive_witness_nonce(mani)
    lt_pub, sign_response = make_server()
    monkeypatch.setitem(roughtime.SERVERS, "synthetic", {"pubkey": lt_pub})
    manifest.attach_ceiling(mani, ceiling_for(nonce_hex, "synthetic", lt_pub, sign_response))
    manifest.save(mani, prereg)

    assert run("verify", prereg, "--tests", "format,selfsig,ceiling") == 0
    out = capsys.readouterr().out
    assert "ceiling witness (created no later than" in out and "witness synthetic" in out
    assert "=== ceiling trust (what you are accepting) ===" in out
    assert "trusting synthetic" in out


def test_verify_prints_invalid_ceiling_error(tmp_path, key, prereg, capsys):
    mani = manifest.load(prereg)
    manifest.attach_ceiling(mani, {"ceiling_type": "roughtime", "witness_id": "nobody"})
    manifest.save(mani, prereg)
    run("verify", prereg, "--tests", "format,selfsig,ceiling")
    out = capsys.readouterr().out
    assert cli.NO in out and "ceiling witness (" in out
    assert "ceiling trust" not in out


def test_verify_prints_content_mismatch(tmp_path, key, capsys, monkeypatch):
    art = tmp_path / "art"
    art.mkdir()
    (art / "a.txt").write_text("one")
    out = tmp_path / "pre.json"
    monkeypatch.chdir(art)
    assert run("prereg", "--key", key, "--target", "t", "--subject", "a.txt",
               "--out", out) == 0  # fmt: skip
    (art / "a.txt").write_text("two")
    capsys.readouterr()
    code = run("verify", out, "--tests", "format,selfsig,content", "--artifacts", art)
    text = capsys.readouterr().out
    assert code == 2
    assert "content hashes mismatch" in text
    assert "a.txt: digest mismatch" in text


def test_verify_prints_content_ok(tmp_path, key, capsys, monkeypatch):
    art = tmp_path / "art"
    art.mkdir()
    (art / "a.txt").write_text("one")
    out = tmp_path / "pre.json"
    monkeypatch.chdir(art)
    run("prereg", "--key", key, "--target", "t", "--subject", "a.txt", "--out", out)
    capsys.readouterr()
    assert run("verify", out, "--tests", "format,selfsig,content", "--artifacts", art) == 0
    assert "content hashes ok" in capsys.readouterr().out


def test_subjects_are_files_named_by_their_relative_paths(tmp_path, key, monkeypatch):
    """--subject names each file by its normalized relative path, with its own hash_alg, so
    two files with one basename stay distinct, and verify finds each under --artifacts."""
    art = tmp_path / "art"
    for name in ("a/run.py", "b/run.py"):
        (art / name).parent.mkdir(parents=True, exist_ok=True)
        (art / name).write_text(name)
    monkeypatch.chdir(art)
    pre, post = tmp_path / "pre.json", tmp_path / "post.json"
    assert run("prereg", "--key", key, "--target", "t", "--subject", "./a/run.py",
               "--out", pre) == 0  # fmt: skip
    assert run("postreg", "--key", key, "--fulfills", pre, "--subject", "a/run.py",
               "b//run.py", "--out", post) == 0  # fmt: skip
    sha = {n: hashlib.sha256(n.encode()).hexdigest() for n in ("a/run.py", "b/run.py")}
    assert _read_body(pre)["subject"] == [
        {"name": "a/run.py", "hash_alg": "sha-256", "digest": {"sha-256": sha["a/run.py"]}}
    ]
    assert [e["name"] for e in _read_body(post)["subject"]] == ["a/run.py", "b/run.py"]
    assert "hash_alg" not in _read_body(pre) and "hash_alg" not in _read_body(post)
    tests = "format,selfsig,content"
    assert run("verify", pre, post, "--tests", tests, "--artifacts", art) == 0


def test_verify_ends_with_code_then_time(prereg, capsys):
    assert run("verify", prereg, "--tests", "format,selfsig") == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines[-2] == "asexec-verify/1 format=PASS selfsig=PASS"
    assert re.fullmatch(r"Checked at \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", lines[-1])


def test_verify_prints_each_commitments_signer(key, prereg, capsys):
    _, pub = keys.load_signing_key(key)
    run("verify", prereg, "--tests", "format,selfsig")
    assert f"    signer       : {keys.derive_keyid(pub)}\n" in capsys.readouterr().out


def test_verify_prints_notarization_only(tmp_path, key, prereg, capsys):
    post = tmp_path / "po.json"
    assert run("postreg", "--key", key, "--target", "t", "--fulfills", REF, "--out", post) == 0
    capsys.readouterr()
    run("verify", post, "--tests", "format,selfsig")
    out = capsys.readouterr().out
    assert "=== notarization-only" in out
    assert f"(fulfills {REF})" in out
    assert "(no pre-registrations among the provided manifests)" in out


def test_verify_lists_rejected_preregistrations(tmp_path, key, prereg, capsys):
    """A prereg that fails selfsig is no commitment: it is listed under its own heading with
    its reason and keyid, and the postreg naming it is listed beneath it as rejected."""
    post = tmp_path / "post.json"
    assert run("postreg", "--key", key, "--fulfills", prereg, "--out", post) == 0
    mani = json.loads(open(prereg).read())
    mani["dsse"]["signatures"][0]["sig"] = base64.b64encode(bytes(64)).decode()
    open(prereg, "w").write(json.dumps(mani))
    capsys.readouterr()
    assert run("verify", prereg, post, "--tests", "format,selfsig,chain,keyconsist") == 2
    out = capsys.readouterr().out
    pre_ref, post_ref = _read_ref(prereg), _read_ref(post)
    commitments = out.split("=== commitments ===\n")[1].split("\n\n")[0]
    assert commitments == "  (no commitments: no pre-registration provided is validly signed)"
    block = out.split("=== rejected pre-registrations ===\n")[1].split("\n\n")[0]
    assert block.splitlines() == [
        f"  {cli.NO} prereg {pre_ref} is NOT a commitment: invalid signature",
        f"    keyid        : {mani['dsse']['signatures'][0]['keyid']}",
        f"    {cli.NO} postreg {post_ref} does NOT count toward fulfillment: "
        "the pre-registration's signature is invalid",
    ]
    assert "=== notarization-only" not in out
    assert "asexec-verify/1 chain=FAIL format=PASS keyconsist=FAIL selfsig=FAIL" in out


def test_verify_prints_no_rejected_preregistrations_block_when_none(tmp_path, key, prereg, capsys):
    post = tmp_path / "post.json"
    assert run("postreg", "--key", key, "--fulfills", prereg, "--out", post) == 0
    capsys.readouterr()
    assert run("verify", prereg, post, "--tests", "format,selfsig") == 0
    assert "rejected pre-registrations" not in capsys.readouterr().out


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


@pytest.mark.parametrize(
    "flag,expected",
    [("--keyid", {"keyid": "kid", "pubkey": None}), ("--pubkey", {"keyid": None, "pubkey": "kid"})],
)
def test_identity_match_passes_explicit_keyid_or_pubkey(monkeypatch, flag, expected):
    seen = {}
    monkeypatch.setattr(
        identity,
        "match_binding",
        lambda domain, keyid=None, pubkey_hex=None, timeout=10: (
            seen.update(keyid=keyid, pubkey=pubkey_hex)
            or {"bound": True, "listed_count": 0, "caveat": ""}
        ),
    )
    assert run("identity", "match", "--domain", "d", flag, "kid") == 0
    assert seen == expected


def test_identity_without_subcommand_is_usage_error():
    with pytest.raises(SystemExit):
        run("identity")


# --- a closed stdout ---------------------------------------------------------- #
def _run_with_stdout_closed(cwd, *argv):
    """Run ``asexec argv`` with stdout a pipe whose reader has already gone, as ``asexec … |
    head -1`` has once head exits: every write to it fails (EPIPE)."""
    read, write = os.pipe()
    os.close(read)
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "asexec", *map(str, argv)],
            stdout=write, stderr=subprocess.PIPE, cwd=cwd, timeout=120,
        )  # fmt: skip
    finally:
        os.close(write)
    return proc.returncode, proc.stderr.decode()


@pytest.mark.parametrize("copies", [1, 300], ids=["short-report", "long-report"])
@pytest.mark.parametrize("tampered,code", [(False, 0), (True, 2)], ids=["pass", "fail"])
def test_verify_keeps_its_verdict_when_stdout_closes(tmp_path, key, prereg, copies, tampered, code):
    """``verify … | head -1``: the reader closing stdout changes nothing about the verdict, so
    the exit status is still 0 or 2, with nothing on stderr. A short report fails at Python's
    flush on exit; a long one while it prints. Before: exit 120 or 1."""
    files = tmp_path / "manifests"
    files.mkdir()
    for i in range(copies):
        (files / f"pre-{i}.json").write_text(open(prereg).read())
    if tampered:
        _edit_body_after_signing(files / "pre-0.json", lambda body: body.update(target="u"))
    assert _run_with_stdout_closed(tmp_path, "verify", files, "--tests", "format,selfsig") == (
        code,
        "",
    )


def test_signing_succeeds_when_stdout_closes(tmp_path, key):
    """prereg writes its file and then prints: a closed stdout leaves exit 0, the file
    written, and nothing on stderr."""
    out = tmp_path / "pre.json"
    assert _run_with_stdout_closed(
        tmp_path, "prereg", "--key", key, "--target", "t", "--out", out
    ) == (
        0,
        "",
    )
    assert _read_body(out)["target"] == "t"


@pytest.mark.parametrize(
    "argv,code,err",
    [
        (("--version",), 0, ""),
        (("--help",), 0, ""),
        (("verify", "--help"), 0, ""),
        (("verify", "pre.json", "--tests", "chain"), 64, "usage: "),
    ],
    ids=["version", "help", "verify-help", "usage-error"],
)
def test_what_argparse_prints_keeps_its_status_when_stdout_closes(tmp_path, argv, code, err):
    """``asexec --version | true``: argparse printed and exits; a reader that has gone does not
    change its status, as for a command that finished (before: exit 1, "stdout was closed")."""
    status, stderr = _run_with_stdout_closed(tmp_path, *argv)
    assert status == code and stderr.startswith(err)
    assert "stdout was closed" not in stderr and "Traceback" not in stderr


def _run_with_stdout(cwd, how, *argv, env=None):
    """Run ``asexec argv`` with stdout closed (``>&-``: Python then has no ``sys.stdout``) or on
    a full device (``>/dev/full``: every flush fails with ENOSPC)."""
    cmd = [sys.executable, "-m", "asexec", *map(str, argv)]
    if how == "closed":
        cmd, stdout = ["sh", "-c", 'exec "$@" >&-', "sh", *cmd], None
    else:
        if not os.path.exists("/dev/full"):
            pytest.skip("no /dev/full")
        stdout = open("/dev/full", "wb")  # noqa: SIM115
    try:
        proc = subprocess.run(cmd, stdout=stdout, stderr=subprocess.PIPE, cwd=cwd, timeout=120,
                              env=env)  # fmt: skip
    finally:
        if stdout is not None:
            stdout.close()
    return proc.returncode, proc.stderr.decode()


@pytest.mark.parametrize("tampered,code", [(False, 0), (True, 2)], ids=["pass", "fail"])
def test_verify_with_stdout_closed_keeps_its_verdict(tmp_path, key, prereg, tampered, code):
    """``verify … >&-``: nothing can be printed, and the verdict stands (as on the base)."""
    if tampered:
        _edit_body_after_signing(prereg, lambda body: body.update(target="u"))
    assert _run_with_stdout(tmp_path, "closed", "verify", prereg, "--tests", "format,selfsig") == (
        code,
        "",
    )


@pytest.mark.parametrize(
    "argv,code,err",
    [
        (("keygen", "--out", "{tmp}/new.key"), 0, ""),
        (("prereg", "--key", "{key}", "--target", "t", "--out", "{tmp}/pre2.json"), 0, ""),
        (("verify", "--help"), 0, ""),
        (("verify", "{prereg}", "--tests", "chain"), 64, "usage: "),
    ],
    ids=["keygen", "prereg", "help", "usage-error"],
)
def test_other_commands_with_stdout_closed(tmp_path, key, prereg, argv, code, err):
    argv = [a.format(tmp=tmp_path, key=key, prereg=prereg) for a in argv]
    status, stderr = _run_with_stdout(tmp_path, "closed", *argv)
    assert status == code and stderr.startswith(err) and "Traceback" not in stderr


@pytest.mark.parametrize(
    "argv",
    [
        ("verify", "{prereg}", "--tests", "format,selfsig"),
        ("prereg", "--key", "{key}", "--target", "t", "--out", "{tmp}/pre2.json"),
    ],
    ids=["verify", "prereg"],
)
def test_a_full_stdout_is_one_error_line(tmp_path, key, prereg, argv):
    """``>/dev/full``: the output can't be written, which is an error (exit 1, one line),
    not a traceback and not Python's exit status 120."""
    argv = [a.format(tmp=tmp_path, key=key, prereg=prereg) for a in argv]
    assert _run_with_stdout(tmp_path, "full", *argv) == (
        1,
        "error: could not write the output: [Errno 28] No space left on device\n",
    )


def test_a_usage_error_with_a_full_stdout_is_still_a_usage_error(tmp_path, prereg):
    status, stderr = _run_with_stdout(tmp_path, "full", "verify", prereg, "--tests", "chain")
    assert status == cli.EXIT_USAGE and stderr.startswith("usage: ")


def test_verify_on_an_ascii_stdout_escapes_what_it_cannot_encode(tmp_path, prereg):
    """``PYTHONIOENCODING=ascii``: ✓ and ✗ are printed as escapes, not a traceback."""
    env = {**os.environ, "PYTHONIOENCODING": "ascii"}
    proc = subprocess.run(
        [sys.executable, "-m", "asexec", "verify", prereg, "--tests", "format,selfsig"],
        capture_output=True, cwd=tmp_path, env=env, timeout=120,
    )  # fmt: skip
    assert (proc.returncode, proc.stderr) == (0, b"")
    assert b"\\u2713 format=PASS" in proc.stdout


def test_a_broken_pipe_writing_a_file_is_not_reported_as_stdout(tmp_path, key, monkeypatch, capsys):
    """A BrokenPipeError from writing --out (a FIFO whose reader left) is that file's error, not
    a closed stdout."""

    def raise_broken_pipe(*_a, **_k):
        raise BrokenPipeError(32, "Broken pipe")

    monkeypatch.setattr(manifest, "save", raise_broken_pipe)
    line = _get_error_line(capsys, "prereg", "--key", key, "--target", "t", "--out", tmp_path / "o")
    assert line == "error: [Errno 32] Broken pipe"


# --- entry points ------------------------------------------------------------ #
def test_python_dash_m_entry_point_exits_with_main_code(monkeypatch, prereg):
    monkeypatch.setattr(sys, "argv", ["asexec", "verify", prereg, "--tests", "format,selfsig"])
    with pytest.raises(SystemExit) as e:
        runpy.run_module("asexec", run_name="__main__")
    assert e.value.code == 0


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as e:
        run("--version")
    assert e.value.code == 0
    assert capsys.readouterr().out.startswith("asexec ")


# --- the claim record -------------------------------------------------------- #
@pytest.fixture
def claim_dir(tmp_path, monkeypatch):
    """An artifacts directory with a plan and two evidence files, signing run inside it."""
    art = tmp_path / "art"
    (art / "results").mkdir(parents=True)
    (art / "plan.md").write_text("# plan\n")
    (art / "results" / "s1.json").write_text("{}\n")
    (art / "results" / "s2.json").write_text("[]\n")
    monkeypatch.chdir(art)
    return art


def _hash_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_prereg_writes_plan_and_items(tmp_path, key, claim_dir):
    """--plan names a file (asexec hashes it and fills in hash_alg and digest), with its
    declared media_type and label; --items is the list as given."""
    pre = tmp_path / "pre.json"
    plan = '{"name": "plan.md", "media_type": "text/markdown", "label": "the plan"}'
    items = '[{"id": "S1", "kind": "run"}, {"id": "S2", "kind": "ablation"}]'
    assert run("prereg", "--key", key, "--target", "t", "--plan", plan, "--items", items,
               "--out", pre) == 0  # fmt: skip
    body = _read_body(pre)
    assert body["plan"] == {
        "name": "plan.md",
        "hash_alg": "sha-256",
        "digest": {"sha-256": _hash_file(claim_dir / "plan.md")},
        "media_type": "text/markdown",
        "label": "the plan",
    }
    assert body["items"] == [{"id": "S1", "kind": "run"}, {"id": "S2", "kind": "ablation"}]


def test_plan_items_and_evidence_from_files(tmp_path, key, claim_dir):
    (tmp_path / "plan.json").write_text('{"name": "plan.md"}')
    (tmp_path / "items.json").write_text('[{"id": "S1"}]')
    (tmp_path / "evidence.json").write_text('[{"name": "results/s1.json"}]')
    pre, post = tmp_path / "pre.json", tmp_path / "post.json"
    assert run("prereg", "--key", key, "--target", "t", "--plan-file", tmp_path / "plan.json",
               "--items-file", tmp_path / "items.json", "--out", pre) == 0  # fmt: skip
    assert run("postreg", "--key", key, "--fulfills", pre, "--evidence-file",
               tmp_path / "evidence.json", "--out", post) == 0  # fmt: skip
    assert _read_body(pre)["plan"]["name"] == "plan.md" and _read_body(pre)["items"] == [
        {"id": "S1"}
    ]
    assert [e["name"] for e in _read_body(post)["evidence"]] == ["results/s1.json"]


def test_postreg_writes_item_id_status_and_evidence(tmp_path, key, claim_dir, capsys):
    pre, post = tmp_path / "pre.json", tmp_path / "post.json"
    assert run("prereg", "--key", key, "--target", "t", "--plan", '{"name": "plan.md"}',
               "--items", '[{"id": "S1"}]', "--out", pre) == 0  # fmt: skip
    evidence = '[{"name": "results/s1.json", "media_type": "application/json", "uri": "https://e"}]'
    assert run("postreg", "--key", key, "--fulfills", pre, "--item-id", "S1", "--status",
               "excluded", "--evidence", evidence, "--hash-alg", "sha-256",
               "--out", post) == 0  # fmt: skip
    body = _read_body(post)
    assert (body["item_id"], body["status"]) == ("S1", "excluded")
    assert body["evidence"] == [
        {
            "name": "results/s1.json",
            "hash_alg": "sha-256",
            "digest": {"sha-256": _hash_file(claim_dir / "results" / "s1.json")},
            "media_type": "application/json",
            "uri": "https://e",
        }
    ]
    assert "plan" not in body and "items" not in body  # prereg fields, not inherited
    capsys.readouterr()
    tests = "format,selfsig,content"
    assert run("verify", pre, post, "--tests", tests, "--artifacts", claim_dir) == 0
    (claim_dir / "plan.md").write_text("# another plan\n")
    (claim_dir / "results" / "s1.json").write_text('{"x": 1}\n')
    capsys.readouterr()
    assert run("verify", pre, post, "--tests", tests, "--artifacts", claim_dir) == 2
    out = capsys.readouterr().out
    assert f"        {cli.NO} plan plan.md: digest mismatch" in out
    assert f"        {cli.NO} evidence results/s1.json: digest mismatch" in out


# Inline values that are wrong on their own: the arguments themselves are wrong, exit 64.
INLINE_USAGE_ERRORS = [
    pytest.param(("prereg", "--plan", "{nope"), "not valid JSON", id="plan-not-json"),
    pytest.param(("prereg", "--items", "[1,"), "not valid JSON", id="items-not-json"),
    pytest.param(("postreg", "--evidence", "not json"), "not valid JSON", id="evidence-not-json"),
    pytest.param(("postreg", "--status", "done"), "invalid choice", id="status-unknown"),
    pytest.param(("prereg", "--plan", '{"name": "plan.md"}', "--plan-file", "p.json"),
                 "not allowed", id="plan-and-file"),
    pytest.param(("prereg", "--items", "[]", "--items-file", "i.json"), "not allowed",
                 id="items-and-file"),
    pytest.param(("postreg", "--evidence", '[{"name": "plan.md"}]', "--evidence-file", "e.json"),
                 "not allowed",
                 id="evidence-and-file"),
    pytest.param(("prereg", "--plan", "[]"), "--plan must be a JSON object", id="plan-list"),
    pytest.param(("prereg", "--plan", '"plan.md"'), "--plan must be a JSON object",
                 id="plan-string"),
    pytest.param(("prereg", "--plan", '{"label": "L"}'), "needs a 'name'", id="plan-no-name"),
    pytest.param(("prereg", "--plan", '{"name": 5}'), "needs a 'name'", id="plan-name-number"),
    pytest.param(("prereg", "--plan", '{"name": "plan.md", "digest": {}}'), "fills in",
                 id="plan-digest-given"),
    pytest.param(("prereg", "--plan", '{"name": "plan.md", "colour": 1}'), "colour",
                 id="plan-unknown-field"),
    pytest.param(("prereg", "--plan", '{"name": "plan.md", "label": 5}'), "'label'",
                 id="plan-label-number"),
    pytest.param(("prereg", "--plan", '{"name": "plan.md", "name": "k.key"}'),
                 "duplicate JSON key 'name'", id="plan-duplicate-key"),
    pytest.param(("prereg", "--items", '{"id": "R1"}'), "--items must be a JSON array",
                 id="items-object"),
    pytest.param(("prereg", "--items", '[{"id": 5}]'), "a string 'id'", id="item-id-number"),
    pytest.param(("prereg", "--items", '[{"kind": "run"}]'), "a string 'id'", id="item-no-id"),
    pytest.param(("prereg", "--items", '["R1"]'), "a string 'id'", id="item-not-object"),
    pytest.param(("prereg", "--items", '[{"id": "R1"}, {"id": "R1"}]'), "'R1' twice",
                 id="item-ids-repeat"),
    pytest.param(("prereg", "--items", '[{"id": "R1", "foo": 1}]'), "'foo'",
                 id="item-unknown-field"),
    pytest.param(("prereg", "--items", '[{"id": "R1", "kind": 5}]'), "'kind'",
                 id="item-kind-number"),
    pytest.param(("prereg", "--items", '[{"id": "R1", "id": "R2"}]'), "duplicate JSON key 'id'",
                 id="item-duplicate-key"),
    pytest.param(("postreg", "--evidence", '{"name": "plan.md"}'),
                 "--evidence must be a JSON array", id="evidence-object"),
    pytest.param(("postreg", "--evidence", "[]"), "at least one", id="evidence-empty"),
    pytest.param(("postreg", "--evidence", '[{"name": "plan.md", "hash_alg": "x"}]'), "fills in",
                 id="evidence-hash_alg-given"),
    pytest.param(("postreg", "--evidence", '[{"name": "plan.md", "uri": 5}]'), "'uri'",
                 id="evidence-uri-number"),
]  # fmt: skip


@pytest.mark.parametrize("argv,message", INLINE_USAGE_ERRORS)
def test_claim_record_argument_errors_are_usage_errors(
    tmp_path, key, claim_dir, argv, message, capsys
):
    """An inline value that is invalid on its own (whatever the files hold): exit 64, the
    reason on stderr, and nothing written. Duplicate JSON keys are refused, as verify
    refuses them in a manifest."""
    cmd, *rest = argv
    link = ["--target", "t"] if cmd == "prereg" else ["--target", "t", "--fulfills", REF]
    with pytest.raises(SystemExit) as e:
        run(cmd, "--key", key, *link, *rest, "--out", tmp_path / "out.json")
    assert e.value.code == cli.EXIT_USAGE
    err = capsys.readouterr().err
    assert err.startswith("usage: ") and "error: argument" in err and message in err
    assert not (tmp_path / "out.json").exists()


_FILE_FLAGS = {"--plan": "--plan-file", "--items": "--items-file", "--evidence": "--evidence-file"}


@pytest.mark.parametrize(
    "argv,message",
    [p for p in INLINE_USAGE_ERRORS if p.values[0][1] in _FILE_FLAGS
     and "not allowed" not in p.values[1] and "duplicate JSON key" not in p.values[1]
     and "not valid JSON" not in p.values[1]],
)  # fmt: skip
def test_claim_record_file_content_errors_exit_EXIT_ERROR(
    tmp_path, key, claim_dir, argv, message, capsys
):
    """The same values from a --…-file are the file's content, not the arguments: exit 1,
    one line, nothing written."""
    cmd, flag, value = argv
    (tmp_path / "value.json").write_text(value)
    link = ["--target", "t"] if cmd == "prereg" else ["--target", "t", "--fulfills", REF]
    out = tmp_path / "out.json"
    code = run(cmd, "--key", key, *link, _FILE_FLAGS[flag], tmp_path / "value.json", "--out", out)
    assert code == cli.EXIT_ERROR
    err = capsys.readouterr().err
    assert err.startswith("error: ") and "Traceback" not in err and message in err
    assert not out.exists()


@pytest.mark.parametrize(
    "argv,message",
    [
        (("prereg", "--plan", '{"name": "results"}'), "is a directory"),
        (("prereg", "--plan", '{"name": "absent.md"}'), "absent.md"),
        (("postreg", "--evidence", '[{"name": "plan.md"}, {"name": "./plan.md"}]'), "twice"),
        (("postreg", "--evidence", '[{"name": "../plan.md"}]'), "'..'"),
    ],
    ids=["plan-directory", "plan-missing-file", "evidence-twice", "evidence-dotdot"],
)
def test_claim_record_value_errors_exit_EXIT_ERROR(tmp_path, key, claim_dir, argv, message, capsys):
    """A file a value names that cannot be signed (a directory, a missing file, two paths
    for one name, a path that is not a relative name), as for --subject: exit 1, one line,
    nothing written."""
    cmd, *rest = argv
    link = ["--target", "t"] if cmd == "prereg" else ["--target", "t", "--fulfills", REF]
    assert run(cmd, "--key", key, *link, *rest, "--out", tmp_path / "out.json") == cli.EXIT_ERROR
    err = capsys.readouterr().err
    assert err.startswith("error: ") and "Traceback" not in err and message in err
    assert not (tmp_path / "out.json").exists()


# --- timely and the no-due state --------------------------------------------- #
@pytest.fixture
def witness(monkeypatch, make_server, ceiling_for):
    """Attach a ceiling from a pinned synthetic witness (MIDP 2023-11-14T22:13:20Z, RADI 1s)
    to the manifest file at a path."""
    lt_pub, sign_response = make_server()
    monkeypatch.setitem(roughtime.SERVERS, "synthetic", {"pubkey": lt_pub})

    def attach(path):
        mani = manifest.load(str(path))
        nonce_hex = d.derive_witness_nonce(json.loads(path.read_text()))
        manifest.attach_ceiling(mani, ceiling_for(nonce_hex, "synthetic", lt_pub, sign_response))
        manifest.save(mani, str(path))

    return attach


def _make_timely_run(tmp_path, key, due, *, ceiling, witness):
    pre, post = tmp_path / "pre.json", tmp_path / "post.json"
    assert run("prereg", "--key", key, "--target", "t", "--due", due, "--out", pre) == 0
    assert run("postreg", "--key", key, "--fulfills", pre, "--out", post) == 0
    if ceiling:
        witness(post)
    return pre, post


@pytest.mark.parametrize(
    "due,ceiling,code,line",
    [
        ("2099-01-01T00:00:00Z", True, 0, None),
        (
            "2023-11-14T22:13:20Z",
            True,
            2,
            "is late: its ceiling (no later than 2023-11-14T22:13:21Z) is after due",
        ),
        ("2099-01-01T00:00:00Z", False, 2, "is not shown on time: it has no ceiling"),
    ],
    ids=["on-time", "late", "no-ceiling"],
)
def test_verify_marks_each_counted_postreg_not_shown_on_time(
    tmp_path, key, capsys, witness, due, ceiling, code, line
):
    """With timely requested, the commitments block marks each counted postreg that is not
    shown on time, and why; a late one still counts, and the commitment is fulfilled."""
    pre, post = _make_timely_run(tmp_path, key, due, ceiling=ceiling, witness=witness)
    capsys.readouterr()
    assert run("verify", pre, post, "--tests", "format,selfsig,timely") == code
    out = capsys.readouterr().out
    assert "[FULFILLED]" in out and "    postregs     : 1\n" in out
    marks = [ln for ln in out.splitlines() if ln.startswith(f"    {cli.NO} postreg ")]
    if line is None:
        assert marks == [] and "timely=PASS" in out
    else:
        assert marks == [f"    {cli.NO} postreg {_read_ref(post)} {line}"]
        assert "timely=FAIL" in out
    # not requested: no marks
    capsys.readouterr()
    run("verify", pre, post, "--tests", "format,selfsig")
    assert f"{cli.NO} postreg" not in capsys.readouterr().out


def test_verify_ceiling_trust_names_the_time_timely_compares(tmp_path, key, capsys, witness):
    pre, post = _make_timely_run(
        tmp_path, key, "2099-01-01T00:00:00Z", ceiling=True, witness=witness
    )
    capsys.readouterr()
    run("verify", pre, post, "--tests", "format,selfsig,ceiling,timely")
    out = capsys.readouterr().out
    assert "(±1.0s), so no later than 2023-11-14T22:13:21Z - you are trusting synthetic" in out


def test_verify_renders_no_due(prereg, capsys):
    """A commitment with no due and no counted postreg is NO-DUE, not OPEN."""
    run("verify", prereg, "--tests", "format,selfsig")
    out = capsys.readouterr().out
    assert "  [NO-DUE] prereg " in out and "[OPEN]" not in out


def test_verify_flags_an_unparseable_due_on_a_fulfilled_commitment(tmp_path, key, capsys):
    pre, post = tmp_path / "pre.json", tmp_path / "post.json"
    assert run("prereg", "--key", key, "--target", "t", "--out", pre) == 0
    _resign(pre, key, lambda body: body.update(due="someday"))
    assert run("postreg", "--key", key, "--fulfills", pre, "--out", post) == 0
    capsys.readouterr()
    assert run("verify", pre, post, "--tests", "format,selfsig,timely") == 2
    out = capsys.readouterr().out
    assert "[FULFILLED]" in out
    assert f"    {cli.NO} due is not a parseable ISO-8601 timestamp\n" in out


# One parse of due (verifier.parse_due) for signing and verify. The witness's time T is
# 2023-11-14T22:13:21Z (MIDP + RADI); "on-time" is T <= due, in whole microseconds.
DUE_READINGS = [
    pytest.param("2023-11-14T22:13:21Z", True, "on-time", id="z-at-T"),
    pytest.param("2023-11-14T22:13:20.999999Z", True, "late", id="one-microsecond-before-T"),
    pytest.param("2023-11-14T23:13:21+01:00", True, "on-time", id="offset-at-T"),
    pytest.param("2023-11-14T12:13:20.999999-10:00", True, "late", id="negative-offset-before-T"),
    pytest.param("2023-11-14T22:13:21.0000009Z", True, "on-time", id="sub-microsecond-truncated"),
    pytest.param("2023-11-14T22:13:20.9999999Z", True, "late", id="sub-microsecond-not-rounded-up"),
    pytest.param("2023-11-14T22:13:21", False, "naive-on-time", id="naive-read-as-utc"),
    pytest.param("2023-11-14", False, "naive-late", id="date-only-read-as-utc-midnight"),
    pytest.param("2023-11-14T22:13:21Z ", False, "invalid", id="trailing-space"),
    pytest.param("2023-11-14T22:13:21+24:00", False, "invalid", id="offset-out-of-range"),
    pytest.param("2023-02-30T00:00:00Z", False, "invalid", id="no-such-day"),
    pytest.param("someday", False, "invalid", id="words"),
    # in the grammar
    pytest.param("2023-11-15T00:00Z", True, "on-time", id="no-seconds"),
    pytest.param("2023-11-14 22:13:21Z", True, "on-time", id="space-separator"),
    pytest.param("2023-11-14T22:13:20.9Z", True, "late", id="one-fraction-digit"),
    pytest.param("2023-11-14T23:13:21+0100", True, "on-time", id="offset-without-colon"),
    pytest.param("2023-11-14T22:13:21-00:00", True, "on-time", id="minus-zero-offset"),
    # outside it, though some or every Python's fromisoformat takes it
    pytest.param("2023-11-30T24:00:00+00:00", False, "invalid", id="hour-24"),
    pytest.param("2030-01-01T12:00:00.+00:00", False, "invalid", id="empty-fraction"),
    pytest.param("2030-01-01T12.5+00:00", False, "invalid", id="fraction-of-an-hour"),
    pytest.param("2030-01-01T12:00:00.123456789xZ", False, "invalid", id="junk-in-fraction"),
    pytest.param("2030-01-01T00:00:00+05:75", False, "invalid", id="offset-minutes-75"),
    pytest.param("2030-01-01x00:00:00Z", False, "invalid", id="any-separator"),
    pytest.param("2030-01-01\ud80000:00:00Z", False, "invalid", id="surrogate-separator"),
    pytest.param("2030-01-01\n00:00:00+00:00", False, "invalid", id="newline-separator"),
    pytest.param("20300101T000000Z", False, "invalid", id="basic-format"),
    pytest.param("2030-W01-2T00:00:00Z", False, "invalid", id="week-date"),
    pytest.param("2030-01-01T00:00:00,5Z", False, "invalid", id="comma-fraction"),
    pytest.param("2030-01-01T12Z", False, "invalid", id="hour-alone"),
    pytest.param("2030-01-01T00:00:00+01", False, "invalid", id="offset-hour-alone"),
    pytest.param("2030-01-01T00:00:00Z\n", False, "invalid", id="trailing-newline"),
    pytest.param("\u0662\u0660\u0663\u0660-01-01T00:00:00Z", False, "invalid", id="other-digits"),
    pytest.param("2030-06-30T23:59:60Z", False, "invalid", id="leap-second"),
]  # fmt: skip


@pytest.mark.parametrize("due,signs,reading", DUE_READINGS)
def test_due_is_parsed_once_for_signing_and_verify(
    tmp_path, key, capsys, monkeypatch, witness, due, signs, reading
):
    """Signing takes a --due exactly when verify parses it with an offset (``parse_due`` for
    both), and verify reads each the same way: a naive due as UTC (flagged) whatever the local
    timezone, an offset applied, digits past the microsecond truncated, and an unparseable due
    named as such."""
    if not hasattr(time, "tzset"):
        pytest.skip("time.tzset is POSIX-only")
    monkeypatch.setenv("TZ", "Pacific/Kiritimati")  # UTC+14: a naive due read locally is off
    time.tzset()
    try:
        out = tmp_path / "signed.json"
        if signs:
            assert run("prereg", "--key", key, "--target", "t", "--due", due, "--out", out) == 0
            assert _read_body(out)["due"] == due  # written verbatim
        else:
            with pytest.raises(SystemExit) as e:
                run("prereg", "--key", key, "--target", "t", "--due", due, "--out", out)
            assert e.value.code == cli.EXIT_USAGE
            assert "error: argument --due: " in capsys.readouterr().err
        # verify reads the same string, signed as anyone could
        pre, post = tmp_path / "pre.json", tmp_path / "post.json"
        _sign_stored_bytes(pre, key, json.dumps({"phase": "prereg", "target": "t", "due": due,
                                                 "predicateType": "x"}).encode())  # fmt: skip
        body = {"phase": "postreg", "target": "t", "fulfills": _read_ref(pre), "predicateType": "x"}
        _sign_stored_bytes(post, key, json.dumps(body).encode())
        witness(post)
        capsys.readouterr()
        code = run("verify", pre, post, "--tests", "format,selfsig,timely")
        report = capsys.readouterr().out
    finally:
        monkeypatch.undo()
        time.tzset()
    naive_line = (
        f"    {cli.NO} due has no timezone; read as UTC (re-sign with an explicit offset)\n"
    )
    invalid_line = f"    {cli.NO} due is not a parseable ISO-8601 timestamp\n"
    assert (naive_line in report) == reading.startswith("naive")
    assert (invalid_line in report) == (reading == "invalid")
    assert ("is late: its ceiling (no later than 2023-11-14T22:13:21Z)" in report) == (
        reading.endswith("late")
    )
    assert code == (0 if reading.endswith("on-time") else 2)


# --- complete ---------------------------------------------------------------------- #
def _make_claim(tmp_path, key, due, witness, *, items=("R1", "R2"), posts=("R1", "R2")):
    """A prereg listing ``items``, and one chained, witnessed postreg per id in ``posts``."""
    pre = tmp_path / "pre.json"
    listed = json.dumps([{"id": i, "kind": "run"} for i in items])
    assert run("prereg", "--key", key, "--target", "t", "--due", due, "--items", listed,
               "--out", pre) == 0  # fmt: skip
    prev, out = None, []
    for i in posts:
        post = tmp_path / f"post-{i}.json"
        args = ["--prev", prev] if prev else []
        assert run("postreg", "--key", key, "--fulfills", pre, "--item-id", i, "--status",
                   "reported", *args, "--out", post) == 0  # fmt: skip
        witness(post)
        prev = post
        out.append(post)
    return pre, out


_LATE = "reported, but not shown on time: its postreg is late"


@pytest.mark.parametrize(
    "due,posts,code,lines",
    [
        ("2099-01-01T00:00:00Z", ("R1", "R2"), 0, [f"{cli.OK} R1: reported",
                                               f"{cli.OK} R2: reported"]),
        ("2099-01-01T00:00:00Z", ("R1",), 2, [f"{cli.OK} R1: reported",
                                          f"{cli.NO} R2: no counted postreg names it"]),
        ("2023-11-14T22:13:20Z", ("R1", "R2"), 2, [f"{cli.NO} R1: {_LATE}",
                                               f"{cli.NO} R2: {_LATE}"]),
    ],
    ids=["complete", "dropped-item", "late-items"],
)  # fmt: skip
def test_verify_shows_each_items_status(tmp_path, key, capsys, witness, due, posts, code, lines):
    """The commitments block lists each item with its status, or why it is not accounted
    for; complete passes only when every item is."""
    pre, out = _make_claim(tmp_path, key, due, witness, posts=posts)
    capsys.readouterr()
    assert run("verify", pre, *out, "--tests", "format,selfsig,complete") == code
    text = capsys.readouterr().out
    assert "    items        : 2\n" in text
    assert [ln.strip() for ln in text.splitlines() if ln.startswith("      ")] == lines
    assert ("complete=PASS" if code == 0 else "complete=FAIL") in text


def test_verify_shows_a_postreg_for_an_unlisted_item(tmp_path, key, capsys, witness):
    pre, out = _make_claim(
        tmp_path, key, "2099-01-01T00:00:00Z", witness, items=("R1",), posts=("R1", "Z9")
    )
    capsys.readouterr()
    assert run("verify", pre, *out, "--tests", "format,selfsig,complete") == 0
    text = capsys.readouterr().out
    ref = _read_ref(out[1])
    line = f"    {cli.NO} postreg {ref} names item 'Z9', which the prereg does not list\n"
    assert line in text


def test_verify_shows_a_witness_time_past_year_9999_as_epoch_seconds(
    tmp_path, key, capsys, monkeypatch, make_server, ceiling_for
):
    """The report never fails to print a time: one with no ISO-8601 form (here 2**62 us)
    is shown as epoch seconds."""
    lt_pub, sign_response = make_server(midpoint_us=2**62, maxt=2**63)
    monkeypatch.setitem(roughtime.SERVERS, "synthetic", {"pubkey": lt_pub})
    pre, post = tmp_path / "pre.json", tmp_path / "post.json"
    assert run("prereg", "--key", key, "--target", "t", "--due", "2099-01-01T00:00:00Z",
               "--out", pre) == 0  # fmt: skip
    assert run("postreg", "--key", key, "--fulfills", pre, "--out", post) == 0
    mani = manifest.load(str(post))
    nonce_hex = d.derive_witness_nonce(json.loads(post.read_text()))
    manifest.attach_ceiling(mani, ceiling_for(nonce_hex, "synthetic", lt_pub, sign_response))
    manifest.save(mani, str(post))
    capsys.readouterr()
    assert run("verify", pre, post, "--tests", "format,selfsig,ceiling,timely") == 2
    out = capsys.readouterr().out
    assert "is late: its ceiling (no later than 4611686018429 (epoch seconds)) is after due" in out
    assert "so no later than 4611686018429 (epoch seconds)" in out


@pytest.mark.parametrize(
    "flag,content,key_name",
    [
        ("--plan-file", '{"name": "plan.md", "name": "k.key"}', "name"),
        ("--items-file", '[{"id": "R1", "id": "R2"}]', "id"),
        ("--evidence-file", '[{"name": "plan.md", "name": "k.key"}]', "name"),
    ],
    ids=["plan-file", "items-file", "evidence-file"],
)
def test_claim_record_file_with_a_duplicate_key_exits_EXIT_ERROR(
    tmp_path, key, claim_dir, flag, content, key_name, capsys
):
    """A --plan-file, --items-file or --evidence-file whose JSON repeats a key is refused, as
    an inline value is: parsers disagree on which value wins. It is the file's content, so
    exit 1, and nothing is hashed or written."""
    (claim_dir / "k.key").write_text("secret")
    (tmp_path / "value.json").write_text(content)
    cmd = "postreg" if flag == "--evidence-file" else "prereg"
    link = ["--target", "t"] if cmd == "prereg" else ["--target", "t", "--fulfills", REF]
    out = tmp_path / "out.json"
    assert run(cmd, "--key", key, *link, flag, tmp_path / "value.json", "--out", out) == 1
    err = capsys.readouterr().err
    assert err.startswith("error: ") and f"duplicate JSON key {key_name!r}" in err
    assert not out.exists()


# --- untrusted and unknown fields (#34) -------------------------------------- #
UNTRUSTED_HEADING = "=== untrusted (unsigned, and read by no test: nothing here was checked) ==="
UNKNOWN_HEADING = (
    "=== unknown fields (signed, but this format does not define them: nothing here was "
    "checked) ==="
)


def _get_block(out, heading):
    """The lines of the report block under ``heading``, up to the blank line after it."""
    return out.split(heading + "\n")[1].split("\n\n")[0].splitlines()


@pytest.mark.parametrize("cmd", ["prereg", "postreg"])
def test_signing_writes_untrusted_asexec_version(tmp_path, key, prereg, cmd):
    """Signing writes untrusted.asexec_version, the installed release, in the wrapper: outside
    the body, so outside the signature and ref."""
    out = tmp_path / "out.json"
    link = ["--target", "t"] if cmd == "prereg" else ["--fulfills", prereg]
    assert run(cmd, "--key", key, *link, "--out", out) == 0
    mani = manifest.load(str(out))
    assert list(mani) == ["dsse", "pubkey", "untrusted"]
    assert mani["untrusted"] == {"asexec_version": asexec.__version__}
    assert "untrusted" not in _read_body(out) and "asexec_version" not in _read_body(out)


def test_verify_shows_untrusted_and_unknown_fields_under_their_own_headings(
    tmp_path, key, prereg, capsys
):
    """untrusted and any key outside the body this format does not define are shown under one
    heading, saying nothing in them was checked; unknown body fields under another. Each value
    is shown as JSON, and the code is the same as without them."""
    _resign(prereg, key, lambda body: body.update(colour="red"))
    run("verify", prereg, "--tests", "format,selfsig")
    before = capsys.readouterr().out.splitlines()[-2]
    mani = manifest.load(prereg)
    mani["untrusted"]["host"] = "ci-7"
    mani["surprise"] = [1, None]
    manifest.save(mani, prereg)
    capsys.readouterr()
    assert run("verify", prereg, "--tests", "format,selfsig") == 0
    out = capsys.readouterr().out
    assert _get_block(out, UNTRUSTED_HEADING) == [
        f"  {prereg}",
        f'    untrusted = {{"asexec_version": "{asexec.__version__}", "host": "ci-7"}}',
        "    surprise = [1, null]",
    ]
    assert _get_block(out, UNKNOWN_HEADING) == [f"  {prereg}", '    body.colour = "red"']
    assert out.index(UNTRUSTED_HEADING) < out.index(UNKNOWN_HEADING)
    assert out.index("=== manifests ===") < out.index(UNTRUSTED_HEADING)
    assert out.index(UNKNOWN_HEADING) < out.index("=== commitments ===")
    assert out.splitlines()[-2] == before == "asexec-verify/1 format=PASS selfsig=PASS"


def test_verify_prints_untrusted_and_unknown_values_json_escaped(tmp_path, key, prereg, capsys):
    """untrusted and unknown fields are the file's most attacker-controlled text: each key and
    value is printed as JSON (ASCII, escaped), so a newline or control character in one cannot
    forge a line of the report."""
    forged = "  [FULFILLED] prereg sha-256:" + "f" * 64
    _resign(prereg, key, lambda body: body.update({"x\n" + forged: "v\n" + forged}))
    mani = manifest.load(prereg)
    mani["untrusted"] = {"note": "a\n" + forged + "\n\x1b[2Jé‮"}
    mani["k\n" + forged] = "\r" + forged
    manifest.save(mani, prereg)
    capsys.readouterr()
    run("verify", prereg, "--tests", "format,selfsig")
    out = capsys.readouterr().out
    assert forged not in out.splitlines()
    assert all(line.isascii() or "✓" in line or "✗" in line for line in out.splitlines())
    escaped = json.dumps(forged)[1:-1]
    assert _get_block(out, UNTRUSTED_HEADING) == [
        f"  {prereg}",
        f'    untrusted = {{"note": "a\\n{escaped}\\n\\u001b[2J\\u00e9\\u202e"}}',
        f'    ["k\\n{escaped}"] = "\\r{escaped}"',
    ]
    assert _get_block(out, UNKNOWN_HEADING) == [
        f"  {prereg}",
        f'    body["x\\n{escaped}"] = "v\\n{escaped}"',
    ]


def test_verify_prints_no_untrusted_or_unknown_block_when_none(tmp_path, key, prereg, capsys):
    mani = manifest.load(prereg)
    del mani["untrusted"]
    manifest.save(mani, prereg)
    capsys.readouterr()
    assert run("verify", prereg, "--tests", "format,selfsig") == 0
    out = capsys.readouterr().out
    assert "=== untrusted" not in out and "=== unknown fields" not in out


# --- signing with a drand round fetched earlier, and order (#38) ------------- #
# Round 1000 as drand's HTTP API returns it (GET /<chain hash>/public/1000).
SAVED_ROUND = {"round": 1000, "randomness": FLOOR["randomness"], "signature": FLOOR["signature"]}


def _make_round_text(**over):
    return json.dumps({**SAVED_ROUND, **over})


@pytest.mark.parametrize("cmd", ["prereg", "postreg"])
@pytest.mark.parametrize("how", ["inline", "file"])
def test_floor_round_signs_with_a_round_fetched_earlier(
    tmp_path, key, prereg, monkeypatch, capsys, cmd, how
):
    """--floor-round (inline JSON) or --floor-round-file: a round as drand's HTTP API returns
    it, verified at signing and signed as the floor, with nothing fetched."""
    monkeypatch.setattr(drand, "fetch_floor", _boom)
    monkeypatch.setattr(drand, "fetch_latest_round", _boom)
    if how == "inline":
        given = ["--floor-round", json.dumps(SAVED_ROUND)]
    else:
        (tmp_path / "round.json").write_text(json.dumps(SAVED_ROUND))
        given = ["--floor-round-file", tmp_path / "round.json"]
    link = ["--target", "t"] if cmd == "prereg" else ["--fulfills", prereg]
    out = tmp_path / "out.json"
    assert run(cmd, "--key", key, *link, *given, "--out", out) == 0
    assert _read_body(out)["anchor"] == {"floor": FLOOR}
    if (cmd, how) == ("postreg", "file"):  # the floor written is the one verify reads (BLS: ~1 s)
        capsys.readouterr()
        assert run("verify", out, "--tests", "format,selfsig,floor") == 0
        assert "floor=PASS format=PASS selfsig=PASS" in capsys.readouterr().out


# A --floor-round value that is wrong on its own: the arguments themselves are wrong, exit 64.
FLOOR_ROUND_USAGE_ERRORS = [
    pytest.param("{nope", "not valid JSON", id="not-json"),
    pytest.param('{"round": 1000, "round": 1000}', "duplicate JSON key 'round'",
                 id="duplicate-key"),
    pytest.param("[]", "--floor-round must be a JSON object", id="a-list"),
    pytest.param(json.dumps({"round": 1000, "signature": FLOOR["signature"]}),
                 "missing 'randomness'", id="no-randomness"),
    pytest.param(_make_round_text(previous_signature="00"), "'previous_signature'",
                 id="unknown-field"),
    pytest.param(_make_round_text(chain_hash=drand.QUICKNET_HASH), "'chain_hash'",
                 id="chain-hash-given"),
    pytest.param(_make_round_text(round="1000"), "'round' must be an integer", id="round-a-string"),
    pytest.param(_make_round_text(round=1000.0), "'round' must be an integer", id="round-a-float"),
    pytest.param(_make_round_text(round=True), "'round' must be an integer", id="round-a-bool"),
    pytest.param(_make_round_text(signature=FLOOR["signature"].upper()),
                 "'signature' must be lowercase hex", id="signature-uppercase"),
    pytest.param(_make_round_text(randomness=5), "'randomness' must be lowercase hex",
                 id="randomness-a-number"),
    pytest.param(_make_round_text(round=1001), "does not verify", id="another-rounds-signature"),
    pytest.param(_make_round_text(randomness="00" * 32), "does not verify", id="randomness-wrong"),
]  # fmt: skip


@pytest.mark.parametrize("value,message", FLOOR_ROUND_USAGE_ERRORS)
def test_floor_round_argument_errors_are_usage_errors(tmp_path, key, value, message, capsys):
    """An inline --floor-round that is not a round of the pinned chain that verifies, whatever
    the files hold: exit 64, the reason on stderr, nothing written. --best-effort does not
    sign without it: there is no fetch to fail."""
    out = tmp_path / "out.json"
    with pytest.raises(SystemExit) as e:
        run("prereg", "--key", key, "--target", "t", "--floor-round", value, "--best-effort",
            "--out", out)  # fmt: skip
    assert e.value.code == cli.EXIT_USAGE
    err = capsys.readouterr().err
    assert err.startswith("usage: ") and "error: argument --floor-round: " in err
    assert message in err
    assert not out.exists()


@pytest.mark.parametrize(
    "value,message",
    [p for p in FLOOR_ROUND_USAGE_ERRORS if p.id != "not-json"]
    + [pytest.param("{nope", "must contain valid JSON", id="not-json")],
)
def test_floor_round_file_content_errors_exit_EXIT_ERROR(tmp_path, key, value, message, capsys):
    """The same values from --floor-round-file are the file's content: exit 1, one line,
    nothing written."""
    (tmp_path / "round.json").write_text(value)
    out = tmp_path / "out.json"
    code = run("prereg", "--key", key, "--target", "t", "--floor-round-file",
               tmp_path / "round.json", "--out", out)  # fmt: skip
    assert code == cli.EXIT_ERROR
    err = capsys.readouterr().err
    assert err.startswith("error: ") and "Traceback" not in err and message in err
    assert not out.exists()


def test_floor_round_file_not_found_exits_EXIT_ERROR(tmp_path, key, capsys):
    with pytest.raises(SystemExit) as e:
        run("prereg", "--key", key, "--target", "t", "--floor-round-file", tmp_path / "none",
            "--out", tmp_path / "out.json")  # fmt: skip
    assert "--floor-round-file not found" in str(e.value)


@pytest.mark.parametrize(
    "given",
    [
        ("--floor", "--floor-round", json.dumps(SAVED_ROUND)),
        ("--floor", "--floor-round-file", "round.json"),
        ("--floor-round", json.dumps(SAVED_ROUND), "--floor-round-file", "round.json"),
    ],
    ids=["floor-and-floor-round", "floor-and-file", "floor-round-and-file"],
)
def test_floor_round_excludes_floor(tmp_path, key, given, capsys):
    """--floor fetches the latest round, and --floor-round gives one: at most one of them."""
    with pytest.raises(SystemExit) as e:
        run("prereg", "--key", key, "--target", "t", *given, "--out", tmp_path / "out.json")
    assert e.value.code == cli.EXIT_USAGE
    assert "not allowed with argument" in capsys.readouterr().err


@pytest.fixture
def witness_at(monkeypatch, make_server, ceiling_for):
    """``witness_at(midpoint_us)(path)``: attach a ceiling from a pinned synthetic witness that
    signs ``midpoint_us`` (RADI 1 s) to the manifest file at ``path``."""

    def make_attacher(midpoint_us):
        lt_pub, sign_response = make_server(midpoint_us=midpoint_us)
        monkeypatch.setitem(roughtime.SERVERS, "synthetic", {"pubkey": lt_pub})

        def attach(path):
            mani = manifest.load(str(path))
            nonce_hex = d.derive_witness_nonce(json.loads(path.read_text()))
            record = ceiling_for(nonce_hex, "synthetic", lt_pub, sign_response)
            manifest.attach_ceiling(mani, record)
            manifest.save(mani, str(path))

        return attach

    return make_attacher


_ROUND_1000_US = 1_692_806_364_000_000  # 2023-08-23T15:59:24Z
_NOT_AFTER = "is not shown after the pre-registration"


@pytest.mark.parametrize(
    "midpoint_us,prereg_ceiling,floor,code,line",
    [
        (_ROUND_1000_US - 10_000_000, True, True, 0, None),
        (
            1_700_000_000_000_000,
            True,
            True,
            2,
            f"{_NOT_AFTER}: its floor (no earlier than 2023-08-23T15:59:24Z) is not after "
            "the pre-registration's ceiling (no later than 2023-11-14T22:13:21Z)",
        ),
        (_ROUND_1000_US - 10_000_000, False, True, 2, None),
        (_ROUND_1000_US - 10_000_000, True, False, 2, f"{_NOT_AFTER}: it has no floor"),
    ],
    ids=["ordered", "floor-before-the-prereg-ceiling", "no-prereg-ceiling", "no-floor"],
)
def test_verify_marks_each_counted_postreg_not_shown_after_its_prereg(
    tmp_path, key, capsys, witness_at, midpoint_us, prereg_ceiling, floor, code, line
):
    """With order requested, the commitments block marks each counted postreg not shown after
    its prereg and why, and a prereg whose ceiling gives no time; without it, no mark."""
    pre, post = tmp_path / "pre.json", tmp_path / "post.json"
    assert run("prereg", "--key", key, "--target", "t", "--out", pre) == 0
    given = ["--floor-round", json.dumps(SAVED_ROUND)] if floor else []
    assert run("postreg", "--key", key, "--fulfills", pre, *given, "--out", post) == 0
    if prereg_ceiling:
        witness_at(midpoint_us)(pre)
    capsys.readouterr()
    assert run("verify", pre, post, "--tests", "format,selfsig,order") == code
    out = capsys.readouterr().out
    commitments = out.split("=== commitments ===\n")[1].split("\n\n")[0].splitlines()
    marks = [m for m in commitments if m.startswith(f"    {cli.NO}")]
    if not prereg_ceiling:
        assert marks == [
            f"    {cli.NO} the pre-registration is not shown before its postregs: it has no ceiling"
        ]
    else:
        assert marks == ([f"    {cli.NO} postreg {_read_ref(post)} {line}"] if line else [])
    assert f"order={'PASS' if code == 0 else 'FAIL'}" in out
    if line and floor:  # without order requested, no mark (BLS: ~1 s a run)
        capsys.readouterr()
        run("verify", pre, post, "--tests", "format,selfsig")
        assert "not shown" not in capsys.readouterr().out
