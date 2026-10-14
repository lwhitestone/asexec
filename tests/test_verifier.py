"""The verifier: states, tamper detection, content, chains, and the canonical
verify CODE — all offline."""

import json

import pytest

from asexec import drand, hashing, keys, manifest
from asexec.errors import VerificationError
from asexec.verifier import parse_tests, verify_paths


# --------------------------------------------------------------------------- #
# --tests parsing / gating
# --------------------------------------------------------------------------- #
def test_BDR_required_in_tests():
    with pytest.raises(VerificationError):
        parse_tests("floor,content")


def test_unknown_test_rejected():
    with pytest.raises(VerificationError):
        parse_tests("BDR,nope")


def test_empty_tests_rejected():
    with pytest.raises(VerificationError):
        parse_tests("")


def test_parse_tests_is_catalog_ordered_and_deduped():
    assert parse_tests("floor,BDR,floor") == ["BDR", "floor"]


# --------------------------------------------------------------------------- #
# canonical code
# --------------------------------------------------------------------------- #
def test_code_is_alphabetical_and_byte_identical(make_commitment):
    commit = make_commitment(n_receipts=1)
    r1 = verify_paths(
        [commit["prereg"]] + commit["receipts"], ["BDR", "chain"], artifacts_dir=commit["artifacts"]
    )
    # request the SAME tests in a different order -> identical code
    r2 = verify_paths(
        [commit["prereg"]] + commit["receipts"], ["chain", "BDR"], artifacts_dir=commit["artifacts"]
    )
    assert r1["code"] == r2["code"]
    assert r1["code"] == "asexec-verify/1 BDR=PASS chain=PASS"


def test_BDR_only_is_a_complete_statement(make_commitment):
    commit = make_commitment(n_receipts=1)
    report = verify_paths([commit["prereg"]] + commit["receipts"], ["BDR"])
    assert report["code"] == "asexec-verify/1 BDR=PASS"
    assert report["ok"] is True


def test_requested_but_absent_is_fail_not_omission(make_commitment):
    # no floor was embedded (offline fixtures), so `floor` applies nowhere -> FAIL.
    commit = make_commitment(n_receipts=1)
    report = verify_paths(
        [commit["prereg"]] + commit["receipts"], ["BDR", "floor"], artifacts_dir=commit["artifacts"]
    )
    assert report["results"]["floor"]["result"] == "FAIL"
    assert report["results"]["floor"]["applicable"] == 0
    assert report["code"] == "asexec-verify/1 BDR=PASS floor=FAIL"
    assert report["ok"] is False


def test_content_without_artifacts_is_fail(make_commitment):
    commit = make_commitment(n_receipts=1)
    report = verify_paths(
        [commit["prereg"]] + commit["receipts"], ["BDR", "content"]
    )  # no artifacts_dir
    assert report["results"]["content"]["result"] == "FAIL"
    assert report["results"]["content"]["applicable"] == 0


# --------------------------------------------------------------------------- #
# states + tamper/content/chain/key (aggregated into the code)
# --------------------------------------------------------------------------- #
def test_fulfilled(make_commitment):
    commit = make_commitment(n_receipts=1)
    rep = verify_paths(
        [commit["prereg"]] + commit["receipts"],
        ["BDR", "content", "chain", "keyconsist"],
        artifacts_dir=commit["artifacts"],
    )
    assert rep["ok"] is True
    assert rep["commitments"][0]["state"] == "fulfilled"
    assert rep["code"] == "asexec-verify/1 BDR=PASS chain=PASS content=PASS keyconsist=PASS"


def test_open_when_window_future_and_no_receipt(make_commitment):
    commit = make_commitment(due="2099-01-01T00:00:00Z", n_receipts=0)
    rep = verify_paths([commit["prereg"]], ["BDR"])
    assert rep["commitments"][0]["state"] == "open"
    assert rep["ok"] is True


def test_elapsed_no_receipt(make_commitment):
    commit = make_commitment(due="2000-01-01T00:00:00Z", n_receipts=0)
    rep = verify_paths([commit["prereg"]], ["BDR"])
    assert rep["commitments"][0]["state"] == "elapsed-no-receipt"


def test_notarization_only(make_commitment):
    commit = make_commitment(n_receipts=1)
    rep = verify_paths(commit["receipts"], ["BDR"])
    assert rep["notarization_only"]
    assert rep["commitments"] == []


def test_tampered_receipt_fails_BDR(make_commitment):
    commit = make_commitment(n_receipts=1)
    rp = commit["receipts"][0]
    mani = json.loads(open(rp).read())
    mani["payload"]["target"]["model_id"] = "SWAPPED"  # alter signed content
    open(rp, "w").write(json.dumps(mani))
    rep = verify_paths([commit["prereg"], rp], ["BDR"], artifacts_dir=commit["artifacts"])
    assert rep["ok"] is False
    assert rep["results"]["BDR"]["result"] == "FAIL"
    sigs = {item["path"]: item["signature"]["signature_ok"] for item in rep["manifests"]}
    assert sigs[rp] is False


def test_content_mismatch_detected(make_commitment):
    commit = make_commitment(n_receipts=1)
    import os

    open(os.path.join(commit["artifacts"], "harness", "eval.py"), "w").write("TAMPERED\n")
    rep = verify_paths(
        [commit["prereg"]] + commit["receipts"],
        ["BDR", "content"],
        artifacts_dir=commit["artifacts"],
    )
    assert rep["results"]["content"]["result"] == "FAIL"
    assert any(mani["content"]["status"] == "mismatch" for mani in rep["manifests"])


def test_chain_gap_detected(make_commitment):
    commit = make_commitment(n_receipts=2)
    rep = verify_paths(
        [commit["prereg"], commit["receipts"][1]],
        ["BDR", "chain"],
        artifacts_dir=commit["artifacts"],
    )
    assert rep["commitments"][0]["chain_ok"] is False
    assert rep["results"]["chain"]["result"] == "FAIL"


def test_receipts_from_wrong_key_flagged(make_commitment):
    commit = make_commitment(n_receipts=1)
    other_priv, other_pub = keys.generate()
    body = manifest.get_body(manifest.load(commit["receipts"][0]))
    manifest.save(manifest.sign(body, other_priv, other_pub), commit["receipts"][0])
    rep = verify_paths(
        [commit["prereg"]] + commit["receipts"],
        ["BDR", "keyconsist"],
        artifacts_dir=commit["artifacts"],
    )
    assert rep["commitments"][0]["key_consistent"] is False
    assert rep["results"]["keyconsist"]["result"] == "FAIL"


# --------------------------------------------------------------------------- #
# 0.3.15 soundness regressions
# --------------------------------------------------------------------------- #
def _resign(path, priv, pub, mutate=None):
    """Re-sign the body at ``path`` (optionally mutated) with the given key."""
    body = manifest.get_body(manifest.load(path))
    if mutate:
        mutate(body)
    manifest.save(manifest.sign(body, priv, pub), path)
    return body


def test_postreg_by_other_key_does_not_fulfill(make_commitment):
    commit = make_commitment(n_receipts=1)
    other_priv, other_pub = keys.generate()
    _resign(commit["receipts"][0], other_priv, other_pub)
    rep = verify_paths([commit["prereg"]] + commit["receipts"], ["BDR", "keyconsist"])
    cm = rep["commitments"][0]
    assert cm["state"] != "fulfilled"
    assert cm["receipts"] == []
    assert len(cm["rejected_receipts"]) == 1
    assert "different key" in cm["rejected_receipts"][0]["reason"]
    assert rep["results"]["keyconsist"]["result"] == "FAIL"


def test_postreg_with_invalid_signature_does_not_fulfill(make_commitment):
    commit = make_commitment(n_receipts=1)
    rp = commit["receipts"][0]
    mani = json.loads(open(rp).read())
    mani["payload"]["target"]["model_id"] = "SWAPPED"  # signature no longer matches
    open(rp, "w").write(json.dumps(mani))
    rep = verify_paths([commit["prereg"], rp], ["BDR"])
    cm = rep["commitments"][0]
    assert cm["state"] != "fulfilled"
    assert cm["receipts"] == []
    assert "invalid signature" in cm["rejected_receipts"][0]["reason"]
    assert rep["results"]["BDR"]["result"] == "FAIL"


def test_forked_chain_fails(make_commitment):
    commit = make_commitment(n_receipts=2)
    # receipt1 currently points at receipt0; make a sibling that also does.
    sibling = commit["tmp"] / "sibling.json"
    body = manifest.get_body(manifest.load(commit["receipts"][1]))
    body["notes"] = "fork"
    manifest.save(manifest.sign(body, commit["priv"], commit["pub"]), str(sibling))
    rep = verify_paths(
        [commit["prereg"], *commit["receipts"], str(sibling)], ["BDR", "chain", "keyconsist"]
    )
    assert rep["commitments"][0]["chain_ok"] is False
    assert "fork" in rep["commitments"][0]["chain_note"]
    assert rep["results"]["chain"]["result"] == "FAIL"


def test_linear_chain_still_passes(make_commitment):
    commit = make_commitment(n_receipts=3)
    rep = verify_paths([commit["prereg"], *commit["receipts"]], ["BDR", "chain"])
    assert rep["results"]["chain"]["result"] == "PASS"


def _escape_setup(make_commitment, name):
    """A prereg whose subject name escapes --artifacts, with a matching outside file."""
    commit = make_commitment(n_receipts=0)
    outside = commit["tmp"] / "secret.txt"
    outside.write_text("outside\n")
    from asexec import hashing

    digest = hashing.hash_file(str(outside))
    subj = [{"name": name.format(outside=outside), "digest": {"sha-256": digest}}]
    body = manifest.build_prereg({"k": "v"}, subject=subj)
    path = commit["tmp"] / "escape.json"
    manifest.save(manifest.sign(body, commit["priv"], commit["pub"]), str(path))
    return commit, str(path)


@pytest.mark.parametrize("name", ["../secret.txt", "{outside}", "harness/../../secret.txt"])
def test_content_cannot_escape_artifacts_dir(make_commitment, name):
    commit, path = _escape_setup(make_commitment, name)
    rep = verify_paths([path], ["BDR", "content"], artifacts_dir=commit["artifacts"])
    assert rep["results"]["content"]["result"] == "FAIL"
    entry = rep["manifests"][0]["content"]["entries"][0]
    assert entry["ok"] is False
    assert "outside" in entry["reason"]


def test_content_rejects_symlink_escape(make_commitment, tmp_path):
    commit, _ = _escape_setup(make_commitment, "x")
    link = tmp_path / "artifacts" / "link.txt"
    try:
        link.symlink_to(tmp_path / "secret.txt")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this platform")

    subj = [{"name": "link.txt", "digest": {"sha-256": hashing.hash_file(str(link))}}]
    body = manifest.build_prereg({"k": "v"}, subject=subj)
    path = tmp_path / "link.json"
    manifest.save(manifest.sign(body, commit["priv"], commit["pub"]), str(path))
    rep = verify_paths([str(path)], ["BDR", "content"], artifacts_dir=commit["artifacts"])
    assert rep["results"]["content"]["result"] == "FAIL"


def test_duplicate_json_keys_rejected(make_commitment):
    commit = make_commitment(n_receipts=0)
    raw = open(commit["prereg"]).read()
    # inject a second "phase" key into the payload (last would win)
    dup = raw.replace('"phase": "prereg"', '"phase": "prereg", "phase": "postreg"', 1)
    assert dup != raw
    open(commit["prereg"], "w").write(dup)
    rep = verify_paths([commit["prereg"]], ["BDR"])
    assert rep["results"]["BDR"]["result"] == "FAIL"
    assert "duplicate" in rep["manifests"][0]["signature"]["errors"][0]


def _bad_sig_envelope(payload):
    return '{"payload": ' + payload + ', "signature": {"pubkey": "00", "sig": "00"}}'


MALFORMED = {
    "empty": "",
    "not-json": "{nope",
    "array": "[1, 2]",
    "string": '"x"',
    "null": "null",
    "payload-list": '{"payload": [], "signature": {}}',
    "payload-str": '{"payload": "x", "signature": {}}',
    "signature-str": '{"payload": {}, "signature": "x"}',
    "bad-hex": '{"payload": {"phase": "prereg"}, "signature": {"pubkey": "zz", "sig": "zz"}}',
    "bad-subject": _bad_sig_envelope('{"phase": "prereg", "subject": [1]}'),
    "unhashable-fulfills": _bad_sig_envelope('{"phase": "postreg", "fulfills": []}'),
}


@pytest.mark.parametrize("raw", MALFORMED.values(), ids=MALFORMED.keys())
def test_malformed_input_is_per_file_failure(make_commitment, tmp_path, raw):
    commit = make_commitment(n_receipts=1)
    bad = tmp_path / "bad.json"
    bad.write_text(raw)
    tests = ["BDR", "chain", "content", "keyconsist"]
    rep = verify_paths(
        [commit["prereg"], *commit["receipts"], str(bad)], tests, commit["artifacts"]
    )
    assert rep["results"]["BDR"]["result"] == "FAIL"
    assert rep["ok"] is False
    assert rep["code"].startswith("asexec-verify/1 BDR=FAIL")


def test_binary_and_missing_files_are_per_file_failures(make_commitment, tmp_path):
    commit = make_commitment(n_receipts=0)
    binf = tmp_path / "bin.json"
    binf.write_bytes(b"\xff\xfe\x00")
    rep = verify_paths([commit["prereg"], str(binf), str(tmp_path / "missing.json")], ["BDR"])
    assert rep["results"]["BDR"]["result"] == "FAIL"
    assert len(rep["manifests"]) == 3


def test_unknown_hash_alg_fails_entry_not_crash(make_commitment):
    commit = make_commitment(n_receipts=0)
    body = manifest.get_body(manifest.load(commit["prereg"]))
    body["hash_alg"] = "blake9"
    body["subject"][0]["digest"] = {"blake9": "00"}
    manifest.save(manifest.sign(body, commit["priv"], commit["pub"]), commit["prereg"])
    rep = verify_paths([commit["prereg"]], ["BDR", "content"], artifacts_dir=commit["artifacts"])
    assert rep["results"]["content"]["result"] == "FAIL"
    entry = rep["manifests"][0]["content"]["entries"][0]
    assert "algorithm unavailable" in entry["reason"]


def _prereg_with_due(commit, due):
    body = manifest.get_body(manifest.load(commit["prereg"]))
    body["due"] = due
    manifest.save(manifest.sign(body, commit["priv"], commit["pub"]), commit["prereg"])


def test_unparseable_due_renders_invalid_due(make_commitment):
    commit = make_commitment(n_receipts=0)
    _prereg_with_due(commit, "next tuesday")
    cm = verify_paths([commit["prereg"]], ["BDR"])["commitments"][0]
    assert cm["state"] == "invalid-due"


def test_non_string_due_renders_invalid_due(make_commitment):
    commit = make_commitment(n_receipts=0)
    _prereg_with_due(commit, 12345)
    cm = verify_paths([commit["prereg"]], ["BDR"])["commitments"][0]
    assert cm["state"] == "invalid-due"


def test_naive_due_is_flagged_and_timezone_independent(make_commitment, monkeypatch):
    import datetime
    import time

    commit = make_commitment(n_receipts=0)
    _prereg_with_due(commit, "2026-01-01T12:00:00")
    now = datetime.datetime(2026, 1, 1, 12, 30, tzinfo=datetime.UTC).timestamp()
    states = set()
    try:
        for tz in ("UTC", "Pacific/Kiritimati", "Pacific/Pago_Pago"):
            monkeypatch.setenv("TZ", tz)
            time.tzset()
            cm = verify_paths([commit["prereg"]], ["BDR"], now=now)["commitments"][0]
            assert cm["due_naive"] is True
            states.add(cm["state"])
    finally:
        monkeypatch.undo()  # restore TZ, then re-sync libc so later tests aren't affected
        time.tzset()
    assert states == {"elapsed-no-receipt"}


def test_aware_due_is_not_flagged(make_commitment):
    commit = make_commitment(due="2099-01-01T00:00:00Z", n_receipts=0)
    cm = verify_paths([commit["prereg"]], ["BDR"])["commitments"][0]
    assert cm["due_naive"] is False
    assert cm["state"] == "open"


@pytest.mark.parametrize(
    "field,value",
    [
        ("anchor", "x"),
        ("anchor", {"floor": "x"}),
        ("anchor", {"floor": {"round": "nope", "signature": 5}}),
        ("subject", "x"),
        ("subject", [{"name": 3}]),
        ("hash_alg", ["a"]),
        ("fulfills", {"a": 1}),
        ("prev_hash", ["a"]),
        ("due", ["a"]),
    ],
)
def test_validly_signed_junk_fields_never_crash(make_commitment, field, value):
    """Signed-but-malformed bodies (BDR checks the signature only) must not crash verify."""
    commit = make_commitment(n_receipts=1)

    def mutate(body):
        body[field] = value

    _resign(commit["receipts"][0], commit["priv"], commit["pub"], mutate)
    if field not in ("fulfills", "prev_hash"):  # keep the receipt linked to the prereg
        _resign(commit["prereg"], commit["priv"], commit["pub"], mutate)
    rep = verify_paths(
        [commit["prereg"], *commit["receipts"]],
        ["BDR", "ceiling", "chain", "content", "floor", "keyconsist"],
        artifacts_dir=commit["artifacts"],
    )
    assert rep["code"].startswith("asexec-verify/1 BDR=PASS")


@pytest.mark.parametrize("ceiling", ["x", [1], {"witness_id": 5}, {"ceiling_type": {}}])
def test_malformed_ceiling_envelope_never_crashes(make_commitment, ceiling):
    commit = make_commitment(n_receipts=0)
    mani = manifest.load(commit["prereg"])
    mani["ceiling"] = ceiling
    manifest.save(mani, commit["prereg"])
    rep = verify_paths([commit["prereg"]], ["BDR", "ceiling"])
    assert rep["results"]["ceiling"]["result"] == "FAIL"


# --------------------------------------------------------------------------- #
# drand floor through verify_paths
# --------------------------------------------------------------------------- #
_FLOOR = {
    "floor_type": "drand",
    "chain_hash": drand.QUICKNET_HASH,
    "round": 1000,
    "signature": (
        "b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125"
        "e342b73a8dd2bacbe47e4b6b63ed5e39"
    ),
    "randomness": "fe290beca10872ef2fb164d2aa4442de4566183ec51c56ff3cd603d930e54fdd",
}


def _prereg_with_floor(commit, floor):
    body = manifest.build_prereg({"k": "v"}, due="2099-01-01T00:00:00Z", floor=floor)
    path = commit["tmp"] / "floored.json"
    manifest.save(manifest.sign(body, commit["priv"], commit["pub"]), str(path))
    return str(path)


def test_floor_passes_through_verify_paths(make_commitment):
    commit = make_commitment(n_receipts=0)
    path = _prereg_with_floor(commit, _FLOOR)
    rep = verify_paths([path], ["BDR", "floor"])
    assert rep["results"]["floor"]["result"] == "PASS"
    assert rep["code"] == "asexec-verify/1 BDR=PASS floor=PASS"
    fl = rep["manifests"][0]["floor"]
    assert fl["status"] == "verified"
    assert fl["created_no_earlier_than"] == drand.time_of_round(1000)


def test_floor_with_tampered_round_fails(make_commitment):
    commit = make_commitment(n_receipts=0)
    path = _prereg_with_floor(commit, {**_FLOOR, "round": 1001})
    rep = verify_paths([path], ["BDR", "floor"])
    assert rep["manifests"][0]["floor"]["status"] == "invalid"
    assert rep["results"]["floor"]["result"] == "FAIL"


def test_floor_verifier_exception_is_invalid_not_crash(make_commitment, monkeypatch):
    commit = make_commitment(n_receipts=0)
    path = _prereg_with_floor(commit, _FLOOR)

    def boom(_floor):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(drand, "verify_floor", boom)
    rep = verify_paths([path], ["BDR", "floor"])
    fl = rep["manifests"][0]["floor"]
    assert fl["status"] == "invalid" and "malformed anchor.floor: kaboom" in fl["error"]
    assert rep["results"]["floor"]["result"] == "FAIL"


# --------------------------------------------------------------------------- #
# content: missing / unreadable artifacts
# --------------------------------------------------------------------------- #
def _content_entry(commit, name, digest="00" * 32):
    subj = [{"name": name, "digest": {"sha-256": digest}}]
    body = manifest.build_prereg({"k": "v"}, subject=subj)
    path = commit["tmp"] / "content.json"
    manifest.save(manifest.sign(body, commit["priv"], commit["pub"]), str(path))
    rep = verify_paths([str(path)], ["BDR", "content"], artifacts_dir=commit["artifacts"])
    assert rep["results"]["content"]["result"] == "FAIL"
    return rep["manifests"][0]["content"]["entries"][0]


def test_content_artifact_not_found(make_commitment):
    commit = make_commitment(n_receipts=0)
    entry = _content_entry(commit, "does-not-exist.txt")
    assert entry["ok"] is False and entry["reason"] == "artifact not found"


def test_content_artifact_unreadable(make_commitment, monkeypatch):
    commit = make_commitment(n_receipts=0)

    def deny(path, alg):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(hashing, "digest_path", deny)
    entry = _content_entry(commit, "harness/eval.py")
    assert entry["ok"] is False
    assert entry["reason"] == "artifact unreadable: Permission denied"


# --------------------------------------------------------------------------- #
# remaining verifier branches
# --------------------------------------------------------------------------- #
def test_verify_ceiling_on_malformed_manifest_is_invalid():
    from asexec.verifier import verify_ceiling

    res = verify_ceiling({"ceiling": {"ceiling_type": "roughtime"}})  # no payload/signature
    assert res["status"] == "invalid"
    assert res["error"].startswith("malformed manifest:")


def test_chain_receipt_pointing_to_missing_prev_is_a_gap(make_commitment):
    commit = make_commitment(n_receipts=1)
    body = manifest.build_postreg(
        {"kind": "api", "provider": "anthropic", "model_id": "m", "endpoint": ""},
        due="2099-01-01T00:00:00Z",
        fulfills=commit["prereg_ref"],
        prev_hash="sha-256:" + "cd" * 32,  # not any receipt we are verifying
    )
    path = commit["tmp"] / "orphan.json"
    manifest.save(manifest.sign(body, commit["priv"], commit["pub"]), str(path))
    rep = verify_paths([commit["prereg"], commit["receipts"][0], str(path)], ["BDR", "chain"])
    cm = rep["commitments"][0]
    assert cm["chain_ok"] is False and "gap" in cm["chain_note"]
    assert rep["results"]["chain"]["result"] == "FAIL"


def test_directory_argument_expands_to_json_files_only(make_commitment):
    commit = make_commitment(n_receipts=1)
    (commit["tmp"] / "notes.txt").write_text("not a manifest")
    (commit["tmp"] / "artifacts").mkdir(exist_ok=True)  # subdir is ignored, not recursed
    rep = verify_paths([str(commit["tmp"])], ["BDR"])
    paths = sorted(mani["path"].rsplit("/", 1)[-1] for mani in rep["manifests"])
    assert paths == ["prereg.json", "receipt0.json"]
    assert rep["ok"] is True
