"""The verifier: states, tamper detection, content, chains, and the canonical
verify CODE — all offline."""

import json

import pytest

from asexec import keys, manifest
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
    c = make_commitment(n_receipts=1)
    r1 = verify_paths([c["prereg"]] + c["receipts"], ["BDR", "chain"], artifacts_dir=c["artifacts"])
    # request the SAME tests in a different order -> identical code
    r2 = verify_paths([c["prereg"]] + c["receipts"], ["chain", "BDR"], artifacts_dir=c["artifacts"])
    assert r1["code"] == r2["code"]
    assert r1["code"] == "asexec-verify/1 BDR=PASS chain=PASS"


def test_BDR_only_is_a_complete_statement(make_commitment):
    c = make_commitment(n_receipts=1)
    r = verify_paths([c["prereg"]] + c["receipts"], ["BDR"])
    assert r["code"] == "asexec-verify/1 BDR=PASS"
    assert r["ok"] is True


def test_requested_but_absent_is_fail_not_omission(make_commitment):
    # no floor was embedded (offline fixtures), so `floor` applies nowhere -> FAIL.
    c = make_commitment(n_receipts=1)
    r = verify_paths([c["prereg"]] + c["receipts"], ["BDR", "floor"], artifacts_dir=c["artifacts"])
    assert r["results"]["floor"]["result"] == "FAIL"
    assert r["results"]["floor"]["applicable"] == 0
    assert r["code"] == "asexec-verify/1 BDR=PASS floor=FAIL"
    assert r["ok"] is False


def test_content_without_artifacts_is_fail(make_commitment):
    c = make_commitment(n_receipts=1)
    r = verify_paths([c["prereg"]] + c["receipts"], ["BDR", "content"])  # no artifacts_dir
    assert r["results"]["content"]["result"] == "FAIL"
    assert r["results"]["content"]["applicable"] == 0


# --------------------------------------------------------------------------- #
# states + tamper/content/chain/key (aggregated into the code)
# --------------------------------------------------------------------------- #
def test_fulfilled(make_commitment):
    c = make_commitment(n_receipts=1)
    rep = verify_paths(
        [c["prereg"]] + c["receipts"],
        ["BDR", "content", "chain", "keyconsist"],
        artifacts_dir=c["artifacts"],
    )
    assert rep["ok"] is True
    assert rep["commitments"][0]["state"] == "fulfilled"
    assert rep["code"] == "asexec-verify/1 BDR=PASS chain=PASS content=PASS keyconsist=PASS"


def test_open_when_window_future_and_no_receipt(make_commitment):
    c = make_commitment(due="2099-01-01T00:00:00Z", n_receipts=0)
    rep = verify_paths([c["prereg"]], ["BDR"])
    assert rep["commitments"][0]["state"] == "open"
    assert rep["ok"] is True


def test_elapsed_no_receipt(make_commitment):
    c = make_commitment(due="2000-01-01T00:00:00Z", n_receipts=0)
    rep = verify_paths([c["prereg"]], ["BDR"])
    assert rep["commitments"][0]["state"] == "elapsed-no-receipt"


def test_notarization_only(make_commitment):
    c = make_commitment(n_receipts=1)
    rep = verify_paths(c["receipts"], ["BDR"])
    assert rep["notarization_only"]
    assert rep["commitments"] == []


def test_tampered_receipt_fails_BDR(make_commitment):
    c = make_commitment(n_receipts=1)
    rp = c["receipts"][0]
    m = json.loads(open(rp).read())
    m["payload"]["target"]["model_id"] = "SWAPPED"  # alter signed content
    open(rp, "w").write(json.dumps(m))
    rep = verify_paths([c["prereg"], rp], ["BDR"], artifacts_dir=c["artifacts"])
    assert rep["ok"] is False
    assert rep["results"]["BDR"]["result"] == "FAIL"
    sigs = {x["path"]: x["signature"]["signature_ok"] for x in rep["manifests"]}
    assert sigs[rp] is False


def test_content_mismatch_detected(make_commitment):
    c = make_commitment(n_receipts=1)
    import os

    open(os.path.join(c["artifacts"], "harness", "eval.py"), "w").write("TAMPERED\n")
    rep = verify_paths(
        [c["prereg"]] + c["receipts"], ["BDR", "content"], artifacts_dir=c["artifacts"]
    )
    assert rep["results"]["content"]["result"] == "FAIL"
    assert any(m["content"]["status"] == "mismatch" for m in rep["manifests"])


def test_chain_gap_detected(make_commitment):
    c = make_commitment(n_receipts=2)
    rep = verify_paths(
        [c["prereg"], c["receipts"][1]], ["BDR", "chain"], artifacts_dir=c["artifacts"]
    )
    assert rep["commitments"][0]["chain_ok"] is False
    assert rep["results"]["chain"]["result"] == "FAIL"


def test_foreign_key_still_verifies_offline(make_commitment):
    priv, pub = keys.generate()
    c = make_commitment(n_receipts=1, priv=priv, pub=pub)
    rep = verify_paths([c["prereg"]] + c["receipts"], ["BDR"], artifacts_dir=c["artifacts"])
    assert rep["ok"] is True
    assert rep["manifests"][0]["keyid"] == keys.keyid_for(pub)


def test_receipts_from_wrong_key_flagged(make_commitment):
    c = make_commitment(n_receipts=1)
    other_priv, other_pub = keys.generate()
    body = manifest.get_body(manifest.load(c["receipts"][0]))
    manifest.save(manifest.sign(body, other_priv, other_pub), c["receipts"][0])
    rep = verify_paths(
        [c["prereg"]] + c["receipts"], ["BDR", "keyconsist"], artifacts_dir=c["artifacts"]
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
    c = make_commitment(n_receipts=1)
    other_priv, other_pub = keys.generate()
    _resign(c["receipts"][0], other_priv, other_pub)
    rep = verify_paths([c["prereg"]] + c["receipts"], ["BDR", "keyconsist"])
    cm = rep["commitments"][0]
    assert cm["state"] != "fulfilled"
    assert cm["receipts"] == []
    assert len(cm["rejected_receipts"]) == 1
    assert "different key" in cm["rejected_receipts"][0]["reason"]
    assert rep["results"]["keyconsist"]["result"] == "FAIL"


def test_postreg_with_invalid_signature_does_not_fulfill(make_commitment):
    c = make_commitment(n_receipts=1)
    rp = c["receipts"][0]
    m = json.loads(open(rp).read())
    m["payload"]["target"]["model_id"] = "SWAPPED"  # signature no longer matches
    open(rp, "w").write(json.dumps(m))
    rep = verify_paths([c["prereg"], rp], ["BDR"])
    cm = rep["commitments"][0]
    assert cm["state"] != "fulfilled"
    assert cm["receipts"] == []
    assert "invalid signature" in cm["rejected_receipts"][0]["reason"]
    assert rep["results"]["BDR"]["result"] == "FAIL"


def test_forked_chain_fails(make_commitment):
    c = make_commitment(n_receipts=2)
    # receipt1 currently points at receipt0; make a sibling that also does.
    sibling = c["tmp"] / "sibling.json"
    body = manifest.get_body(manifest.load(c["receipts"][1]))
    body["notes"] = "fork"
    manifest.save(manifest.sign(body, c["priv"], c["pub"]), str(sibling))
    rep = verify_paths([c["prereg"], *c["receipts"], str(sibling)], ["BDR", "chain", "keyconsist"])
    assert rep["commitments"][0]["chain_ok"] is False
    assert "fork" in rep["commitments"][0]["chain_note"]
    assert rep["results"]["chain"]["result"] == "FAIL"


def test_linear_chain_still_passes(make_commitment):
    c = make_commitment(n_receipts=3)
    rep = verify_paths([c["prereg"], *c["receipts"]], ["BDR", "chain"])
    assert rep["results"]["chain"]["result"] == "PASS"


def _escape_setup(make_commitment, name):
    """A prereg whose subject name escapes --artifacts, with a matching outside file."""
    c = make_commitment(n_receipts=0)
    outside = c["tmp"] / "secret.txt"
    outside.write_text("outside\n")
    from asexec import hashing

    digest = hashing.hash_file(str(outside))
    subj = [{"name": name.format(outside=outside), "digest": {"sha-256": digest}}]
    body = manifest.build_prereg({"k": "v"}, subject=subj)
    p = c["tmp"] / "escape.json"
    manifest.save(manifest.sign(body, c["priv"], c["pub"]), str(p))
    return c, str(p)


@pytest.mark.parametrize("name", ["../secret.txt", "{outside}", "harness/../../secret.txt"])
def test_content_cannot_escape_artifacts_dir(make_commitment, name):
    c, p = _escape_setup(make_commitment, name)
    rep = verify_paths([p], ["BDR", "content"], artifacts_dir=c["artifacts"])
    assert rep["results"]["content"]["result"] == "FAIL"
    entry = rep["manifests"][0]["content"]["entries"][0]
    assert entry["ok"] is False
    assert "outside" in entry["reason"]


def test_content_rejects_symlink_escape(make_commitment, tmp_path):
    c, _ = _escape_setup(make_commitment, "x")
    link = tmp_path / "artifacts" / "link.txt"
    link.symlink_to(tmp_path / "secret.txt")
    from asexec import hashing

    subj = [{"name": "link.txt", "digest": {"sha-256": hashing.hash_file(str(link))}}]
    body = manifest.build_prereg({"k": "v"}, subject=subj)
    p = tmp_path / "link.json"
    manifest.save(manifest.sign(body, c["priv"], c["pub"]), str(p))
    rep = verify_paths([str(p)], ["BDR", "content"], artifacts_dir=c["artifacts"])
    assert rep["results"]["content"]["result"] == "FAIL"


def test_duplicate_json_keys_rejected(make_commitment):
    c = make_commitment(n_receipts=0)
    raw = open(c["prereg"]).read()
    # inject a second "phase" key into the payload (last would win)
    dup = raw.replace('"phase": "prereg"', '"phase": "prereg", "phase": "postreg"', 1)
    assert dup != raw
    open(c["prereg"], "w").write(dup)
    rep = verify_paths([c["prereg"]], ["BDR"])
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
    c = make_commitment(n_receipts=1)
    bad = tmp_path / "bad.json"
    bad.write_text(raw)
    tests = ["BDR", "chain", "content", "keyconsist"]
    rep = verify_paths([c["prereg"], *c["receipts"], str(bad)], tests, c["artifacts"])
    assert rep["results"]["BDR"]["result"] == "FAIL"
    assert rep["ok"] is False
    assert rep["code"].startswith("asexec-verify/1 BDR=FAIL")


def test_binary_and_missing_files_are_per_file_failures(make_commitment, tmp_path):
    c = make_commitment(n_receipts=0)
    binf = tmp_path / "bin.json"
    binf.write_bytes(b"\xff\xfe\x00")
    rep = verify_paths([c["prereg"], str(binf), str(tmp_path / "missing.json")], ["BDR"])
    assert rep["results"]["BDR"]["result"] == "FAIL"
    assert len(rep["manifests"]) == 3


def test_unknown_hash_alg_fails_entry_not_crash(make_commitment):
    c = make_commitment(n_receipts=0)
    body = manifest.get_body(manifest.load(c["prereg"]))
    body["hash_alg"] = "blake9"
    body["subject"][0]["digest"] = {"blake9": "00"}
    manifest.save(manifest.sign(body, c["priv"], c["pub"]), c["prereg"])
    rep = verify_paths([c["prereg"]], ["BDR", "content"], artifacts_dir=c["artifacts"])
    assert rep["results"]["content"]["result"] == "FAIL"
    entry = rep["manifests"][0]["content"]["entries"][0]
    assert "algorithm unavailable" in entry["reason"]


def _prereg_with_due(c, due):
    body = manifest.get_body(manifest.load(c["prereg"]))
    body["due"] = due
    manifest.save(manifest.sign(body, c["priv"], c["pub"]), c["prereg"])


def test_unparseable_due_renders_invalid_due(make_commitment):
    c = make_commitment(n_receipts=0)
    _prereg_with_due(c, "next tuesday")
    cm = verify_paths([c["prereg"]], ["BDR"])["commitments"][0]
    assert cm["state"] == "invalid-due"


def test_non_string_due_renders_invalid_due(make_commitment):
    c = make_commitment(n_receipts=0)
    _prereg_with_due(c, 12345)
    cm = verify_paths([c["prereg"]], ["BDR"])["commitments"][0]
    assert cm["state"] == "invalid-due"


def test_naive_due_is_flagged_and_timezone_independent(make_commitment, monkeypatch):
    import datetime
    import time

    c = make_commitment(n_receipts=0)
    _prereg_with_due(c, "2026-01-01T12:00:00")
    now = datetime.datetime(2026, 1, 1, 12, 30, tzinfo=datetime.UTC).timestamp()
    states = set()
    for tz in ("UTC", "Pacific/Kiritimati", "Pacific/Pago_Pago"):
        monkeypatch.setenv("TZ", tz)
        time.tzset()
        cm = verify_paths([c["prereg"]], ["BDR"], now=now)["commitments"][0]
        assert cm["due_naive"] is True
        states.add(cm["state"])
    assert states == {"elapsed-no-receipt"}


def test_aware_due_is_not_flagged(make_commitment):
    c = make_commitment(due="2099-01-01T00:00:00Z", n_receipts=0)
    cm = verify_paths([c["prereg"]], ["BDR"])["commitments"][0]
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
    c = make_commitment(n_receipts=1)

    def mutate(body):
        body[field] = value

    _resign(c["receipts"][0], c["priv"], c["pub"], mutate)
    if field not in ("fulfills", "prev_hash"):  # keep the receipt linked to the prereg
        _resign(c["prereg"], c["priv"], c["pub"], mutate)
    rep = verify_paths(
        [c["prereg"], *c["receipts"]],
        ["BDR", "ceiling", "chain", "content", "floor", "keyconsist"],
        artifacts_dir=c["artifacts"],
    )
    assert rep["code"].startswith("asexec-verify/1 BDR=PASS")


@pytest.mark.parametrize("ceiling", ["x", [1], {"witness_id": 5}, {"ceiling_type": {}}])
def test_malformed_ceiling_envelope_never_crashes(make_commitment, ceiling):
    c = make_commitment(n_receipts=0)
    m = manifest.load(c["prereg"])
    m["ceiling"] = ceiling
    manifest.save(m, c["prereg"])
    rep = verify_paths([c["prereg"]], ["BDR", "ceiling"])
    assert rep["results"]["ceiling"]["result"] == "FAIL"
