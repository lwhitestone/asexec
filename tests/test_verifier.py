"""The verifier: states, tamper detection, content, chains, and the canonical
verify CODE — all offline."""
import json

import pytest

from asexec import keys, manifest, verifier
from asexec.errors import VerificationError
from asexec.verifier import verify_paths, parse_tests


# --------------------------------------------------------------------------- #
# --tests parsing / gating
# --------------------------------------------------------------------------- #
def test_bedrock_required_in_tests():
    with pytest.raises(VerificationError):
        parse_tests("floor,content")


def test_unknown_test_rejected():
    with pytest.raises(VerificationError):
        parse_tests("bedrock,nope")


def test_empty_tests_rejected():
    with pytest.raises(VerificationError):
        parse_tests("")


def test_parse_tests_is_catalog_ordered_and_deduped():
    assert parse_tests("floor,bedrock,floor") == ["bedrock", "floor"]


# --------------------------------------------------------------------------- #
# canonical code
# --------------------------------------------------------------------------- #
def test_code_is_alphabetical_and_byte_identical(make_commitment):
    c = make_commitment(n_receipts=1)
    r1 = verify_paths([c["prereg"]] + c["receipts"], ["bedrock", "chain"],
                      artifacts_dir=c["artifacts"])
    # request the SAME tests in a different order -> identical code
    r2 = verify_paths([c["prereg"]] + c["receipts"], ["chain", "bedrock"],
                      artifacts_dir=c["artifacts"])
    assert r1["code"] == r2["code"]
    assert r1["code"] == "asexec-verify/1 bedrock=PASS chain=PASS"


def test_bedrock_only_is_a_complete_statement(make_commitment):
    c = make_commitment(n_receipts=1)
    r = verify_paths([c["prereg"]] + c["receipts"], ["bedrock"])
    assert r["code"] == "asexec-verify/1 bedrock=PASS"
    assert r["ok"] is True


def test_requested_but_absent_is_fail_not_omission(make_commitment):
    # no floor was embedded (offline fixtures), so `floor` applies nowhere -> FAIL.
    c = make_commitment(n_receipts=1)
    r = verify_paths([c["prereg"]] + c["receipts"], ["bedrock", "floor"],
                     artifacts_dir=c["artifacts"])
    assert r["results"]["floor"]["result"] == "FAIL"
    assert r["results"]["floor"]["applicable"] == 0
    assert r["code"] == "asexec-verify/1 bedrock=PASS floor=FAIL"
    assert r["ok"] is False


def test_content_without_artifacts_is_fail(make_commitment):
    c = make_commitment(n_receipts=1)
    r = verify_paths([c["prereg"]] + c["receipts"], ["bedrock", "content"])  # no artifacts_dir
    assert r["results"]["content"]["result"] == "FAIL"
    assert r["results"]["content"]["applicable"] == 0


# --------------------------------------------------------------------------- #
# states + tamper/content/chain/key (aggregated into the code)
# --------------------------------------------------------------------------- #
def test_fulfilled(make_commitment):
    c = make_commitment(n_receipts=1)
    rep = verify_paths([c["prereg"]] + c["receipts"],
                       ["bedrock", "content", "chain", "keyconsist"],
                       artifacts_dir=c["artifacts"])
    assert rep["ok"] is True
    assert rep["commitments"][0]["state"] == "fulfilled"
    assert rep["code"] == "asexec-verify/1 bedrock=PASS chain=PASS content=PASS keyconsist=PASS"


def test_open_when_window_future_and_no_receipt(make_commitment):
    c = make_commitment(closes="2099-01-01T00:00:00Z", n_receipts=0)
    rep = verify_paths([c["prereg"]], ["bedrock"])
    assert rep["commitments"][0]["state"] == "open"
    assert rep["ok"] is True


def test_elapsed_no_receipt(make_commitment):
    c = make_commitment(closes="2000-01-01T00:00:00Z", n_receipts=0)
    rep = verify_paths([c["prereg"]], ["bedrock"])
    assert rep["commitments"][0]["state"] == "elapsed-no-receipt"


def test_notarization_only(make_commitment):
    c = make_commitment(n_receipts=1)
    rep = verify_paths(c["receipts"], ["bedrock"])
    assert rep["notarization_only"]
    assert rep["commitments"] == []


def test_tampered_receipt_fails_bedrock(make_commitment):
    c = make_commitment(n_receipts=1)
    rp = c["receipts"][0]
    m = json.loads(open(rp).read())
    m["payload"]["target_identity"]["model_id"] = "SWAPPED"  # alter signed content
    open(rp, "w").write(json.dumps(m))
    rep = verify_paths([c["prereg"], rp], ["bedrock"], artifacts_dir=c["artifacts"])
    assert rep["ok"] is False
    assert rep["results"]["bedrock"]["result"] == "FAIL"
    sigs = {x["path"]: x["signature"]["signature_ok"] for x in rep["manifests"]}
    assert sigs[rp] is False


def test_content_mismatch_detected(make_commitment):
    c = make_commitment(n_receipts=1)
    import os
    open(os.path.join(c["artifacts"], "harness", "eval.py"), "w").write("TAMPERED\n")
    rep = verify_paths([c["prereg"]] + c["receipts"], ["bedrock", "content"],
                       artifacts_dir=c["artifacts"])
    assert rep["results"]["content"]["result"] == "FAIL"
    assert any(m["content"]["status"] == "mismatch" for m in rep["manifests"])


def test_chain_gap_detected(make_commitment):
    c = make_commitment(n_receipts=2)
    rep = verify_paths([c["prereg"], c["receipts"][1]], ["bedrock", "chain"],
                       artifacts_dir=c["artifacts"])
    assert rep["commitments"][0]["chain_ok"] is False
    assert rep["results"]["chain"]["result"] == "FAIL"


def test_foreign_key_still_verifies_offline(make_commitment):
    priv, pub = keys.generate()
    c = make_commitment(n_receipts=1, priv=priv, pub=pub)
    rep = verify_paths([c["prereg"]] + c["receipts"], ["bedrock"],
                       artifacts_dir=c["artifacts"])
    assert rep["ok"] is True
    assert rep["manifests"][0]["keyid"] == keys.keyid_for(pub)


def test_receipts_from_wrong_key_flagged(make_commitment):
    c = make_commitment(n_receipts=1)
    other_priv, other_pub = keys.generate()
    body = manifest.get_body(manifest.load(c["receipts"][0]))
    manifest.save(manifest.sign(body, other_priv, other_pub), c["receipts"][0])
    rep = verify_paths([c["prereg"]] + c["receipts"], ["bedrock", "keyconsist"],
                       artifacts_dir=c["artifacts"])
    assert rep["commitments"][0]["key_consistent"] is False
    assert rep["results"]["keyconsist"]["result"] == "FAIL"
