"""Manifest build/sign/ref + bedrock enforcement (asexec schema)."""

import base64

import pytest
from pydantic import ValidationError

from asexec import MANIFEST_PREDICATE_TYPE, drand, keys, manifest
from asexec.canonical import canonical_bytes, signing_input
from asexec.constants import MANIFEST_PAYLOAD_TYPE
from asexec.errors import ManifestError
from asexec.models import Ceiling, Dsse, Manifest, Signature


def _target():
    return {"kind": "api", "provider": "p", "model_id": "m", "endpoint": ""}


DUE = "2099-01-01T00:00:00Z"


def _subj(name="h.py"):
    return [{"name": name, "hash_alg": "sha-256", "digest": {"sha-256": "00"}}]


def test_predicate_type_is_the_only_format_identifier_in_the_body():
    # predicateType says the body is an asexec manifest; schema_id is no longer written.
    assert MANIFEST_PREDICATE_TYPE == "https://asexec.org/manifest/v1"
    body = manifest.build_prereg(_target(), due=DUE, subject=_subj())
    assert body["predicateType"] == "https://asexec.org/manifest/v1"
    assert body["phase"] == "prereg"
    assert "schema_id" not in body


def test_target_may_be_freeform_text():
    # freeform: a plain-string target is a valid (lower-disclosure) commitment.
    body = manifest.build_prereg("claude-opus-4-8 via the anthropic API", due=DUE)
    assert body["target"] == "claude-opus-4-8 via the anthropic API"


def test_ref_is_signature_independent():
    body = manifest.build_prereg(_target(), due=DUE, subject=_subj())
    priv1, pub1 = keys.generate()
    priv2, pub2 = keys.generate()
    m1 = manifest.sign(body, priv1, pub1)
    m2 = manifest.sign(dict(body), priv2, pub2)
    # different signatures, same body => same ref
    assert m1["dsse"]["signatures"][0]["sig"] != m2["dsse"]["signatures"][0]["sig"]
    assert manifest.ref(manifest.read_body(m1)[0]) == manifest.ref(manifest.read_body(m2)[0])


def test_sign_writes_a_dsse_envelope_in_the_wrapper():
    """The file is {dsse: {payloadType, payload, signatures: [{keyid, sig}]}, pubkey}, and
    dsse.payload is the base64 of the body's canonical serialization."""
    priv, pub = keys.generate()
    body = manifest.build_prereg(_target(), due=DUE, subject=_subj())
    signed = manifest.sign(body, priv, pub)
    assert list(signed) == ["dsse", "pubkey"]
    assert list(signed["dsse"]) == ["payloadType", "payload", "signatures"]
    assert signed["dsse"]["payloadType"] == MANIFEST_PAYLOAD_TYPE
    assert signed["dsse"]["payload"] == base64.b64encode(canonical_bytes(body)).decode()
    (entry,) = signed["dsse"]["signatures"]
    assert entry == {"keyid": keys.keyid_for(pub), "sig": entry["sig"]}
    assert signed["pubkey"] == pub.hex()
    assert manifest.read_body(signed) == (canonical_bytes(body), body)


def test_sign_then_verify_matches():
    priv, pub = keys.generate()
    body = manifest.build_prereg(_target(), due=DUE, subject=_subj())
    signed = manifest.sign(body, priv, pub)
    raw, _body = manifest.read_body(signed)
    sig = base64.b64decode(signed["dsse"]["signatures"][0]["sig"], validate=True)
    assert keys.verify(bytes.fromhex(signed["pubkey"]), signing_input(raw), sig)


def test_sign_refuses_a_body_with_no_utf8_form():
    """A string holding a lone surrogate has no UTF-8 encoding, so the writer cannot store
    it: a clean ManifestError, not a UnicodeEncodeError."""
    priv, pub = keys.generate()
    body = manifest.build_prereg(_target(), declaration="\ud800")
    with pytest.raises(ManifestError, match="no UTF-8 form"):
        manifest.sign(body, priv, pub)


@pytest.mark.parametrize(
    "mani",
    [
        {},
        {"dsse": []},
        {"dsse": {"payload": 5}},
        {"dsse": {"payload": "e30"}},
        {"dsse": {"payload": "e31="}},
        {"dsse": {"payload": "WzFd"}},  # [1]
        {"payload": {"phase": "prereg"}, "signature": {}},  # 0.3.x's layout
    ],
    ids=["no-dsse", "dsse-list", "payload-number", "unpadded", "non-canonical", "array", "0.3.x"],
)
def test_read_body_refuses_what_is_not_a_body(mani):
    with pytest.raises(ManifestError):
        manifest.read_body(mani)


def test_subject_optional_at_prereg():
    # a pre-registration may commit to a target before hashing a harness.
    priv, pub = keys.generate()
    body = manifest.build_prereg(_target(), due=DUE)
    assert "subject" not in body and "hash_alg" not in body
    signed = manifest.sign(body, priv, pub)  # bedrock without subject is fine
    assert manifest.read_body(signed)[1]["phase"] == "prereg"


def test_due_optional_at_prereg():
    # a deadline is optional: such a commitment simply stays 'open' forever.
    body = manifest.build_prereg(_target())
    assert "due" not in body


def test_subject_entry_requires_its_own_hash_alg():
    # Each entry carries its own hash_alg; one stripped from a hand-built body is refused.
    priv, pub = keys.generate()
    body = manifest.build_prereg(_target(), due=DUE, subject=_subj())
    assert body["subject"][0]["hash_alg"] == "sha-256"
    assert "hash_alg" not in body  # no body-level hash_alg is written
    del body["subject"][0]["hash_alg"]
    with pytest.raises(ManifestError, match="hash_alg"):
        manifest.sign(body, priv, pub)


def test_builders_take_no_body_level_hash_alg():
    with pytest.raises(TypeError):
        manifest.build_prereg(_target(), subject=_subj(), hash_alg="sha-256")


def test_writer_subject_entry_requires_hash_alg():
    entry = {"name": "h.py", "digest": {"sha-256": "00"}}
    with pytest.raises(ValidationError):
        manifest.build_prereg(_target(), subject=[entry])


def test_writer_refuses_duplicate_subject_names():
    with pytest.raises(ValidationError, match="twice"):
        manifest.build_prereg(_target(), subject=_subj() + _subj())


def test_sign_refuses_a_hand_built_body_with_duplicate_subject_names():
    priv, pub = keys.generate()
    body = manifest.build_prereg(_target(), subject=_subj())
    body["subject"].append(dict(body["subject"][0]))
    with pytest.raises(ManifestError, match="twice"):
        manifest.sign(body, priv, pub)


@pytest.mark.parametrize(
    "name", ["/abs.py", "./h.py", "a//h.py", "a/../h.py", "h/", "a\\h.py", "", "."]
)
def test_writer_refuses_a_name_that_is_not_a_normalized_relative_path(name):
    with pytest.raises(ValidationError):
        manifest.build_prereg(_target(), subject=_subj(name))


def test_missing_semantic_bedrock_rejected():
    priv, pub = keys.generate()
    # no target (the only semantic bedrock field)
    body = {
        "predicateType": MANIFEST_PREDICATE_TYPE,
        "phase": "prereg",
        "due": DUE,
    }
    with pytest.raises(ManifestError):
        manifest.sign(body, priv, pub)


def test_missing_structural_bedrock_rejected():
    priv, pub = keys.generate()
    body = manifest.build_prereg(_target(), due=DUE, subject=_subj())
    del body["predicateType"]  # structural frame invariant gone
    with pytest.raises(ManifestError):
        manifest.sign(body, priv, pub)


def test_postreg_requires_fulfills():
    priv, pub = keys.generate()
    body = manifest.build_prereg(_target(), due=DUE, subject=_subj())
    body["phase"] = "postreg"  # now it's a postreg with no fulfills
    with pytest.raises(ManifestError):
        manifest.sign(body, priv, pub)


@pytest.mark.parametrize(
    "change",
    [
        pytest.param({"chain_hash": None}, id="null-is-not-a-default"),
        pytest.param({"round": "1000"}, id="no-coercion"),
        pytest.param({"signature": "zz"}, id="signature-not-hex"),
        pytest.param({"signature": "CD"}, id="signature-uppercase"),
        pytest.param({"randomness": "e f"}, id="randomness-spaced"),
        pytest.param({"extra": 1}, id="no-extra-fields"),
    ],
)
def test_writer_floor_rejects_what_it_would_not_write(change):
    """The writer gates what it writes: no coercion, no None-as-default, no stray field, and
    hex only as lowercase without whitespace (the spelling exact comparisons expect)."""
    floor = {"floor_type": "drand", "chain_hash": drand.QUICKNET_HASH, "round": 1,
             "signature": "cd", **change}  # fmt: skip
    with pytest.raises(ValidationError):
        manifest.build_prereg(_target(), due=DUE, subject=_subj(), floor=floor)


@pytest.mark.parametrize("field", ["nonce", "pubkey", "response"])
@pytest.mark.parametrize("value", ["AB", "a b"], ids=["uppercase", "spaced"])
def test_writer_ceiling_rejects_non_lowercase_hex(field, value):
    ceiling = {"ceiling_type": "roughtime", "witness_id": "w", "nonce": "ab", "pubkey": "ab",
               "response": "ab", "midpoint": 1.0, "radius": 1.0, field: value}  # fmt: skip
    with pytest.raises(ValidationError):
        Ceiling(**ceiling)


SIG = base64.b64encode(bytes(64)).decode()  # well-formed, as DSSE has it: base64 of 64 bytes


@pytest.mark.parametrize(
    "sig",
    [
        bytes(64).hex(),  # hex, as asexec wrote before
        base64.b64encode(bytes(63)).decode(),
        base64.b64encode(bytes(65)).decode(),
        SIG.rstrip("="),
        SIG[:-3] + "B==",  # an unused bit set
        SIG + "\n",
    ],
    ids=["hex", "63-bytes", "65-bytes", "unpadded", "non-canonical", "newline"],
)
def test_writer_signature_is_strict_base64_of_64_bytes(sig):
    Signature(keyid="k", sig=SIG)
    with pytest.raises(ValidationError):
        Signature(keyid="k", sig=sig)


def test_writer_pubkey_rejects_non_lowercase_hex():
    dsse = Dsse(payload="e30=", signatures=[Signature(keyid="k", sig=SIG)])
    Manifest(dsse=dsse, pubkey="ab")
    with pytest.raises(ValidationError):
        Manifest(dsse=dsse, pubkey="AB")


@pytest.mark.parametrize("count", [0, 2])
def test_writer_writes_exactly_one_signature(count):
    with pytest.raises(ValidationError):
        Dsse(payload="e30=", signatures=[Signature(keyid="k", sig=SIG)] * count)


@pytest.mark.parametrize("payload", ["e30", "e31=", "e3 0=", "-_8="])
def test_writer_payload_is_strict_base64(payload):
    with pytest.raises(ValidationError):
        Dsse(payload=payload, signatures=[Signature(keyid="k", sig=SIG)])


def test_floor_lands_in_anchor_and_ref_stable_across_ceiling():
    priv, pub = keys.generate()
    floor = {
        "floor_type": "drand",
        "chain_hash": drand.QUICKNET_HASH,
        "round": 1,
        "signature": "cd",
        "randomness": "ef",
    }
    body = manifest.build_prereg(_target(), due=DUE, subject=_subj(), floor=floor)
    assert body["anchor"]["floor"]["floor_type"] == "drand"
    signed = manifest.sign(body, priv, pub)
    ref_before = manifest.ref(manifest.read_body(signed)[0])
    # attaching a ceiling in the wrapper must not perturb the body ref
    manifest.attach_ceiling(signed, {"ceiling_type": "roughtime", "nonce": ref_before})
    assert manifest.ref(manifest.read_body(signed)[0]) == ref_before
    assert manifest.get_ceiling(signed)["nonce"] == ref_before


# --- the claim record ------------------------------------------------------- #
PLAN = {"name": "plan.md", "hash_alg": "sha-256", "digest": {"sha-256": "00"}}
EVIDENCE = [{"name": "e.json", "hash_alg": "sha-256", "digest": {"sha-256": "00"}}]


def test_claim_record_fields_are_written_as_given():
    plan = {**PLAN, "media_type": "text/markdown", "label": "L"}
    items = [{"id": "S1", "kind": "run"}, {"id": "S2"}]
    pre = manifest.build_prereg(_target(), plan=plan, items=items)
    assert pre["plan"] == plan and pre["items"] == items
    evidence = [{**EVIDENCE[0], "media_type": "application/json", "uri": "https://e"}]
    post = manifest.build_postreg(
        _target(), fulfills="sha-256:00", item_id="S1", status="reported", evidence=evidence
    )
    assert (post["item_id"], post["status"], post["evidence"]) == ("S1", "reported", evidence)


@pytest.mark.parametrize(
    "fields",
    [
        {"plan": {**PLAN, "extra": 1}},
        {"plan": {k: v for k, v in PLAN.items() if k != "hash_alg"}},
        {"plan": {**PLAN, "name": "./plan.md"}},
        {"items": [{"id": "S1"}, {"id": "S1", "kind": "again"}]},
        {"items": [{"kind": "run"}]},
        {"items": [{"id": 1}]},
        {"status": "done"},
        {"status": None, "item_id": 5},
        {"evidence": []},
        {"evidence": EVIDENCE * 2},
        {"evidence": [{**EVIDENCE[0], "uri": 5}]},
    ],
    ids=[
        "plan-extra-field",
        "plan-no-hash_alg",
        "plan-name-not-normalized",
        "item-ids-repeat",
        "item-without-id",
        "item-id-not-string",
        "status-unknown",
        "item_id-not-string",
        "evidence-empty",
        "evidence-names-repeat",
        "uri-not-string",
    ],
)
def test_writer_refuses_a_claim_record_content_or_complete_would_fail(fields):
    """Signing validates status (reported | excluded | blocked) and item ids (strings,
    unique), and holds plan and evidence entries to the subject entry's rules."""
    with pytest.raises(ValidationError):
        manifest.build_postreg(_target(), fulfills="sha-256:00", **fields)


@pytest.mark.parametrize("field", ["subject", "evidence"])
def test_writer_refuses_an_empty_entry_list(field):
    """content #1 fails an empty subject or evidence list, so the writer never writes one."""
    with pytest.raises(ValidationError):
        manifest.build_postreg(_target(), fulfills="sha-256:00", **{field: []})
