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


def _subj():
    return [{"name": "h/", "digest": {"sha-256": "00"}}]


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
    sig = bytes.fromhex(signed["dsse"]["signatures"][0]["sig"])
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


def test_subject_requires_hash_alg():
    # a subject present but its algorithm stripped -> conditional bedrock fails.
    priv, pub = keys.generate()
    body = manifest.build_prereg(_target(), due=DUE, subject=_subj())
    del body["hash_alg"]
    with pytest.raises(ManifestError):
        manifest.sign(body, priv, pub)


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


def test_writer_signature_rejects_non_lowercase_hex():
    Signature(keyid="k", sig="ab")
    with pytest.raises(ValidationError):
        Signature(keyid="k", sig="AB")


def test_writer_pubkey_rejects_non_lowercase_hex():
    dsse = Dsse(payload="e30=", signatures=[Signature(keyid="k", sig="ab")])
    Manifest(dsse=dsse, pubkey="ab")
    with pytest.raises(ValidationError):
        Manifest(dsse=dsse, pubkey="AB")


@pytest.mark.parametrize("count", [0, 2])
def test_writer_writes_exactly_one_signature(count):
    with pytest.raises(ValidationError):
        Dsse(payload="e30=", signatures=[Signature(keyid="k", sig="ab")] * count)


@pytest.mark.parametrize("payload", ["e30", "e31=", "e3 0=", "-_8="])
def test_writer_payload_is_strict_base64(payload):
    with pytest.raises(ValidationError):
        Dsse(payload=payload, signatures=[Signature(keyid="k", sig="ab")])


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
