"""Manifest build/sign/ref + bedrock enforcement (asexec schema)."""

import pytest
from pydantic import ValidationError

from asexec import PREDICATE_TYPE, SCHEMA_VERSION, drand, keys, manifest
from asexec.canonical import signing_input
from asexec.errors import ManifestError
from asexec.models import Ceiling, Signature


def _target():
    return {"kind": "api", "provider": "p", "model_id": "m", "endpoint": ""}


DUE = "2099-01-01T00:00:00Z"


def _subj():
    return [{"name": "h/", "digest": {"sha-256": "00"}}]


def test_schema_and_predicate_identifiers():
    # Plain, unversioned format identifiers (no parallel v1/v2 numbering scheme).
    assert SCHEMA_VERSION == "asexec"
    assert PREDICATE_TYPE == "https://asexec.dev/manifest"
    body = manifest.build_prereg(_target(), due=DUE, subject=_subj())
    assert body["schema_version"] == "asexec"
    assert body["predicateType"] == "https://asexec.dev/manifest"
    assert body["phase"] == "prereg"


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
    assert m1["signature"]["sig"] != m2["signature"]["sig"]
    assert manifest.ref(manifest.get_body(m1)) == manifest.ref(manifest.get_body(m2))


def test_sign_then_verify_matches():
    priv, pub = keys.generate()
    body = manifest.build_prereg(_target(), due=DUE, subject=_subj())
    signed = manifest.sign(body, priv, pub)
    assert keys.verify(
        pub, signing_input(signed["payload"]), bytes.fromhex(signed["signature"]["sig"])
    )


def test_subject_optional_at_prereg():
    # a pre-registration may commit to a target before hashing a harness.
    priv, pub = keys.generate()
    body = manifest.build_prereg(_target(), due=DUE)
    assert "subject" not in body and "hash_alg" not in body
    signed = manifest.sign(body, priv, pub)  # bedrock without subject is fine
    assert signed["payload"]["phase"] == "prereg"


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
        "schema_version": SCHEMA_VERSION,
        "predicateType": PREDICATE_TYPE,
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


@pytest.mark.parametrize("field", ["pubkey", "sig"])
def test_writer_signature_rejects_non_lowercase_hex(field):
    signature = {"keyid": "k", "pubkey": "ab", "sig": "ab", field: "AB"}
    with pytest.raises(ValidationError):
        Signature(**signature)


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
    ref_before = manifest.ref(manifest.get_body(signed))
    # attaching a ceiling at the envelope must not perturb the body ref
    manifest.attach_ceiling(signed, {"ceiling_type": "roughtime", "nonce": ref_before})
    assert manifest.ref(manifest.get_body(signed)) == ref_before
    assert manifest.get_ceiling(signed)["nonce"] == ref_before
