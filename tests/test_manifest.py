"""Manifest build/sign/ref + bedrock enforcement (asexec schema)."""
import pytest

from asexec import keys, manifest, SCHEMA_VERSION, PREDICATE_TYPE
from asexec.canonical import signing_input
from asexec.errors import ManifestError


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
    m = manifest.sign(body, priv, pub)
    assert keys.verify(pub, signing_input(m["payload"]), bytes.fromhex(m["signature"]["sig"]))


def test_subject_optional_at_prereg():
    # a pre-registration may commit to a target before hashing a harness.
    priv, pub = keys.generate()
    body = manifest.build_prereg(_target(), due=DUE)
    assert "subject" not in body and "hash_alg" not in body
    m = manifest.sign(body, priv, pub)  # bedrock without subject is fine
    assert m["payload"]["phase"] == "prereg"


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
    body = {"schema_version": SCHEMA_VERSION, "predicateType": PREDICATE_TYPE,
            "phase": "prereg", "due": DUE}
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


def test_floor_lands_in_anchor_and_ref_stable_across_ceiling():
    priv, pub = keys.generate()
    floor = {"floor_type": "drand", "chain_hash": "ab", "round": 1,
             "signature": "cd", "randomness": "ef"}
    body = manifest.build_prereg(_target(), due=DUE, subject=_subj(), floor=floor)
    assert body["anchor"]["floor"]["floor_type"] == "drand"
    m = manifest.sign(body, priv, pub)
    ref_before = manifest.ref(manifest.get_body(m))
    # attaching a ceiling at the envelope must not perturb the body ref
    manifest.attach_ceiling(m, {"ceiling_type": "roughtime", "nonce": ref_before})
    assert manifest.ref(manifest.get_body(m)) == ref_before
    assert manifest.get_ceiling(m)["nonce"] == ref_before
