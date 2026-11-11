"""Pins every asexec-defined identifier as a literal. A failure here means stop and think.

The values are written out on purpose. Importing them from ``asexec.constants`` would let
an edit there pass unnoticed, because the code and its test would move together. Do not
compare against the constants instead, and do not update a literal just to pass a test.

The rule, starting with the 0.4.0 release: add a new format version and keep accepting the old
ones. Never replace a value in a way that makes a manifest signed by 0.4.0 or later fail. Until
0.4.0 ships, breaking changes are allowed: get the format right rather than preserve it.

This is not built yet (design: ``docs/MULTIVERSION.md``). The verifier accepts only one value
of each identifier, so changing a BREAKS_USERS constant does break users. From 0.4.0, its
fallback has to be built first, in the same PR; the comment on each test says what it is.

Each identifier has exactly one class in ``IMPACT``:

BREAKS_USERS: without a fallback, a change makes a published manifest fail, or stops an
    existing key file, published document or tool from working.
NEW_OUTPUT: only newly written files change, whether or not a fallback exists.

To change an identifier, in one PR:

1. Build its fallback, if it is BREAKS_USERS. Move it to NEW_OUTPUT if the change then affects
   only new output.
2. Change ``asexec.constants`` and the literals here.
3. Add a frozen manifest for the new version. From 0.4.0, never edit or regenerate an existing
   one: if one fails, the change breaks users.
4. Update the README, ``docs/VERIFICATION.md`` and any golden vectors.
5. Release it as a ``MINOR`` (``ROADMAP.md``, Versioning), with this release-note entry:

       Identifier: <name>, <old value> -> <new value>
       Impact: <class>
       Affected: <what existing files or tools are touched, or "nothing published">
       Action: <what users must do, or "none">

The ``test_not_enforced_yet__*`` tests record what verify does not check today. They are not
requirements: when one fails because enforcement was added, update it and reclassify the
identifier if needed.
"""

import copy
import hashlib
import json
from types import SimpleNamespace

from asexec import (
    MANIFEST_PREDICATE_TYPE,
    MANIFEST_SCHEMA_ID,
    constants,
    hashing,
    identity,
    keys,
    manifest,
    roughtime,
)
from asexec.canonical import signing_input
from asexec.verifier import verify_paths

BREAKS_USERS = "BREAKS_USERS"
NEW_OUTPUT = "NEW_OUTPUT"

IMPACT = {
    "DIGEST_REF_PREFIX": BREAKS_USERS,
    "IDENTITY_WELL_KNOWN_PATH": BREAKS_USERS,
    "MANIFEST_PAYLOAD_TYPE": BREAKS_USERS,
    "SIGNING_KEY_ALG": BREAKS_USERS,
    "SIGNING_PAE_VERSION": BREAKS_USERS,
    "SUBJECT_DEFAULT_HASH_ALG": BREAKS_USERS,
    "VERIFY_CODE_VERSION": BREAKS_USERS,
    "IDENTITY_DOCUMENT_VERSION": NEW_OUTPUT,
    "MANIFEST_PREDICATE_TYPE": NEW_OUTPUT,
    "MANIFEST_SCHEMA_ID": NEW_OUTPUT,
}

# Signed once with the all-zero seed and then frozen, standing in for published manifests.
FROZEN_KEY = {
    "alg": "ed25519",
    "keyid": "sha-256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070",
    "pubkey": "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
}
FROZEN_BODY = {"phase": "prereg", "target": "m"}
FROZEN_MANIFEST = {
    "payloadType": "application/vnd.asexec+json",
    "payload": FROZEN_BODY,
    "signature": {
        **FROZEN_KEY,
        "sig": "2e993406b7492218b6a366a83fa99ecd53c9385bfb53c0bb00b5981ea83b8098"
        "008837c636d7467eae6d33afb377f62c2a42b4aba74d4e71014b5bf4670e5c05",
    },
}
# A subject with no hash_alg, which relies on the verifier's fallback. The digest is of b"x".
FROZEN_NO_HASH_ALG_MANIFEST = {
    "payloadType": "application/vnd.asexec+json",
    "payload": {
        **FROZEN_BODY,
        "subject": [
            {
                "name": "a.txt",
                "digest": {
                    "sha-256": "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"
                },
            }
        ],
    },
    "signature": {
        **FROZEN_KEY,
        "sig": "e222249eb2257f71248098758c4ce5fa0de8685b9e5304ca8941b107503d65e4"
        "675eebe8121959eb90d4ba95d85698d18fbd2b5cbb56b7b2a860438fe460ab08",
    },
}


def _result_tokens(tmp_path, mani, tests, artifacts_dir=None):
    # Only the result tokens, so a VERIFY_CODE_VERSION bump does not count as a broken manifest.
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(mani))
    return verify_paths([str(path)], tests, artifacts_dir=artifacts_dir)["code"].split()[1:]


def _bdr_passes(tmp_path, mani):
    return _result_tokens(tmp_path, mani, ["BDR"]) == ["BDR=PASS"]


def _signed_prereg():
    priv, pub = keys.generate()
    return manifest.sign(manifest.build_prereg("m"), priv, pub)


def test_every_identifier_is_classified():
    public = {name for name in vars(constants) if name.isupper()}
    assert public == set(IMPACT)


def test_frozen_manifests_still_verify(tmp_path):
    assert _bdr_passes(tmp_path, FROZEN_MANIFEST)

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "a.txt").write_bytes(b"x")
    assert _result_tokens(
        tmp_path, FROZEN_NO_HASH_ALG_MANIFEST, ["BDR", "content"], str(artifacts)
    ) == ["BDR=PASS", "content=PASS"]


def test_signing_pae_version_and_manifest_payload_type():
    # BREAKS_USERS: both are in the bytes every signature covers, so replacing either fails
    # every published signature. Refs don't change, because they hash the body without PAE.
    # Fallback: a new format entry, selected by payloadType. From 0.4.0 the PAE value is the
    # fixed DSSEv1, so payloadType is what carries the format version.
    assert constants.SIGNING_PAE_VERSION == b"asexec-PAE/v1"
    assert constants.MANIFEST_PAYLOAD_TYPE == "application/vnd.asexec+json"
    assert signing_input(FROZEN_BODY) == (
        b'asexec-PAE/v1 27 application/vnd.asexec+json 31 {"phase":"prereg","target":"m"}'
    )
    assert _signed_prereg()["payloadType"] == "application/vnd.asexec+json"


def test_digest_ref_prefix():
    # BREAKS_USERS: replacing it fails every published keyid and link.
    # Fallback: a new format entry, selected by payloadType. The label must never disagree
    # with the digest.
    assert constants.DIGEST_REF_PREFIX == "sha-256:"
    assert keys.keyid_for(bytes(32)) == (
        "sha-256:66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
    )
    assert manifest.ref({"a": 1}) == (
        "sha-256:015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862"
    )


def test_subject_default_hash_alg():
    # BREAKS_USERS: verifying ``content`` falls back to it for a subject with no hash_alg, so
    # replacing it fails those published manifests.
    # Fallback: split it in two. Each format's verify fallback never changes, and a new default
    # affects signing only, which always writes hash_alg.
    assert constants.SUBJECT_DEFAULT_HASH_ALG == "sha-256"
    assert hashing.hash_bytes(b"") == hashlib.sha256(b"").hexdigest()


def test_signing_key_alg():
    # BREAKS_USERS: existing key files stop loading. Verify is unaffected, but only because it
    # doesn't read signature.alg. Changing the string alone would mislabel ed25519 signatures.
    # Fallback: a new format entry, selected by payloadType, never by an unsigned field. Signing
    # with a new algorithm needs a new key.
    assert constants.SIGNING_KEY_ALG == "ed25519"
    assert _signed_prereg()["signature"]["alg"] == "ed25519"


def test_verify_code_version():
    # BREAKS_USERS: a new tool can't byte-match a published code in the old version.
    # Fallback: keep the old version available through ``--code-version``. Bump /N only if the
    # grammar or the documented meaning of an existing test name changes; adding a test name
    # needs no bump. Never reuse a number: a code means one thing, permanently.
    assert constants.VERIFY_CODE_VERSION == "asexec-verify/1"
    assert verify_paths([], ["BDR"])["code"].startswith("asexec-verify/1 ")


def test_identity_well_known_path():
    # BREAKS_USERS: moving it strands the documents domains have already published.
    # Fallback: fetch the new path, then the old one.
    assert constants.IDENTITY_WELL_KNOWN_PATH == ".well-known/asexec.json"


def test_manifest_schema_id_and_predicate_type():
    # NEW_OUTPUT: written into new signed bodies only, and verify doesn't compare them (see
    # below). A future test of these fields would move them to BREAKS_USERS.
    # MANIFEST_SCHEMA_ID is deliberately unversioned, with no parallel v1/v2 numbering.
    assert constants.MANIFEST_SCHEMA_ID == MANIFEST_SCHEMA_ID == "asexec"
    assert (
        constants.MANIFEST_PREDICATE_TYPE
        == MANIFEST_PREDICATE_TYPE
        == "https://asexec.dev/manifest"
    )
    body = manifest.build_prereg("m")
    assert body["schema_id"] == "asexec"
    assert body["predicateType"] == "https://asexec.dev/manifest"


def test_identity_document_version():
    # NEW_OUTPUT: nothing reads the number back. Bump it when the document's shape changes.
    assert constants.IDENTITY_DOCUMENT_VERSION == 1
    assert identity.build_wellknown([])["asexec_identity_version"] == 1


def test_not_enforced_yet__schema_id_and_predicate_type(tmp_path):
    assert "schema_id" not in FROZEN_MANIFEST["payload"]
    assert "predicateType" not in FROZEN_MANIFEST["payload"]
    assert _bdr_passes(tmp_path, FROZEN_MANIFEST)


def test_not_enforced_yet__envelope_payload_type(tmp_path):
    mani = copy.deepcopy(FROZEN_MANIFEST)
    mani["payloadType"] = "application/something-else"
    assert _bdr_passes(tmp_path, mani)


def test_not_enforced_yet__signature_alg(tmp_path):
    mani = copy.deepcopy(FROZEN_MANIFEST)
    mani["signature"]["alg"] = "something-else"
    assert _bdr_passes(tmp_path, mani)


def test_not_enforced_yet__digest_prefix_in_ceiling_binding():
    # A ceiling binds on the hex alone. "unpinned" is the next check after the nonce matches.
    ceiling = SimpleNamespace(witness_id="w", nonce="ab" * 32)
    assert roughtime.verify_ceiling(ceiling, "other:" + "ab" * 32, servers={})["status"] == (
        "unpinned"
    )
    assert roughtime.verify_ceiling(ceiling, "other:" + "cd" * 32, servers={})["status"] == (
        "invalid"
    )
