"""Pins every asexec-defined identifier as a literal. A failure here means stop and think.

The values are written out on purpose. Importing them from ``asexec.constants`` would let
an edit there pass unnoticed, because the code and its test would move together. Do not
compare against the constants instead, and do not update a literal just to pass a test.

Each identifier is in one of three change classes, named in a comment on its test:

MAJOR ONLY: published manifests stop verifying, and only re-signing can repair them.
    Needs a major release. Before 1.0.0 a ``0.MINOR`` release stands in for one, as the
    ``DSSEv1`` switch does in 0.4.0.

BREAKING: published manifests still verify, but people or tools relying on the value break.
    Needs at least a ``MINOR`` release, with the break and the required action stated in the
    release notes.

MINOR: only newly written files change, and nothing already published is affected.
    Needs a ``MINOR`` release, with the change listed in the release notes.

To change an identifier, in one PR:

1. Change ``asexec.constants`` and the literals here.
2. Update the README, ``docs/VERIFICATION.md`` and any golden vectors.
3. Regenerate ``FROZEN_MANIFEST`` only for a MAJOR ONLY change. For any other class it must
   keep passing untouched; if it fails, the change is in the wrong class.
4. Release it under the class above and the rules in ``ROADMAP.md`` (Versioning).

The ``test_not_enforced_yet__*`` tests record what verify does not check today. They are not
requirements: when one fails because enforcement was added, update it and reclassify the
identifier if needed.
"""

import copy
import hashlib
import json
from types import SimpleNamespace

from asexec import (
    PREDICATE_TYPE,
    SCHEMA_VERSION,
    constants,
    hashing,
    identity,
    keys,
    manifest,
    roughtime,
)
from asexec.canonical import signing_input
from asexec.verifier import verify_paths

# Signed once with the all-zero seed and then frozen, standing in for a published manifest.
FROZEN_BODY = {"phase": "prereg", "target": "m"}
FROZEN_MANIFEST = {
    "payloadType": "application/vnd.asexec+json",
    "payload": FROZEN_BODY,
    "signature": {
        "alg": "ed25519",
        "keyid": "sha-256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070",
        "pubkey": "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
        "sig": "2e993406b7492218b6a366a83fa99ecd53c9385bfb53c0bb00b5981ea83b8098"
        "008837c636d7467eae6d33afb377f62c2a42b4aba74d4e71014b5bf4670e5c05",
    },
}


def _bdr_passes(tmp_path, mani):
    # Only the result token, so that a CODE_VERSION bump does not count as a broken manifest.
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(mani))
    return verify_paths([str(path)], ["BDR"])["code"].endswith(" BDR=PASS")


def _signed_prereg():
    priv, pub = keys.generate()
    return manifest.sign(manifest.build_prereg("m"), priv, pub)


def test_frozen_manifest_still_verifies(tmp_path):
    assert _bdr_passes(tmp_path, FROZEN_MANIFEST)


def test_pae_prefix_and_payload_type():
    # MAJOR ONLY. Both are in the bytes every signature covers, so changing either
    # invalidates every published signature. Bump the prefix's /vN or adopt a new prefix.
    assert constants.PAE_PREFIX == b"asexec-PAE/v1"
    assert constants.PAYLOAD_TYPE == "application/vnd.asexec+json"
    assert signing_input(FROZEN_BODY) == (
        b'asexec-PAE/v1 27 application/vnd.asexec+json 31 {"phase":"prereg","target":"m"}'
    )
    assert _signed_prereg()["payloadType"] == "application/vnd.asexec+json"


def test_digest_prefix():
    # MAJOR ONLY. Invalidates every published keyid and link. The prefix names a hash, so
    # changing the hash must change the prefix with it; the label never disagrees with the
    # digest.
    assert constants.DIGEST_PREFIX == "sha-256:"
    assert keys.keyid_for(bytes(32)) == (
        "sha-256:66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
    )
    assert manifest.ref({"a": 1}) == (
        "sha-256:015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862"
    )


def test_default_hash_alg():
    # MAJOR ONLY. Verifying ``content`` falls back to this for a subject with no hash_alg, so
    # changing it fails those published manifests.
    assert constants.DEFAULT_HASH_ALG == "sha-256"
    assert hashing.hash_bytes(b"") == hashlib.sha256(b"").hexdigest()


def test_key_alg():
    # MAJOR ONLY. Existing key files stop loading. Changing the string alone does not change
    # the algorithm: it would label ed25519 signatures as something else, so the signing and
    # verifying code must change with it.
    assert constants.KEY_ALG == "ed25519"
    assert _signed_prereg()["signature"]["alg"] == "ed25519"


def test_code_version():
    # BREAKING. Anyone reproducing a code compares it byte for byte. Bump /N only if the
    # grammar or the documented meaning of an existing test name changes; adding a test name
    # needs no bump. Never reuse a number: a code means one thing, permanently.
    assert constants.CODE_VERSION == "asexec-verify/1"
    assert verify_paths([], ["BDR"])["code"].startswith("asexec-verify/1 ")


def test_well_known_path():
    # BREAKING. Moving it strands the documents domains have already published. Tell them
    # what to move in the release notes.
    assert constants.WELL_KNOWN_PATH == ".well-known/asexec.json"


def test_schema_version_and_predicate_type():
    # MINOR. Written into new signed bodies only (see the test below). SCHEMA_VERSION is
    # deliberately unversioned, with no parallel v1/v2 numbering.
    assert constants.SCHEMA_VERSION == SCHEMA_VERSION == "asexec"
    assert constants.PREDICATE_TYPE == PREDICATE_TYPE == "https://asexec.dev/manifest"
    body = manifest.build_prereg("m")
    assert body["schema_version"] == "asexec"
    assert body["predicateType"] == "https://asexec.dev/manifest"


def test_identity_assertion_version():
    # MINOR. Nothing reads the number back. Bump it when the identity document's shape changes.
    assert constants.IDENTITY_ASSERTION_VERSION == 1
    assert identity.build_wellknown([])["asexec_identity_version"] == 1


def test_not_enforced_yet__schema_version_and_predicate_type(tmp_path):
    assert "schema_version" not in FROZEN_MANIFEST["payload"]
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
