"""Pins every asexec-defined identifier as a literal. A failure here means stop and think.

The values are written out on purpose. Importing them from ``asexec.constants`` would let
an edit there pass unnoticed, because the code and its test would move together. Do not
"simplify" these tests to compare against the constants, and do not update a literal just
to make a test pass.

To change an identifier deliberately:

1. Read its section below: what it reaches, and who it breaks.
2. Change ``asexec.constants`` and the literals here in the same commit.
3. Release it under the versioning rules in ``ROADMAP.md`` (Versioning). A change to the
   manifest format, the signed bytes, or a verify test's documented meaning is a ``MINOR``
   and is called out in the release notes. Update the README, ``docs/VERIFICATION.md`` and
   any golden vectors in the same change.

Several identifiers are NOT checked when a published manifest is verified: only the
sections marked "Verify enforces" change the result for a manifest that already exists.
The others affect what is newly written, so an old manifest keeps its old value and still
passes. Reading one of those as "a mismatch fails verify" would be wrong.
"""

import hashlib
import json
import re

from asexec import PREDICATE_TYPE, SCHEMA_VERSION, constants, hashing, identity, keys, manifest
from asexec.canonical import signing_input
from asexec.verifier import verify_paths

# A manifest signed once with the all-zero seed and then frozen, standing in for one that
# has already been published. Never regenerate it for a change that is meant to be
# compatible: that it still verifies, unchanged, is the point of the test using it.
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


def test_pae_prefix_and_payload_type():
    # PAE_PREFIX and PAYLOAD_TYPE. Verify enforces: both are in the bytes ``BDR`` checks
    # the signature over (``canonical.signing_input``), and signer and verifier supply them
    # from the code, never from the file.
    #
    # Reaches: the signing input of every manifest. PAYLOAD_TYPE is also written to the
    # envelope's ``payloadType``, but the verifier never reads that field.
    # Breaks: every published signature fails ``BDR``, since the verifier has no way to
    # accept the old value.
    # To change: a format break, so a MINOR. Bump the ``/vN`` of the prefix, or adopt a new
    # prefix outright, as 0.4.0 plans with ``DSSEv1``. The code version does not move
    # unless the documented meaning of a test does.
    assert constants.PAE_PREFIX == b"asexec-PAE/v1"
    assert constants.PAYLOAD_TYPE == "application/vnd.asexec+json"
    assert signing_input(FROZEN_BODY) == (
        b'asexec-PAE/v1 27 application/vnd.asexec+json 31 {"phase":"prereg","target":"m"}'
    )


def test_frozen_manifest_still_verifies(tmp_path):
    # The end-to-end guard: a published manifest must keep passing. It fails if PAE_PREFIX,
    # PAYLOAD_TYPE or DIGEST_PREFIX moves, or if canonicalization or the code prefix drifts.
    path = tmp_path / "prereg.json"
    path.write_text(json.dumps(FROZEN_MANIFEST))
    assert verify_paths([str(path)], ["BDR"])["code"] == "asexec-verify/1 BDR=PASS"


def test_schema_version_and_predicate_type():
    # SCHEMA_VERSION and PREDICATE_TYPE. Written, not enforced: signing requires the fields
    # to be present (``manifest._check_bedrock``), but verify does not compare their values.
    # ``FROZEN_MANIFEST`` has neither and passes ``BDR`` (VERIFICATION.md: any validly signed
    # object passes). The planned ``frame`` test is what would start enforcing them.
    #
    # Reaches: the signed body, and so the signature and ``ref``, of new manifests.
    # Breaks: nothing already published.
    # To change: a manifest format change, so a MINOR. ``SCHEMA_VERSION`` is deliberately
    # unversioned, with no parallel v1/v2 numbering. 0.4.0 plans a new ``PREDICATE_TYPE``.
    assert constants.SCHEMA_VERSION == SCHEMA_VERSION == "asexec"
    assert constants.PREDICATE_TYPE == PREDICATE_TYPE == "https://asexec.dev/manifest"
    body = manifest.build_prereg("m")
    assert body["schema_version"] == "asexec"
    assert body["predicateType"] == "https://asexec.dev/manifest"


def test_code_version():
    # CODE_VERSION. Written, not enforced: it is the prefix of the code ``verify`` prints
    # (``verifier._build_code``), never signed or read back.
    #
    # Breaks: anyone comparing a code byte for byte, which is how a code is reproduced.
    # To change: bump ``/N`` only if the grammar or the documented meaning of an existing
    # test name changes. Adding a test name needs no bump, since a code names its tests. A
    # meaning change is a MINOR. Never reuse a number: a code means one thing, permanently.
    # The ``tests/verify`` suite spells this out too, and must move with it.
    assert constants.CODE_VERSION == "asexec-verify/1"
    assert verify_paths([], ["BDR"])["code"].startswith("asexec-verify/1 ")


def test_digest_prefix():
    # DIGEST_PREFIX. Verify enforces: ``BDR`` recomputes ``keyid`` and compares the prefixed
    # string exactly, and links between manifests (``fulfills``, ``prev_hash``) match refs
    # the same way. The CLI validates links with ``cli.REF_RE``. ``ceiling`` is the exception:
    # ``roughtime.verify_ceiling`` strips the prefix and compares only the hex.
    #
    # Breaks: every published ``keyid`` and link, but not ceiling nonces.
    # To change: a format break, so a MINOR. The prefix names a hash, and ``keys.keyid_for``
    # and ``manifest.ref`` call ``hashlib.sha256`` directly: change those with it, so that
    # the label never disagrees with the digest. Keep ``DEFAULT_HASH_ALG`` separate.
    assert constants.DIGEST_PREFIX == "sha-256:"
    assert keys.keyid_for(bytes(32)) == (
        "sha-256:66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
    )
    assert manifest.ref({"a": 1}) == (
        "sha-256:015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862"
    )
    assert re.fullmatch(r"sha-256:[0-9a-f]{64}", manifest.ref(FROZEN_BODY))


def test_default_hash_alg():
    # DEFAULT_HASH_ALG. Verify enforces, narrowly: ``content`` falls back to it when a
    # manifest has a subject but no ``hash_alg`` (absent or null). A manifest that names its
    # algorithm is unaffected.
    #
    # Reaches: the ``hash_alg`` written beside new subjects, and the name looked up in
    # ``hashing._ALGORITHMS``. That registry keeps its own "sha-256" entry on purpose: it
    # maps a name to a function, so a default that nothing implements fails loudly.
    # Breaks: ``content`` for published manifests that rely on the fallback.
    # To change: a MINOR, because the meaning of ``content`` changes for those manifests.
    assert constants.DEFAULT_HASH_ALG == "sha-256"
    assert hashing.hash_bytes(b"") == hashlib.sha256(b"").hexdigest()


def test_key_alg():
    # KEY_ALG. Enforced only when loading a signing key (``keys.load_signing_key`` rejects
    # any other ``alg``). Verify does not read ``signature.alg``: it always checks ed25519.
    #
    # Reaches: key files, the signature block, and identity documents.
    # Breaks: every existing key file. Changing the string alone is not a new algorithm:
    # the signing code would still be ed25519, under a false label.
    # To change: a format break, so a MINOR, along with the implementation in ``keys``.
    assert constants.KEY_ALG == "ed25519"
    priv, pub = keys.generate()
    signed = manifest.sign(manifest.build_prereg("m"), priv, pub)
    assert signed["signature"]["alg"] == "ed25519"


def test_identity_document():
    # WELL_KNOWN_PATH and IDENTITY_ASSERTION_VERSION. Outside verify and outside the signed
    # bytes: ``identity.match_binding`` fetches the path and reads only ``keys``, and nothing
    # compares the version number.
    #
    # Breaks: moving the path orphans every document domains have already published.
    # To change: not a signed-format change, but one that strands domains, so call it out in
    # the release notes. Bump the integer when the document's shape changes.
    assert constants.WELL_KNOWN_PATH == ".well-known/asexec.json"
    assert constants.IDENTITY_ASSERTION_VERSION == 1
    assert identity.build_wellknown([])["asexec_identity_version"] == 1


def test_payload_type_is_written_to_the_envelope():
    # See test_pae_prefix_and_payload_type: the same constant, at its other use.
    priv, pub = keys.generate()
    signed = manifest.sign(manifest.build_prereg("m"), priv, pub)
    assert signed["payloadType"] == "application/vnd.asexec+json"
