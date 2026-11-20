"""Pins every asexec-defined identifier as a literal. A failure here means stop and think.

The values are written out on purpose. Importing them from ``asexec.constants`` would let
an edit there pass unnoticed, because the code and its test would move together. Do not
compare against the constants instead, and do not update a literal just to pass a test.

The rule, starting with the 0.4.0 release: add a new format version and keep accepting the old
ones. Never replace a value in a way that makes a manifest signed by 0.4.0 or later fail. Until
0.4.0 ships, breaking changes are allowed: get the format right rather than preserve it.

The selector is built (design: ``docs/MULTIVERSION.md``): ``FORMATS`` holds the rules of each
``payloadType`` verify reads, and a file is read under its own entry or fails ``format``. It
has one entry, so changing a value in it, or another BREAKS_USERS constant, does break users.
From 0.4.0, its fallback has to be built first, in the same PR (for a ``FORMATS`` value, a new
entry); the comment on each test says what it is.

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
5. Release it as a ``MINOR`` (``ROADMAP.md``, Versioning), or before 0.4.0 as a ``PATCH``, with
   this release-note entry:

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
    "FORMATS": BREAKS_USERS,
    "IDENTITY_WELL_KNOWN_PATH": BREAKS_USERS,
    "MANIFEST_PAYLOAD_TYPE": BREAKS_USERS,
    "VERIFY_CODE_VERSION": BREAKS_USERS,
    "IDENTITY_DOCUMENT_VERSION": NEW_OUTPUT,
    "MANIFEST_PREDICATE_TYPE": NEW_OUTPUT,
    "SUBJECT_DEFAULT_HASH_ALG": NEW_OUTPUT,
}

# Signed once with the all-zero seed and then frozen, standing in for published manifests.
FROZEN_KEY = {
    "alg": "ed25519",
    "keyid": "sha-256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070",
    "pubkey": "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
}
FROZEN_BODY = {"phase": "prereg", "target": "m"}
FROZEN_MANIFEST = {
    "payloadType": "application/vnd.asexec.v1+json",
    "payload": FROZEN_BODY,
    "signature": {
        **FROZEN_KEY,
        "sig": "afd85bcbaba92826ababc6860c09bd704fb18fe986470efddd6e601a1d6b3d1e"
        "857c315a4458043a7c8f096d694cb5eb78c21eebb43deea8901bb96948847e06",
    },
}
# A subject with no hash_alg, which relies on the verifier's fallback. The digest is of b"x".
FROZEN_NO_HASH_ALG_MANIFEST = {
    "payloadType": "application/vnd.asexec.v1+json",
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
        "sig": "13dccac3cdaa9d4d094d01a35a9643aa4a0fd62d67e27c4e511b71c712e63893"
        "b5b5f4f01e05a73630b6fc59c77e968395a239474c27b452a9280f2dfd3e3d0b",
    },
}

# FROZEN_MANIFEST as 0.3.x signed it, under the payloadType "application/vnd.asexec+json".
PRE_V1_MANIFEST = {
    "payloadType": "application/vnd.asexec+json",
    "payload": FROZEN_BODY,
    "signature": {
        **FROZEN_KEY,
        "sig": "2e993406b7492218b6a366a83fa99ecd53c9385bfb53c0bb00b5981ea83b8098"
        "008837c636d7467eae6d33afb377f62c2a42b4aba74d4e71014b5bf4670e5c05",
    },
}


def _report(tmp_path, manis, tests, artifacts_dir=None):
    paths = []
    for i, mani in enumerate(manis):
        path = tmp_path / f"manifest-{i}.json"
        path.write_text(json.dumps(mani))
        paths.append(str(path))
    return verify_paths(paths, tests, artifacts_dir=artifacts_dir)


def _result_tokens(tmp_path, mani, tests, artifacts_dir=None):
    # Only the result tokens, so a VERIFY_CODE_VERSION bump does not count as a broken manifest.
    return _report(tmp_path, [mani], tests, artifacts_dir)["code"].split()[1:]


def _required_tokens(tmp_path, mani):
    return _result_tokens(tmp_path, mani, ["format", "selfsig"])


def _required_pass(tmp_path, mani):
    return _required_tokens(tmp_path, mani) == ["format=PASS", "selfsig=PASS"]


def _signed_prereg():
    priv, pub = keys.generate()
    return manifest.sign(manifest.build_prereg("m"), priv, pub)


def _signing_format():
    # The entry signing uses. MANIFEST_PAYLOAD_TYPE is pinned as a literal below.
    return constants.FORMATS[constants.MANIFEST_PAYLOAD_TYPE]


def test_every_identifier_is_classified():
    public = {name for name in vars(constants) if name.isupper()}
    assert public == set(IMPACT)


def test_frozen_manifests_still_verify(tmp_path):
    assert _required_pass(tmp_path, FROZEN_MANIFEST)

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "a.txt").write_bytes(b"x")
    assert _result_tokens(
        tmp_path, FROZEN_NO_HASH_ALG_MANIFEST, ["content", "format", "selfsig"], str(artifacts)
    ) == ["content=PASS", "format=PASS", "selfsig=PASS"]


def test_formats_has_one_entry_keyed_by_manifest_payload_type():
    # BREAKS_USERS: verify reads a file only under the entry its payloadType names, so
    # editing an entry fails every manifest published under it, and removing one fails them
    # all as an unknown format. Fallback: add an entry instead; existing entries are never
    # edited. Each value is pinned again, with what it does, in the tests below.
    # One entry, keyed by the MANIFEST_PAYLOAD_TYPE name itself: a release commit rewrites
    # that one literal, and the key moves with it. Signing uses this entry, the newest.
    assert list(constants.FORMATS) == [constants.MANIFEST_PAYLOAD_TYPE]
    assert constants.FORMATS[constants.MANIFEST_PAYLOAD_TYPE] == {
        "digest_ref_prefix": "sha-256:",
        "signing_key_alg": "ed25519",
        "signing_pae_version": b"asexec-PAE/v1",
        "subject_default_hash_alg": "sha-256",
    }


def test_signing_pae_version_and_manifest_payload_type():
    # BREAKS_USERS: both are in the bytes every signature covers, so replacing either fails
    # every published signature. Refs don't change, because they hash the body without PAE.
    # The PAE value is the entry's signing_pae_version; MANIFEST_PAYLOAD_TYPE is the selector,
    # the key of the entry signing uses. Fallback: a new format entry, selected by
    # payloadType. From 0.4.0 the PAE value is the fixed DSSEv1, so payloadType is what
    # carries the format version.
    # The 0.4.0 format is v1, and a later format N is vN, matching MANIFEST_PREDICATE_TYPE.
    assert _signing_format()["signing_pae_version"] == b"asexec-PAE/v1"
    assert constants.MANIFEST_PAYLOAD_TYPE == "application/vnd.asexec.v1+json"
    assert signing_input(FROZEN_BODY) == (
        b'asexec-PAE/v1 30 application/vnd.asexec.v1+json 31 {"phase":"prereg","target":"m"}'
    )
    assert signing_input(FROZEN_BODY, constants.MANIFEST_PAYLOAD_TYPE) == (
        signing_input(FROZEN_BODY)
    )
    assert _signed_prereg()["payloadType"] == "application/vnd.asexec.v1+json"


def test_manifest_payload_type_change_fails_what_was_signed_before_it(tmp_path):
    # What BREAKS_USERS means for MANIFEST_PAYLOAD_TYPE: the same body and key, signed under
    # the type 0.3.x used, fails format, because no entry reads that type. Verify never falls
    # back to another entry, so the reason says what the file is, not "invalid signature".
    assert PRE_V1_MANIFEST["payload"] == FROZEN_MANIFEST["payload"]
    report = _report(tmp_path, [PRE_V1_MANIFEST], ["format", "selfsig"])
    assert report["code"].split()[1:] == ["format=FAIL", "selfsig=FAIL"]
    assert report["manifests"][0]["format"]["errors"] == [
        "payloadType names the format of asexec before 0.4.0, which is not supported:"
        " re-sign with this release"
    ]


# A second format, for the tests of the selector only: every rule differs from v1's.
OTHER_FORMAT = "application/vnd.asexec.other+json"
OTHER_RULES = {
    "digest_ref_prefix": "other-256:",
    "signing_key_alg": "ed25519",
    "signing_pae_version": b"asexec-PAE/other",
    "subject_default_hash_alg": "no-such-alg",
}


def _signed_under(payload_type, body):
    priv, pub = bytes(32), bytes.fromhex(FROZEN_KEY["pubkey"])
    return {
        "payloadType": payload_type,
        "payload": body,
        "signature": {
            "alg": "ed25519",
            "keyid": keys.keyid_for(pub, payload_type),
            "pubkey": pub.hex(),
            "sig": keys.sign(priv, signing_input(body, payload_type)).hex(),
        },
    }


def test_formats__a_file_is_read_under_its_own_entry(tmp_path, monkeypatch):
    # The selector (docs/MULTIVERSION.md, Verifier design): with a second entry, a file is
    # verified under the rules its own payloadType names, beside a v1 file under v1's.
    monkeypatch.setitem(constants.FORMATS, OTHER_FORMAT, OTHER_RULES)
    # No hash_alg: under its own rules content looks for digest["no-such-alg"], under v1's
    # for digest["sha-256"], which it lacks.
    body = {**FROZEN_BODY, "subject": [{"name": "a.txt", "digest": {"no-such-alg": "00"}}]}
    other = _signed_under(OTHER_FORMAT, body)
    assert signing_input(FROZEN_BODY, OTHER_FORMAT) == (
        b'asexec-PAE/other 33 application/vnd.asexec.other+json 31 {"phase":"prereg","target":"m"}'
    )
    assert other["signature"]["keyid"].startswith("other-256:")
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "a.txt").write_bytes(b"x")
    current = _signed_under(constants.MANIFEST_PAYLOAD_TYPE, FROZEN_NO_HASH_ALG_MANIFEST["payload"])
    report = _report(
        tmp_path,
        [current, other],
        ["content", "format", "selfsig"],
        str(artifacts),
    )
    v1, mine = report["manifests"]
    assert report["results"]["format"]["reason"] == "2/2 manifest(s) ok"
    assert report["results"]["selfsig"]["reason"] == "2/2 manifest(s) ok"  # each PAE, each keyid
    assert v1["ref"].startswith("sha-256:") and mine["ref"].startswith("other-256:")
    assert v1["content"]["status"] == "ok"  # falls back to v1's sha-256
    assert mine["content"]["entries"][0]["reason"] == "algorithm unavailable: 'no-such-alg'"


def test_formats__payload_type_is_signed_so_relabelling_fails_selfsig(tmp_path, monkeypatch):
    # Tampering (docs/MULTIVERSION.md, Testing): payloadType is in the signed bytes, so a file
    # relabelled with another known format reads under that format and fails selfsig. It is
    # never read under the rules of the format it was signed in.
    monkeypatch.setitem(constants.FORMATS, OTHER_FORMAT, OTHER_RULES)
    relabelled = [
        {
            **_signed_under(OTHER_FORMAT, FROZEN_BODY),
            "payloadType": constants.MANIFEST_PAYLOAD_TYPE,
        },
        {**FROZEN_MANIFEST, "payloadType": OTHER_FORMAT},
    ]
    for mani in relabelled:
        assert _required_tokens(tmp_path, mani) == ["format=PASS", "selfsig=FAIL"]


def test_formats__signing_uses_the_entry_of_manifest_payload_type(monkeypatch):
    # Signing always writes the newest format, whatever other entries exist.
    monkeypatch.setitem(constants.FORMATS, OTHER_FORMAT, OTHER_RULES)
    signed = _signed_prereg()
    assert signed["payloadType"] == constants.MANIFEST_PAYLOAD_TYPE
    assert signed["signature"]["keyid"].startswith("sha-256:")
    assert manifest.ref(signed["payload"]).startswith("sha-256:")


def test_digest_ref_prefix():
    # BREAKS_USERS (FORMATS): replacing it fails every published keyid and link.
    # Fallback: a new format entry, selected by payloadType. The label must never disagree
    # with the digest.
    assert _signing_format()["digest_ref_prefix"] == "sha-256:"
    assert keys.keyid_for(bytes(32)) == (
        "sha-256:66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
    )
    assert manifest.ref({"a": 1}) == (
        "sha-256:015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862"
    )


def test_subject_default_hash_alg():
    # NEW_OUTPUT: the signing default only, which picks the hash_alg a new subject is hashed
    # with. Signing always writes hash_alg beside a subject, so changing it fails nothing
    # published. Verify's fallback for a subject with no hash_alg is the format's own (below).
    assert constants.SUBJECT_DEFAULT_HASH_ALG == "sha-256"
    assert hashing.hash_bytes(b"") == hashlib.sha256(b"").hexdigest()


def test_format_subject_default_hash_alg():
    # BREAKS_USERS (FORMATS): verifying ``content`` falls back to it for a subject with no
    # hash_alg, so replacing it fails those published manifests
    # (FROZEN_NO_HASH_ALG_MANIFEST). Fallback: a new format entry; each format's verify
    # fallback never changes.
    assert _signing_format()["subject_default_hash_alg"] == "sha-256"


def test_signing_key_alg():
    # BREAKS_USERS (FORMATS): existing key files stop loading. Verify is unaffected, but only
    # because it doesn't read signature.alg. Changing the string alone would mislabel ed25519
    # signatures. Fallback: a new format entry, selected by payloadType, never by an unsigned
    # field. Signing with a new algorithm needs a new key.
    assert _signing_format()["signing_key_alg"] == "ed25519"
    assert _signed_prereg()["signature"]["alg"] == "ed25519"


def test_verify_code_version():
    # BREAKS_USERS: a new tool can't byte-match a published code in the old version.
    # Fallback: keep the old version available through ``--code-version``. Bump /N only if the
    # grammar or the documented meaning of an existing test name changes; adding a test name
    # needs no bump. From 0.4.0, never change what a number means; 0.4.0 keeps /1.
    assert constants.VERIFY_CODE_VERSION == "asexec-verify/1"
    assert verify_paths([], ["format", "selfsig"])["code"].startswith("asexec-verify/1 ")


def test_identity_well_known_path():
    # BREAKS_USERS: moving it strands the documents domains have already published.
    # Fallback: fetch the new path, then the old one.
    assert constants.IDENTITY_WELL_KNOWN_PATH == ".well-known/asexec.json"


def test_manifest_predicate_type():
    # NEW_OUTPUT: written into new signed bodies only, and verify doesn't compare it (see
    # below). A future test of this field would move it to BREAKS_USERS.
    # Versioned like MANIFEST_PAYLOAD_TYPE: vN goes with payloadType vN. The body has no
    # other format identifier: schema_id was removed, as a third one that could disagree.
    assert (
        constants.MANIFEST_PREDICATE_TYPE
        == MANIFEST_PREDICATE_TYPE
        == "https://asexec.org/manifest/v1"
    )
    body = manifest.build_prereg("m")
    assert body["predicateType"] == "https://asexec.org/manifest/v1"
    assert "schema_id" not in body


def test_identity_document_version():
    # NEW_OUTPUT: nothing reads the number back. Bump it when the document's shape changes.
    assert constants.IDENTITY_DOCUMENT_VERSION == 1
    assert identity.build_wellknown([])["asexec_identity_version"] == 1


def test_not_enforced_yet__predicate_type(tmp_path):
    assert "predicateType" not in FROZEN_MANIFEST["payload"]
    assert _required_pass(tmp_path, FROZEN_MANIFEST)


def test_not_enforced_yet__signature_alg(tmp_path):
    mani = copy.deepcopy(FROZEN_MANIFEST)
    mani["signature"]["alg"] = "something-else"
    assert _required_pass(tmp_path, mani)


def test_not_enforced_yet__digest_prefix_in_ceiling_binding():
    # A ceiling binds on the hex alone. "unpinned" is the next check after the nonce matches.
    ceiling = SimpleNamespace(witness_id="w", nonce="ab" * 32)
    assert roughtime.verify_ceiling(ceiling, "other:" + "ab" * 32, servers={})["status"] == (
        "unpinned"
    )
    assert roughtime.verify_ceiling(ceiling, "other:" + "cd" * 32, servers={})["status"] == (
        "invalid"
    )
