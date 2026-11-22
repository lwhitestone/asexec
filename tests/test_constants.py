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

import base64
import copy
import hashlib
import json
import re
from types import SimpleNamespace

import pytest

from asexec import (
    MANIFEST_PREDICATE_TYPE,
    constants,
    hashing,
    identity,
    keys,
    manifest,
    roughtime,
)
from asexec.canonical import build_signing_input, serialize_canonical
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
# Each is a DSSE envelope in the asexec wrapper: dsse.payload is the base64 of the body bytes.
FROZEN_KEY = {
    "keyid": "sha-256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070",
    "pubkey": "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
}
FROZEN_BODY = {"phase": "prereg", "target": "m"}
FROZEN_BODY_BYTES = b'{"phase":"prereg","target":"m"}'
FROZEN_MANIFEST = {
    "dsse": {
        "payloadType": "application/vnd.asexec.v1+json",
        "payload": "eyJwaGFzZSI6InByZXJlZyIsInRhcmdldCI6Im0ifQ==",
        "signatures": [
            {
                "keyid": FROZEN_KEY["keyid"],
                "sig": "Ob82ilGMEivKXPiY/S76agTjJrP5vNi0AohtyFB4DOEsI6/p240P"
                "mZnCtN/g0P5bjJrwLCIcn6C7e4MjLwimDw==",
            }
        ],
    },
    "pubkey": FROZEN_KEY["pubkey"],
}
# A subject entry carrying its own hash_alg, as every entry must. The digest is of b"x".
FROZEN_SUBJECT_MANIFEST = {
    "dsse": {
        "payloadType": "application/vnd.asexec.v1+json",
        "payload": (
            "eyJwaGFzZSI6InByZXJlZyIsInN1YmplY3QiOlt7ImRpZ2VzdCI6eyJzaGEtMjU2IjoiMmQ3MTE2NDJi"
            "NzI2YjA0NDAxNjI3Y2E5ZmJhYzMyZjVjODUzMGZiMTkwM2NjNGRiMDIyNTg3MTc5MjFhNDg4MSJ9LCJo"
            "YXNoX2FsZyI6InNoYS0yNTYiLCJuYW1lIjoiYS50eHQifV0sInRhcmdldCI6Im0ifQ=="
        ),
        "signatures": [
            {
                "keyid": FROZEN_KEY["keyid"],
                "sig": "s/vhj6pty0QZTWYjEZWWqyeyZflL0HLnjwJS2nUNbQpy6KKpbn1WuTTc"
                "NEsX+o/0CVPMfvke+1qgOqVR3ki7BQ==",
            }
        ],
    },
    "pubkey": FROZEN_KEY["pubkey"],
}
A_TXT_DIGEST = "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"
FROZEN_SUBJECT_BODY = {
    **FROZEN_BODY,
    "subject": [{"name": "a.txt", "hash_alg": "sha-256", "digest": {"sha-256": A_TXT_DIGEST}}],
}
# Signed before subject entries carried their own hash_alg: a subject with no hash_alg at
# all, which content read under the format's default. There is no default now.
NO_HASH_ALG_MANIFEST = {
    "dsse": {
        "payloadType": "application/vnd.asexec.v1+json",
        "payload": (
            "eyJwaGFzZSI6InByZXJlZyIsInN1YmplY3QiOlt7ImRpZ2VzdCI6eyJzaGEtMjU2IjoiMmQ3MTE2NDJi"
            "NzI2YjA0NDAxNjI3Y2E5ZmJhYzMyZjVjODUzMGZiMTkwM2NjNGRiMDIyNTg3MTc5MjFhNDg4MSJ9LCJu"
            "YW1lIjoiYS50eHQifV0sInRhcmdldCI6Im0ifQ=="
        ),
        "signatures": [
            {
                "keyid": FROZEN_KEY["keyid"],
                "sig": "MrRTzCmZpaeniNSl87VqNBFM7m4rHfXV3bzaBQDXZdfsv1r9Usey"
                "+6FIKYA24bHnMAJjkupF++kl4DmzCs8SCw==",
            }
        ],
    },
    "pubkey": FROZEN_KEY["pubkey"],
}

# FROZEN_BODY as 0.3.x signed it: its layout (no dsse; the body as a JSON object, signed over
# its canonical bytes under the asexec-PAE/v1 prefix) and its payloadType
# "application/vnd.asexec+json". A genuine 0.3.x file, never regenerated.
PRE_V1_MANIFEST = {
    "payloadType": "application/vnd.asexec+json",
    "payload": FROZEN_BODY,
    "signature": {
        "alg": "ed25519",
        **FROZEN_KEY,
        "sig": "2e993406b7492218b6a366a83fa99ecd53c9385bfb53c0bb00b5981ea83b8098"
        "008837c636d7467eae6d33afb377f62c2a42b4aba74d4e71014b5bf4670e5c05",
    },
}

# The format the frozen vectors are signed in, released by 0.4.0.
V1_PAYLOAD_TYPE = "application/vnd.asexec.v1+json"


def _is_before_v1(payload_type):
    pattern = r"application/vnd\.asexec\.(0\.3\.[0-9]+|0\.4\.0b[0-9]+)\+json"
    return re.fullmatch(pattern, payload_type) is not None


# The release commit of a 0.3.x (from 0.3.21) or of a 0.4.0 beta sets MANIFEST_PAYLOAD_TYPE to
# its own type, and the build reads that type only, so the frozen v1 vectors read as an unknown
# format there. Every test that reads them is skipped in that build, and
# test_current_format_sign_then_verify_roundtrip covers the current entry instead (D6b and D6c
# in docs/040b1-PATH.md). Only those builds: they come before any format is released, and
# every later build, betas included, still reads v1 and runs these tests
# (test_v1_is_read_by_every_build_from_0_4_0).
frozen_v1 = pytest.mark.skipif(
    _is_before_v1(constants.MANIFEST_PAYLOAD_TYPE),
    reason="a 0.3.x or 0.4.0 beta build does not read v1, the frozen vectors' format (D6b, D6c)",
)


def _get_report(tmp_path, manis, tests, artifacts_dir=None):
    paths = []
    for i, mani in enumerate(manis):
        path = tmp_path / f"manifest-{i}.json"
        path.write_text(json.dumps(mani))
        paths.append(str(path))
    return verify_paths(paths, tests, artifacts_dir=artifacts_dir)


def _get_result_tokens(tmp_path, mani, tests, artifacts_dir=None):
    # Only the result tokens, so a VERIFY_CODE_VERSION bump does not count as a broken manifest.
    return _get_report(tmp_path, [mani], tests, artifacts_dir)["code"].split()[1:]


def _get_required_tokens(tmp_path, mani):
    return _get_result_tokens(tmp_path, mani, ["format", "selfsig"])


def _passes_required(tmp_path, mani):
    return _get_required_tokens(tmp_path, mani) == ["format=PASS", "selfsig=PASS"]


def _signed_prereg():
    priv, pub = keys.generate()
    return manifest.sign(manifest.build_prereg("m"), priv, pub)


def _decode_payload(mani):
    return base64.b64decode(mani["dsse"]["payload"], validate=True)


def _get_signing_format():
    # The entry signing uses. MANIFEST_PAYLOAD_TYPE is pinned as a literal below.
    return constants.FORMATS[constants.MANIFEST_PAYLOAD_TYPE]


def test_every_identifier_is_classified():
    public = {name for name in vars(constants) if name.isupper()}
    assert public == set(IMPACT)


@frozen_v1
def test_frozen_manifests_still_verify(tmp_path):
    assert _passes_required(tmp_path, FROZEN_MANIFEST)

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "a.txt").write_bytes(b"x")
    assert json.loads(_decode_payload(FROZEN_SUBJECT_MANIFEST)) == FROZEN_SUBJECT_BODY
    assert _get_result_tokens(
        tmp_path, FROZEN_SUBJECT_MANIFEST, ["content", "format", "selfsig"], str(artifacts)
    ) == ["content=PASS", "format=PASS", "selfsig=PASS"]


def test_formats_has_one_entry_keyed_by_manifest_payload_type():
    # BREAKS_USERS: verify reads a file only under the entry its payloadType names, so
    # editing an entry fails every manifest published under it, and removing one fails them
    # all as an unknown format. Fallback: add an entry instead; a released entry is never
    # edited or re-keyed. Each value is pinned again, with what it does, in the tests below.
    # One entry, the one under development, keyed by the MANIFEST_PAYLOAD_TYPE name itself:
    # each beta's release commit rewrites that one literal, and the key moves with it.
    # Signing uses this entry, the newest. scripts/release.sh's 0.4.0 release commit makes
    # its key the literal "application/vnd.asexec.v1+json"; this pin holds either way.
    assert list(constants.FORMATS) == [constants.MANIFEST_PAYLOAD_TYPE]
    assert constants.FORMATS[constants.MANIFEST_PAYLOAD_TYPE] == {
        "digest_ref_prefix": "sha-256:",
        "signing_key_alg": "ed25519",
        "signing_pae_version": b"DSSEv1",
    }


def test_signing_pae_version_and_manifest_payload_type():
    # BREAKS_USERS: both are in the bytes every signature covers, so replacing either fails
    # every published signature. Refs don't change, because they hash the body bytes alone.
    # The PAE value is the entry's signing_pae_version, DSSE's own "DSSEv1", which standard
    # DSSE tooling requires and asexec does not version; MANIFEST_PAYLOAD_TYPE, the selector
    # read from dsse.payloadType and the key of the entry signing uses, is what carries the
    # format version. Fallback: a new format entry, selected by payloadType.
    # The 0.4.0 format is v1, and a later format N is vN, matching MANIFEST_PREDICATE_TYPE.
    # A beta writes application/vnd.asexec.X.Y.ZbN+json, and a 0.3.x from 0.3.21
    # application/vnd.asexec.0.3.N+json. scripts/release.sh rewrites the
    # MANIFEST_PAYLOAD_TYPE literal in the release commit, here and in constants.py, and this
    # is the one line in this file that holds it: the others compare against it.
    assert _get_signing_format()["signing_pae_version"] == b"DSSEv1"
    assert constants.MANIFEST_PAYLOAD_TYPE == "application/vnd.asexec.0.3.21+json"
    assert build_signing_input(FROZEN_BODY_BYTES, constants.MANIFEST_PAYLOAD_TYPE) == (
        build_signing_input(FROZEN_BODY_BYTES)
    )
    assert _signed_prereg()["dsse"]["payloadType"] == constants.MANIFEST_PAYLOAD_TYPE


@frozen_v1
def test_signing_input_of_the_frozen_v1_vector():
    # The bytes a v1 signature covers (FROZEN_MANIFEST's). Replacing the PAE version or the
    # type, or how they are framed, fails every published v1 signature.
    # DSSE's PAE: "DSSEv1" SP len(type) SP type SP len(body) SP body, over the body bytes as
    # stored (FROZEN_MANIFEST's dsse.payload decodes to them), never re-serialized.
    assert _decode_payload(FROZEN_MANIFEST) == FROZEN_BODY_BYTES
    assert build_signing_input(FROZEN_BODY_BYTES, V1_PAYLOAD_TYPE) == (
        b'DSSEv1 30 application/vnd.asexec.v1+json 31 {"phase":"prereg","target":"m"}'
    )


@frozen_v1
def test_ref_of_the_frozen_v1_vector_is_the_digest_of_its_stored_body_bytes(tmp_path):
    # ref = sha-256 of the bytes dsse.payload decodes to. Replacing what ref hashes fails every
    # published fulfills and prev_hash link, and every ceiling nonce.
    ref = "sha-256:" + hashlib.sha256(FROZEN_BODY_BYTES).hexdigest()
    assert ref == ("sha-256:2e2ecfe58f9e44cc6ac359b15857029bf231a027d1276c1715f970c25248e53e")
    assert manifest.derive_ref(FROZEN_BODY_BYTES) == ref
    assert (
        _get_report(tmp_path, [FROZEN_MANIFEST], ["format", "selfsig"])["manifests"][0]["ref"]
        == ref
    )


def test_v1_is_read_by_every_build_from_0_4_0():
    # Never skipped. From 0.4.0 on, v1 is released, and every later build reads it under its
    # own entry, keyed by the literal (scripts/release.sh writes that key in the 0.4.0 release
    # commit). Only a 0.3.x or 0.4.0 beta build, made before any format was released, doesn't. A
    # release commit that re-keyed the released entry fails here.
    assert _is_before_v1(constants.MANIFEST_PAYLOAD_TYPE) or (V1_PAYLOAD_TYPE in constants.FORMATS)


@pytest.mark.parametrize(
    "payload_type,skipped",
    [
        ("application/vnd.asexec.0.4.0b1+json", True),
        ("application/vnd.asexec.0.4.0b12+json", True),
        ("application/vnd.asexec.0.3.21+json", True),
        ("application/vnd.asexec.0.3.105+json", True),
        ("application/vnd.asexec+json", False),  # 0.3.20 and earlier
        ("application/vnd.asexec.0.30.1+json", False),
        ("application/vnd.asexec.0.3.21b1+json", False),  # no such release
        ("application/vnd.asexec.v1+json", False),
        ("application/vnd.asexec.0.5.0b1+json", False),  # v1 is released by then
        ("application/vnd.asexec.0.4.1b1+json", False),
        ("application/vnd.asexec.10.4.0b1+json", False),
        ("application/vnd.asexec.0.4.0rc1+json", False),
        ("application/vnd.asexec.0.4.0b1+json ", False),
    ],
)
def test_frozen_v1_vectors_are_skipped_only_before_v1(payload_type, skipped):
    assert _is_before_v1(payload_type) is skipped


def test_current_format_sign_then_verify_roundtrip(tmp_path):
    # Runs in every build, and is what checks the current entry while the frozen vectors are
    # skipped (D6b): files signed now pass format and selfsig through verify, each ref and
    # keyid carries the entry's prefix, and content reads each subject entry's own hash_alg.
    # It does not freeze signed bytes; the frozen vectors do.
    entry = _get_signing_format()
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "a.txt").write_bytes(b"x")
    priv, pub = keys.generate()
    subject = [
        {
            "name": "a.txt",
            "hash_alg": "sha-256",
            "digest": {"sha-256": hashlib.sha256(b"x").hexdigest()},
        }
    ]
    written = manifest.sign(manifest.build_prereg("m", subject=subject), priv, pub)
    # Not from the writer: a body signed as anyone could, with the entry's own hash_alg.
    hand_built = _sign_under(constants.MANIFEST_PAYLOAD_TYPE, FROZEN_SUBJECT_BODY)
    manis = [written, hand_built]
    assert [m["dsse"]["payloadType"] for m in manis] == [constants.MANIFEST_PAYLOAD_TYPE] * 2

    report = _get_report(tmp_path, manis, ["content", "format", "selfsig"], str(artifacts))
    assert report["code"].split()[1:] == ["content=PASS", "format=PASS", "selfsig=PASS"]
    assert report["results"]["format"]["reason"] == "2/2 manifest(s) ok"
    assert report["results"]["selfsig"]["reason"] == "2/2 manifest(s) ok"
    assert [m["content"]["status"] for m in report["manifests"]] == ["ok", "ok"]
    for mani, shown in zip(manis, report["manifests"], strict=True):
        assert mani["dsse"]["signatures"][0]["keyid"].startswith(entry["digest_ref_prefix"])
        assert shown["ref"].startswith(entry["digest_ref_prefix"])
        assert shown["ref"] == manifest.derive_ref(
            _decode_payload(mani)
        )  # the stored bytes' digest

    # selfsig checked the signatures: the same files changed after signing fail it.
    tampered = copy.deepcopy(manis)
    for mani in tampered:
        changed = {**json.loads(_decode_payload(mani)), "target": "n"}
        mani["dsse"]["payload"] = base64.b64encode(serialize_canonical(changed)).decode()
    report = _get_report(tmp_path, tampered, ["format", "selfsig"])
    assert report["code"].split()[1:] == ["format=PASS", "selfsig=FAIL"]
    assert report["results"]["selfsig"]["reason"] == "2/2 manifest(s) failed"


def test_manifest_payload_type_change_fails_what_was_signed_before_it(tmp_path):
    # What BREAKS_USERS means for MANIFEST_PAYLOAD_TYPE: the same body and key, signed under
    # the type 0.3.x used, fails format, because no entry reads that type. Verify never falls
    # back to another entry, so the reason says what the file is, not "invalid signature".
    assert PRE_V1_MANIFEST["payload"] == FROZEN_BODY == json.loads(_decode_payload(FROZEN_MANIFEST))
    report = _get_report(tmp_path, [PRE_V1_MANIFEST], ["format", "selfsig"])
    assert report["code"].split()[1:] == ["format=FAIL", "selfsig=FAIL"]
    assert report["manifests"][0]["format"]["errors"] == [
        "payloadType names the format of asexec before 0.4.0, which is not supported:"
        " re-sign with this release"
    ]


# A second format, for the tests of the selector only: every rule but signing_key_alg differs
# from v1's (ed25519 is the only algorithm verify checks).
OTHER_FORMAT = "application/vnd.asexec.other+json"
OTHER_RULES = {
    "digest_ref_prefix": "other-256:",
    "signing_key_alg": "ed25519",
    "signing_pae_version": b"asexec-PAE/other",
}


def _sign_under(payload_type, body):
    priv, pub = bytes(32), bytes.fromhex(FROZEN_KEY["pubkey"])
    raw = serialize_canonical(body)
    return {
        "dsse": {
            "payloadType": payload_type,
            "payload": base64.b64encode(raw).decode(),
            "signatures": [
                {
                    "keyid": keys.derive_keyid(pub, payload_type),
                    "sig": base64.b64encode(
                        keys.sign(priv, build_signing_input(raw, payload_type))
                    ).decode(),
                }
            ],
        },
        "pubkey": pub.hex(),
    }


def _relabel_copy(mani, payload_type):
    return {**mani, "dsse": {**mani["dsse"], "payloadType": payload_type}}


def test_formats__a_file_is_read_under_its_own_entry(tmp_path, monkeypatch):
    # The selector (docs/MULTIVERSION.md, Verifier design): with a second entry, a file is
    # verified under the rules its own payloadType names, beside a v1 file under v1's.
    monkeypatch.setitem(constants.FORMATS, OTHER_FORMAT, OTHER_RULES)
    other = _sign_under(OTHER_FORMAT, FROZEN_BODY)
    assert build_signing_input(FROZEN_BODY_BYTES, OTHER_FORMAT) == (
        b'asexec-PAE/other 33 application/vnd.asexec.other+json 31 {"phase":"prereg","target":"m"}'
    )
    assert other["dsse"]["signatures"][0]["keyid"].startswith("other-256:")
    current = _sign_under(constants.MANIFEST_PAYLOAD_TYPE, FROZEN_BODY)
    report = _get_report(tmp_path, [current, other], ["format", "selfsig"])
    v1, mine = report["manifests"]
    assert report["results"]["format"]["reason"] == "2/2 manifest(s) ok"
    assert report["results"]["selfsig"]["reason"] == "2/2 manifest(s) ok"  # each PAE, each keyid
    assert v1["ref"].startswith("sha-256:") and mine["ref"].startswith("other-256:")


def test_formats__payload_type_is_signed_so_relabelling_fails_selfsig(tmp_path, monkeypatch):
    # Tampering (docs/MULTIVERSION.md, Testing): payloadType is in the signed bytes, so a file
    # relabelled with another known format reads under that format and fails selfsig. It is
    # never read under the rules of the format it was signed in.
    monkeypatch.setitem(constants.FORMATS, OTHER_FORMAT, OTHER_RULES)
    relabelled = [
        _relabel_copy(_sign_under(OTHER_FORMAT, FROZEN_BODY), constants.MANIFEST_PAYLOAD_TYPE),
        _relabel_copy(FROZEN_MANIFEST, OTHER_FORMAT),
    ]
    for mani in relabelled:
        assert _get_required_tokens(tmp_path, mani) == ["format=PASS", "selfsig=FAIL"]


def test_formats__signing_uses_the_entry_of_manifest_payload_type(monkeypatch):
    # Signing always writes the newest format, whatever other entries exist.
    monkeypatch.setitem(constants.FORMATS, OTHER_FORMAT, OTHER_RULES)
    signed = _signed_prereg()
    assert signed["dsse"]["payloadType"] == constants.MANIFEST_PAYLOAD_TYPE
    assert signed["dsse"]["signatures"][0]["keyid"].startswith("sha-256:")
    assert manifest.derive_ref(_decode_payload(signed)).startswith("sha-256:")


def test_digest_ref_prefix():
    # BREAKS_USERS (FORMATS): replacing it fails every published keyid and link.
    # Fallback: a new format entry, selected by payloadType. The label must never disagree
    # with the digest.
    assert _get_signing_format()["digest_ref_prefix"] == "sha-256:"
    assert keys.derive_keyid(bytes(32)) == (
        "sha-256:66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"
    )
    assert manifest.derive_ref(b'{"a":1}') == (
        "sha-256:015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862"
    )


def test_subject_default_hash_alg(tmp_path):
    # NEW_OUTPUT: the signing default only, which picks the hash_alg a new subject entry is
    # hashed with. Signing writes it into every entry, so changing it fails nothing
    # published. Verify has no fallback: it reads each entry's own (below).
    assert constants.SUBJECT_DEFAULT_HASH_ALG == "sha-256"
    empty = tmp_path / "empty"
    empty.write_bytes(b"")
    assert hashing.hash_file(str(empty), constants.SUBJECT_DEFAULT_HASH_ALG) == (
        hashlib.sha256(b"").hexdigest()
    )


@frozen_v1
def test_subject_entry_hash_alg_has_no_fallback(tmp_path):
    # What removing the format's subject_default_hash_alg broke: a subject entry with no
    # hash_alg of its own, which content used to read as sha-256, is now a malformed entry.
    # Each entry carries its own hash_alg, and no format supplies one.
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "a.txt").write_bytes(b"x")
    report = _get_report(
        tmp_path, [NO_HASH_ALG_MANIFEST], ["content", "format", "selfsig"], str(artifacts)
    )
    assert report["code"].split()[1:] == ["content=FAIL", "format=PASS", "selfsig=PASS"]
    assert report["manifests"][0]["content"]["entries"][0]["reason"] == "malformed subject entry"


def test_signing_key_alg(tmp_path):
    # BREAKS_USERS (FORMATS): existing key files stop loading, and identity documents name
    # it. Verify is unaffected: a manifest names no algorithm (a DSSE signature entry is
    # keyid and sig only), and the format's is the one it checks. Changing the string alone
    # would mislabel ed25519 keys. Fallback: a new format entry, selected by payloadType,
    # never by an unsigned field. Signing with a new algorithm needs a new key.
    assert _get_signing_format()["signing_key_alg"] == "ed25519"
    keys.save(bytes(32), str(tmp_path / "k.key"))
    assert json.loads((tmp_path / "k.key.pub").read_text())["alg"] == "ed25519"
    assert identity.build_wellknown([{"keyid": "k", "pubkey": "p"}], None)["keys"][0]["alg"] == (
        "ed25519"
    )
    (entry,) = _signed_prereg()["dsse"]["signatures"]
    assert set(entry) == {"keyid", "sig"}
    assert len(base64.b64decode(entry["sig"], validate=True)) == 64  # base64, as DSSE has it


def test_verify_code_version():
    # BREAKS_USERS: a new tool can't byte-match a published code in the old version.
    # Fallback: keep the old version available through ``--code-version``. Bump /N only if the
    # grammar or the documented meaning of an existing test name changes; adding a test name
    # needs no bump. From 0.4.0, never change what a number means; 0.4.0 keeps /1.
    assert constants.VERIFY_CODE_VERSION == "asexec-verify/1"
    assert verify_paths([], ["format", "selfsig"], None)["code"].startswith("asexec-verify/1 ")


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
    assert identity.build_wellknown([], None)["asexec_identity_version"] == 1


@frozen_v1
def test_not_enforced_yet__predicate_type(tmp_path):
    assert "predicateType" not in json.loads(_decode_payload(FROZEN_MANIFEST))
    assert _passes_required(tmp_path, FROZEN_MANIFEST)


@frozen_v1
def test_not_enforced_yet__signature_alg(tmp_path):
    # An "alg" in the signature entry, which this format does not define, is not read.
    mani = copy.deepcopy(FROZEN_MANIFEST)
    mani["dsse"]["signatures"][0]["alg"] = "something-else"
    assert _passes_required(tmp_path, mani)


def test_not_enforced_yet__digest_prefix_in_ceiling_binding():
    # A ceiling binds on the hex alone. "unpinned" is the next check after the nonce matches.
    ceiling = SimpleNamespace(witness_id="w", nonce="ab" * 32)
    assert roughtime.verify_ceiling(ceiling, "other:" + "ab" * 32, servers={})["status"] == (
        "unpinned"
    )
    assert roughtime.verify_ceiling(ceiling, "other:" + "cd" * 32, servers={})["status"] == (
        "invalid"
    )
