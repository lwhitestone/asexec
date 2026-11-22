"""Manifest build/sign/ref + the signing gate (asexec schema)."""

import base64
import subprocess
import sys
import time

import pytest
from pydantic import ValidationError

import asexec
from asexec import MANIFEST_PREDICATE_TYPE, drand, keys, manifest
from asexec.canonical import canonical_bytes, signing_input
from asexec.constants import MANIFEST_PAYLOAD_TYPE
from asexec.errors import ManifestError
from asexec.models import BODY_FIELDS, WRAPPER_FIELDS, Ceiling, Dsse, Manifest, Signature


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
    """The file is {dsse: {payloadType, payload, signatures: [{keyid, sig}]}, pubkey,
    untrusted: {asexec_version}}, and dsse.payload is the base64 of the body's canonical
    serialization."""
    priv, pub = keys.generate()
    body = manifest.build_prereg(_target(), due=DUE, subject=_subj())
    signed = manifest.sign(body, priv, pub)
    assert list(signed) == ["dsse", "pubkey", "untrusted"]
    assert signed["untrusted"] == {"asexec_version": asexec.__version__}
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


def test_sign_refuses_a_body_nested_deeper_than_format_reads():
    """A body more than 64 deep would fail format #2: the writer refuses it (the CLI's inputs
    are held to 63 for a value inside the body, so this is the backstop)."""
    priv, pub = keys.generate()
    deep: dict = {}
    for _ in range(63):  # 64 deep, so the body holding it is 65
        deep = {"a": deep}
    with pytest.raises(ManifestError, match="the body would be nested more than 64 deep"):
        manifest.build_prereg(_target(), notes=deep)
    body = {**manifest.build_prereg(_target()), "notes": deep}  # built by hand
    with pytest.raises(ManifestError, match="the body would be nested more than 64 deep"):
        manifest.sign(body, priv, pub)
    manifest.sign(manifest.build_prereg(_target(), notes=deep["a"]), priv, pub)  # 64: signed


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


def test_an_unterminated_string_is_refused_in_linear_time():
    # each escaped quote was rescanned to the end: this took about half a minute
    text = '"' + '\\"' * 40_000
    start = time.monotonic()
    with pytest.raises(ManifestError):
        manifest.parse_body(text.encode())
    assert time.monotonic() - start < 5


# Run in a thread with a small stack, where recursing into a deep body segfaults instead of
# raising RecursionError, so in a process of its own.
_REFUSE_DEEP_BODY = """
import sys, threading
from asexec import keys, manifest
from asexec.errors import ManifestError

value = {}
for _ in range(5000):
    value = {"a": value}

def refuse():
    try:
        if sys.argv[1] == "sign":
            body = {"predicateType": "x", "phase": "prereg", "target": value}
            manifest.sign(body, *keys.generate())
        elif sys.argv[1] == "target":
            manifest.build_prereg(value)
        else:
            manifest.build_prereg("t", repro_recipe=value)
    except ManifestError as e:
        print(e)

threading.stack_size(256 * 1024)
thread = threading.Thread(target=refuse)
thread.start()
thread.join()
"""


@pytest.mark.parametrize("route", ["sign", "target", "repro_recipe"])
def test_a_deep_body_is_refused_before_anything_recurses_into_it(route):
    run = subprocess.run(
        [sys.executable, "-c", _REFUSE_DEEP_BODY, route], capture_output=True, text=True, timeout=60
    )
    assert (run.returncode, run.stdout) == (0, "the body would be nested more than 64 deep\n")


def test_a_cyclic_body_is_refused():
    target = {}
    target["self"] = target
    with pytest.raises(ManifestError, match="more than 64 deep"):
        manifest.build_prereg(target)


def test_the_depth_check_visits_a_shared_value_once_per_level():
    shared = []
    for _ in range(70):
        shared = [shared, shared]  # 2**70 paths, 71 distinct lists
    with pytest.raises(ManifestError, match="more than 64 deep"):
        manifest.sign({"predicateType": "x", "phase": "prereg", "target": shared}, *keys.generate())


@pytest.mark.parametrize("value", [None, "", 123, ["sha-256:00"]])
def test_sign_refuses_a_postreg_whose_fulfills_is_not_a_non_empty_string(value):
    body = manifest.build_postreg(_target(), fulfills="sha-256:00")
    body["fulfills"] = value
    with pytest.raises(ManifestError, match="fulfills"):
        manifest.sign(body, *keys.generate())


def test_subject_optional_at_prereg():
    # a pre-registration may commit to a target before hashing a harness.
    priv, pub = keys.generate()
    body = manifest.build_prereg(_target(), due=DUE)
    assert "subject" not in body and "hash_alg" not in body
    signed = manifest.sign(body, priv, pub)  # the gate needs no subject
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


def test_signing_refuses_a_body_without_target():
    priv, pub = keys.generate()
    body = {
        "predicateType": MANIFEST_PREDICATE_TYPE,
        "phase": "prereg",
        "due": DUE,
    }
    with pytest.raises(ManifestError):
        manifest.sign(body, priv, pub)


def test_signing_refuses_a_body_without_predicate_type():
    priv, pub = keys.generate()
    body = manifest.build_prereg(_target(), due=DUE, subject=_subj())
    del body["predicateType"]
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


# What this format defines, as verify reads it to list unknown fields (VERIFICATION.md,
# Untrusted): each field, and for an object or an array of objects the format defines, its
# fields. A free-form value (target, declaration, notes, repro_recipe, a digest) has
# no fields: what it holds is its value.
_ENTRY = {"name": None, "hash_alg": None, "digest": None}
KNOWN_BODY = {
    "predicateType": None,
    "phase": None,
    "target": None,
    "due": None,
    "declaration": None,
    "subject": ("array", _ENTRY),
    "fulfills": None,
    "prev_hash": None,
    "plan": ("object", {**_ENTRY, "media_type": None, "label": None}),
    "items": ("array", {"id": None, "kind": None}),
    "item_id": None,
    "status": None,
    "evidence": ("array", {**_ENTRY, "media_type": None, "uri": None}),
    "anchor": (
        "object",
        {
            "floor": (
                "object",
                {"floor_type": None, "chain_hash": None, "round": None, "signature": None,
                 "randomness": None},
            )
        },
    ),
    "provenance": None,
    "repro_recipe": None,
    "notes": None,
}  # fmt: skip
KNOWN_WRAPPER = {
    "dsse": (
        "object",
        {"payloadType": None, "payload": None,
         "signatures": ("array", {"keyid": None, "sig": None})},
    ),
    "pubkey": None,
    "untrusted": None,  # shown whole: nothing in it is a field of the format
    "ceiling": (
        "object",
        {"ceiling_type": None, "nonce": None, "witness_id": None, "pubkey": None,
         "response": None, "midpoint": None, "radius": None},
    ),
}  # fmt: skip


def test_known_fields_are_what_the_writer_models_define():
    """The fields verify treats as known are those the writer models can write, derived from
    them, so a field added to a writer model is known to verify in the same change."""
    assert BODY_FIELDS == KNOWN_BODY
    assert WRAPPER_FIELDS == KNOWN_WRAPPER
