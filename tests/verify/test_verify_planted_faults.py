"""Planted faults: inputs the production writer refuses or cannot produce.

Built from ``tests/manifest_data.py`` alone, without ``Scenario``, to show what verify does
with files that someone else wrote. Faults that a ``test_verify_<name>.py`` file already
covers are not repeated here. Naming: ``test_fault__<what>``. An ``xfail`` marks behaviour
that looks wrong against docs/VERIFICATION.md; it is recorded here, not fixed.
"""

import json

import manifest_data as d
import pytest

from asexec import keys
from asexec.verifier import verify_paths

PREFIX = "asexec-verify/1 "
REQUIRED = ("format", "selfsig")
TESTS_LINKED = ("chain", "format", "keyconsist", "selfsig")


def _run(tmp_path, *manifests, tests=REQUIRED):
    """Verify ``manifests`` (envelopes, or raw file text) with the scenario's artifacts."""
    paths = []
    for i, mani in enumerate(manifests):
        path = tmp_path / f"m{i}.json"
        path.write_text(mani if isinstance(mani, str) else json.dumps(mani))
        paths.append(str(path))
    for rel, text in d.ARTIFACTS.items():
        (tmp_path / "artifacts" / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / "artifacts" / rel).write_text(text)
    return verify_paths(paths, list(tests), artifacts_dir=str(tmp_path / "artifacts"))


def _pair(prereg):
    """``prereg`` and the base postreg, re-linked to it, both signed."""
    return d.sign(prereg), d.sign(d.with_field(d.POSTREG, "fulfills", d.ref(prereg)))


def _content_reasons(report):
    return [
        e.get("reason", "digest mismatch")
        for m in report["manifests"]
        for e in (m.get("content") or {}).get("entries", [])
        if not e["ok"]
    ]


# --- subject and hash_alg -------------------------------------------------------- #


def test_fault__hash_alg_only_at_the_body_level(tmp_path):
    """Before 0.4.0 hash_alg sat beside the subject. A body laid out that way, with no
    hash_alg in its entries, fails content: an entry's own hash_alg is the only one read,
    and there is no default."""

    def use_old_layout(body):
        body = d.with_field(body, "hash_alg", "sha-256")
        for i in range(len(body["subject"])):
            body = d.without_field(body, f"subject.{i}.hash_alg")
        return body

    pre, post = (d.sign(use_old_layout(b)) for b in (d.PREREG, d.POSTREG))
    report = _run(tmp_path, pre, post, tests=(*REQUIRED, "content"))
    assert report["code"] == PREFIX + "content=FAIL format=PASS selfsig=PASS"
    assert set(_content_reasons(report)) == {"malformed subject entry"}


def test_fault__subject_entry_without_a_digest(tmp_path):
    report = _run(
        tmp_path,
        d.sign(d.without_field(d.PREREG, "subject.0.digest")),
        tests=(*REQUIRED, "content"),
    )
    assert report["code"] == PREFIX + "content=FAIL format=PASS selfsig=PASS"
    assert _content_reasons(report) == ["malformed subject entry"]


# --- fields the writer would never write ----------------------------------------- #


@pytest.mark.parametrize(
    "path,value",
    [
        ("surprise", {"x": 1}),
        ("schema_id", "asexec"),
        ("target", 5),
        ("declaration", ["a"]),
        ("notes", {"n": None}),
    ],
    ids=[
        "unknown-field",
        "schema_id-no-longer-written",
        "target-int",
        "declaration-list",
        "notes-object",
    ],
)
def test_fault__signed_body_field_verify_does_not_examine(tmp_path, path, value):
    """Unknown fields and wrong types in fields no test examines change nothing."""
    report = _run(tmp_path, *_pair(d.with_field(d.PREREG, path, value)), tests=TESTS_LINKED)
    assert report["code"] == PREFIX + "chain=PASS format=PASS keyconsist=PASS selfsig=PASS"
    assert report["commitments"][0]["state"] == "fulfilled"


def test_fault__empty_signed_body_passes_format_and_selfsig(tmp_path):
    """Documented: format does not establish that payload is a well-formed asexec body."""
    report = _run(tmp_path, d.sign({}))
    assert report["code"] == PREFIX + "format=PASS selfsig=PASS"
    assert report["commitments"] == [] and report["notarization_only"] == []


def test_fault__phase_not_a_string_joins_nothing(tmp_path):
    report = _run(tmp_path, d.sign(d.with_field(d.PREREG, "phase", ["prereg"])))
    assert report["code"] == PREFIX + "format=PASS selfsig=PASS"
    assert report["commitments"] == [] and report["notarization_only"] == []


_HEX = d.ref(d.PREREG).split(":")[1]


@pytest.mark.parametrize(
    "post",
    [
        d.with_field(d.POSTREG, "fulfills", "sha-256:" + _HEX.upper()),
        d.with_field(d.POSTREG, "fulfills", _HEX),
        d.without_field(d.POSTREG, "fulfills"),
    ],
    ids=["uppercase-hex", "no-prefix", "missing"],
)
def test_fault__fulfills_not_exactly_the_ref(tmp_path, post):
    """Matching #1 compares fulfills to ref(prereg) exactly; anything else links nowhere."""
    report = _run(tmp_path, d.sign(d.PREREG), d.sign(post), tests=TESTS_LINKED)
    assert report["code"] == PREFIX + "chain=FAIL format=PASS keyconsist=FAIL selfsig=PASS"
    assert report["commitments"][0]["counted_postregs"] == []
    assert len(report["notarization_only"]) == 1


# --- the file around the body ---------------------------------------------------- #


@pytest.mark.parametrize(
    "edit",
    [
        lambda env: env.update(surprise=1),
        lambda env: env.update(payloadType="application/vnd.asexec.v2+json"),
        lambda env: env["dsse"].update(surprise=1),
        lambda env: env["dsse"]["signatures"][0].update(alg="something-else"),
    ],
    ids=["unknown-field", "top-level-payload-type", "unknown-dsse-field", "signature-alg"],
)
def test_fault__unsigned_envelope_field_verify_does_not_examine(tmp_path, edit):
    """Fields of the file outside the body that this format does not define are read by no
    test: the format is dsse.payloadType, and the algorithm is the format's."""
    pre, post = _pair(d.PREREG)
    edit(pre)
    assert _run(tmp_path, pre, post, tests=TESTS_LINKED)["code"] == (
        PREFIX + "chain=PASS format=PASS keyconsist=PASS selfsig=PASS"
    )


SIGNED = d.sign(d.PREREG)
SIG = SIGNED["dsse"]["signatures"][0]


@pytest.mark.parametrize(
    "changes",
    [
        {"keyid": None},
        {"sig": d.encode_b64(d.decode_payload({"dsse": {"payload": SIG["sig"]}})[:63])},
        {"sig": d.encode_b64(d.decode_payload({"dsse": {"payload": SIG["sig"]}}) + b"\0")},
        {"sig": ""},
        {"sig": d.decode_payload({"dsse": {"payload": SIG["sig"]}}).hex()},
        {"pubkey": "00" * 31, "keyid": keys.keyid_for(bytes(31))},
        {"pubkey": "00" * 33},
    ],
    ids=[
        "keyid-missing",
        "sig-63-bytes",
        "sig-65-bytes",
        "sig-empty",
        "sig-as-hex",
        "pubkey-31-bytes",
        "pubkey-33-bytes",
    ],
)
def test_fault__signature_fields_of_the_wrong_shape(tmp_path, changes):
    """A key or signature of the wrong length (a hex sig, as earlier versions wrote, is
    base64 of 96 bytes), or a missing keyid, passes format and fails selfsig without
    raising."""
    env = d.sign(d.PREREG)
    for key, value in changes.items():
        holder = env if key == "pubkey" else env["dsse"]["signatures"][0]
        if value is None:
            del holder[key]
        else:
            holder[key] = value
    assert _run(tmp_path, env)["code"] == PREFIX + "format=PASS selfsig=FAIL"


@pytest.mark.parametrize("raw", [b"[1]", b'"x"'], ids=["list", "string"])
def test_fault__body_not_an_object(tmp_path, raw):
    assert _run(tmp_path, d.sign_bytes(raw))["code"] == PREFIX + "format=FAIL selfsig=FAIL"


@pytest.mark.parametrize("payload", [{}, [d.PREREG], d.PREREG], ids=["empty", "list", "object"])
def test_fault__payload_as_json_rather_than_base64(tmp_path, payload):
    """A payload stored as JSON, as asexec did before 0.4.0, is not the base64 of any body."""
    env = d.sign(d.PREREG)
    env["dsse"]["payload"] = payload
    assert _run(tmp_path, env)["code"] == PREFIX + "format=FAIL selfsig=FAIL"


def test_fault__very_deep_file_fails_format_everywhere(tmp_path):
    """100,000 levels: rejected before parsing, so the code is the same on every Python
    version and machine (the parser's own limit is not)."""
    raw = json.dumps(d.sign(d.PREREG))[:-1] + ', "junk": ' + "[" * 100_000 + "]" * 100_000 + "}"
    assert _run(tmp_path, raw)["code"] == PREFIX + "format=FAIL selfsig=FAIL"


def test_fault__very_deep_body_fails_format_everywhere(tmp_path):
    """The same for the body, validly signed: its own depth is checked before it is parsed."""
    raw = b'{"junk":' + b"[" * 100_000 + b"]" * 100_000 + b"}"
    assert _run(tmp_path, d.sign_bytes(raw))["code"] == PREFIX + "format=FAIL selfsig=FAIL"


def test_fault__postreg_with_a_duplicate_key_in_the_body_joins_no_commitment(tmp_path):
    """Run rules: a postreg whose body repeats a key is malformed, validly signed or not, so
    it is neither counted nor rejected, nor notarization-only."""
    post = d.with_field(d.POSTREG, "fulfills", d.ref(d.PREREG))
    raw = d.make_body_bytes(post).replace(b'"notes":"postreg0"', b'"notes":"a","notes":"postreg0"')
    report = _run(tmp_path, d.sign(d.PREREG), d.sign_bytes(raw), tests=TESTS_LINKED)
    assert report["code"] == PREFIX + "chain=FAIL format=FAIL keyconsist=FAIL selfsig=PASS"
    (commitment,) = report["commitments"]
    assert commitment["counted_postregs"] == [] and commitment["rejected_postregs"] == []
    assert report["notarization_only"] == []


def test_fault__nan_in_the_body_is_valid_json(tmp_path):
    """Valid JSON is what json.load accepts, and it accepts NaN."""
    assert _run(tmp_path, d.sign(d.with_field(d.PREREG, "notes", float("nan"))))["code"] == (
        PREFIX + "format=PASS selfsig=PASS"
    )
