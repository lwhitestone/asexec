"""``untrusted`` and unknown fields: docs/VERIFICATION.md `## Untrusted`.

``untrusted`` is the wrapper's unsigned section for metadata that nothing checks. Verify shows
it, and any key outside the body that this format does not define, for each file that passes
``format``; it shows any body field this format does not define as unknown and unchecked. No
test reads any of them, and none is part of ``ref``, so none changes a verdict.

Naming: ``test_untrusted__<rule>`` and ``test_unknown__<rule>``; the report's record of each
manifest lists them under ``untrusted`` and ``unknown`` as ``{path, value}``, the path a list
of keys and indexes from the file's root (``["body", "subject", 0, "colour"]``).
"""

import copy
import json

import manifest_data as d
import pytest

from asexec.verifier import TEST_CATALOG

ALL_TESTS = tuple(t for t in TEST_CATALOG if t not in ("format", "selfsig"))


@pytest.fixture
def sc(scenario):
    """The all-passing scenario with a ceiling on every manifest, a plan and items on the
    prereg, and an item and evidence on a postreg, so that most tests examine something a
    change might reach. (No floor: each costs about a second of BLS math per run.)"""
    for name in ("prereg", "postreg0", "postreg1", "postreg2"):
        scenario.with_ceiling(name)
    scenario.mutate("prereg", lambda body: body.update(plan=copy.deepcopy(d.PLAN)))
    scenario.mutate("prereg", lambda body: body.update(items=[{"id": "S1"}]))
    claim = {"item_id": "S1", "status": "reported", "evidence": d.EVIDENCE}
    scenario.mutate("postreg0", lambda body: body.update(copy.deepcopy(claim)))
    return scenario


def _get_record(report, name):
    (rec,) = [m for m in report["manifests"] if m["path"].endswith(f"/{name}.json")]
    return rec


def _get_verdicts(report):
    """Everything a verdict rests on: the code, every result, and every commitment."""
    return report["code"], report["results"], report["commitments"], report["rejected_preregs"]


def _get_results(report):
    """The verdicts of a run whose bodies changed, so whose refs did: the code, every result
    and every commitment's state."""
    return report["code"], report["results"], [c["state"] for c in report["commitments"]]


def _set_untrusted(sc, value, names=("prereg", "postreg0", "postreg1", "postreg2")):
    for name in names:
        sc.tamper(name, lambda env: env.update(untrusted=copy.deepcopy(value)))


# --- untrusted ---------------------------------------------------------------- #


def test_untrusted__shown_for_each_file_and_read_by_no_test(sc):
    """untrusted is shown, as it is, for each file that has it, and no test reads it: every
    result and commitment is the same with it as without it."""
    before = sc.verify(*ALL_TESTS)
    value = {"asexec_version": "9.9.9", "run": {"host": "x", "argv": ["a", 1, None, True]}}
    _set_untrusted(sc, value)
    after = sc.verify(*ALL_TESTS)
    assert _get_verdicts(after) == _get_verdicts(before)
    for name in ("prereg", "postreg0", "postreg1", "postreg2"):
        assert _get_record(after, name)["untrusted"] == [{"path": ["untrusted"], "value": value}]
        assert _get_record(before, name)["untrusted"] == []


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("a string", id="string"),
        pytest.param(5, id="number"),
        pytest.param(False, id="false"),
        pytest.param([1, "x", {}], id="list"),
        pytest.param({}, id="empty-object"),
        pytest.param(float("nan"), id="nan"),
        pytest.param({"asexec_version": {"not": "a string"}}, id="version-not-a-string"),
        pytest.param("x" * 1_000_000, id="huge-string"),
        pytest.param(list(range(100_000)), id="huge-list"),
        pytest.param({f"k{i}": i for i in range(10_000)}, id="many-keys"),
        pytest.param(json.loads("[" * 62 + "]" * 62), id="nested-to-the-file-limit"),
        pytest.param("\ud800 \x00 ‮", id="lone-surrogate-nul-and-bidi"),
    ],
)
def test_untrusted__any_value_changes_no_verdict(sc, value):
    """untrusted may be any JSON value, of any size, nested as deep as the file's JSON rules
    allow: it never makes a file malformed and never changes a result."""
    before = sc.verify(*ALL_TESTS)
    _set_untrusted(sc, value)
    after = sc.verify(*ALL_TESTS)
    assert _get_verdicts(after) == _get_verdicts(before)
    shown = _get_record(after, "prereg")["untrusted"]
    assert len(shown) == 1 and shown[0]["path"] == ["untrusted"]


def test_untrusted__null_is_absent(sc):
    """An untrusted of null is absent (Run rules), so nothing is shown."""
    _set_untrusted(sc, None)
    assert _get_record(sc.verify(), "prereg")["untrusted"] == []


def test_untrusted__is_not_part_of_ref(sc):
    """ref is the digest of the body bytes, so editing untrusted leaves every ref, and with
    it every link and every ceiling's nonce, as it was."""
    before = sc.verify("ceiling", "chain")
    _set_untrusted(sc, {"asexec_version": "0.0.1"})
    after = sc.verify("ceiling", "chain")
    assert [m["ref"] for m in after["manifests"]] == [m["ref"] for m in before["manifests"]]
    assert (
        after["code"]
        == before["code"]
        == ("asexec-verify/1 ceiling=PASS chain=PASS format=PASS selfsig=PASS")
    )


def test_untrusted__is_held_to_the_file_json_rules(sc):
    """untrusted is part of the file, so the file's JSON rules hold inside it as everywhere: a
    duplicate key there makes the whole file malformed, as a duplicate key anywhere does (a
    parser could otherwise read a different file). That is format's rule, not a reading of
    untrusted: format=FAIL, and the file joins no commitment."""
    raw = sc.read("postreg2")[:-2] + ', "untrusted": {"a": 1, "a": 2}\n}\n'
    sc.drop("postreg2")
    sc.add_raw("postreg2-dup", raw)
    report = sc.verify("chain")
    rec = _get_record(report, "postreg2-dup")
    assert rec["format"]["errors"] == ["malformed: duplicate JSON key 'a'"]
    assert rec["untrusted"] == []
    assert report["code"] == "asexec-verify/1 chain=PASS format=FAIL selfsig=PASS"


def test_untrusted__deeper_than_the_file_limit_makes_the_file_malformed(sc):
    """The same for depth: the file, untrusted included, nests at most 64 deep."""
    sc.set("postreg2", "untrusted", json.loads("[" * 64 + "]" * 64))
    report = sc.verify("chain")
    rec = _get_record(report, "postreg2")
    assert rec["format"]["errors"] == ["malformed: nested more than 64 deep"]
    assert report["code"] == "asexec-verify/1 chain=PASS format=FAIL selfsig=PASS"


def test_untrusted__an_integer_past_the_digit_limit_makes_the_file_malformed(sc):
    """The same for an integer of more than 4,300 digits, which the file's JSON rules (Python's
    default limit) do not read: anywhere in the file, untrusted included."""
    raw = sc.read("postreg2")[:-2] + ', "untrusted": {"big": ' + "1" * 5001 + "}\n}\n"
    sc.drop("postreg2")
    sc.add_raw("postreg2-big", raw)
    report = sc.verify("chain")
    (error,) = _get_record(report, "postreg2-big")["format"]["errors"]
    assert error.startswith("malformed: Exceeds the limit (4300 digits)")
    assert report["code"] == "asexec-verify/1 chain=PASS format=FAIL selfsig=PASS"


def test_untrusted__not_shown_for_a_file_that_fails_format(scenario):
    """A file that fails format is read by nothing past format, untrusted included."""
    env = d.make_malformed(d.PREREG)
    env["untrusted"] = {"asexec_version": "1"}
    scenario.add_raw("bad", json.dumps(env))
    rec = _get_record(scenario.verify(), "bad")
    assert rec["untrusted"] == [] and rec["unknown"] == []


# --- keys outside the body this format does not define ------------------------ #


@pytest.mark.parametrize(
    "path,value,shown",
    [
        pytest.param("surprise", {"x": 1}, ["surprise"], id="top-level"),
        pytest.param("payloadType", "v9", ["payloadType"], id="top-level-payloadType"),
        pytest.param("dsse.extra", 1, ["dsse", "extra"], id="in-dsse"),
        pytest.param("dsse.signatures[0].alg", "ed25519", ["dsse", "signatures", 0, "alg"],
                     id="in-the-signature-entry"),
        pytest.param("ceiling.extra", [1], ["ceiling", "extra"], id="in-the-ceiling"),
        pytest.param("a\nb", "c", ["a\nb"], id="key-with-a-newline"),
    ],
)  # fmt: skip
def test_untrusted__unknown_keys_outside_the_body_are_shown_with_it(sc, path, value, shown):
    """Any key outside the body that this format does not define, at the top level or inside
    dsse, a signature entry or the ceiling, is unsigned and read by no test: it is shown with
    untrusted, and changes no verdict."""
    before = sc.verify(*ALL_TESTS)
    sc.set("prereg", path, value)
    after = sc.verify(*ALL_TESTS)
    assert _get_verdicts(after) == _get_verdicts(before)
    assert _get_record(after, "prereg")["untrusted"] == [{"path": shown, "value": value}]


def test_untrusted__the_section_comes_first_then_the_keys_in_file_order(sc):
    sc.tamper("prereg", lambda env: env.update(zz=1, untrusted={"asexec_version": "x"}, aa=2))
    shown = _get_record(sc.verify(), "prereg")["untrusted"]
    assert [s["path"] for s in shown] == [["untrusted"], ["zz"], ["aa"]]


def test_untrusted__known_keys_are_not_listed(sc):
    """dsse, its payloadType, payload and signatures (each keyid and sig), pubkey, the ceiling
    and its fields are the format's own: none is listed, even the ceiling's unsigned
    midpoint and radius."""
    report = sc.verify()
    assert all(m["untrusted"] == [] for m in report["manifests"])


# --- unknown signed fields ----------------------------------------------------- #


@pytest.mark.parametrize(
    "path,value,shown",
    [
        pytest.param("body.surprise", {"x": 1}, ["body", "surprise"], id="top-level"),
        pytest.param("body.hash_alg", "sha-256", ["body", "hash_alg"], id="body-level-hash_alg"),
        pytest.param("body.schema_id", "asexec", ["body", "schema_id"], id="schema_id"),
        pytest.param("body.identity", ["lab.example"], ["body", "identity"], id="identity"),
        pytest.param("body.subject.0.colour", "red", ["body", "subject", 0, "colour"],
                     id="in-a-subject-entry"),
        pytest.param("body.anchor.extra", 1, ["body", "anchor", "extra"], id="in-anchor"),
        pytest.param("body.anchor.floor.time", "2020", ["body", "anchor", "floor", "time"],
                     id="in-the-floor"),
        pytest.param("body.plan.x", 1, ["body", "plan", "x"], id="in-the-plan"),
        pytest.param("body.items.0.x", [], ["body", "items", 0, "x"], id="in-an-item"),
        pytest.param("body.evidence.0.x", 0, ["body", "evidence", 0, "x"],
                     id="in-an-evidence-entry"),
        pytest.param("body.a\nb", "c", ["body", "a\nb"], id="key-with-a-newline"),
    ],
)  # fmt: skip
def test_unknown__signed_fields_this_format_does_not_define_are_shown(sc, path, value, shown):
    """A body field this format does not define, at the top of the body or inside an object the
    format defines (a subject, plan or evidence entry, an item, anchor or its floor), is
    signed but read by no test: it is shown as unknown and unchecked, never dropped, and
    changes no verdict."""
    if path == "body.anchor.floor.time":
        sc.with_floor("prereg")  # a verified floor beside the unknown field
    before = sc.verify(*ALL_TESTS)
    name = "postreg0" if "evidence" in path else "prereg"  # the postreg carries the evidence
    sc.set(name, path, value)
    after = sc.verify(*ALL_TESTS)
    assert _get_results(after) == _get_results(before)  # a body edit changes refs, not verdicts
    if path == "body.anchor.floor.time":
        assert _get_record(after, "prereg")["floor"]["status"] == "verified"
    assert _get_record(after, name)["unknown"] == [{"path": shown, "value": value}]
    assert _get_record(after, name)["untrusted"] == []


def test_unknown__every_field_the_format_defines_is_known(scenario):
    """A body with every field this format defines, the free-form ones holding objects and
    lists of their own, lists nothing as unknown: what a free-form field holds is its value,
    not fields."""
    free = {"k": {"nested": [1, {"deep": True}]}}
    body = {
        **d.CLAIM_PREREG,
        "anchor": {"floor": d.FLOOR},
        "target": free,
        "declaration": free,
        "notes": free,
        "provenance": "reproducible",
        "repro_recipe": free,
        "fulfills": "sha-256:" + "0" * 64,
        "prev_hash": "sha-256:" + "1" * 64,
        "item_id": "S1",
        "status": "reported",
        "evidence": d.EVIDENCE,
    }
    body["subject"] = [{**body["subject"][0], "digest": {"sha-256": "00", "blake3": "11"}}]
    scenario.mutate("prereg", lambda b: (b.clear(), b.update(copy.deepcopy(body))))
    rec = _get_record(scenario.verify(), "prereg")
    assert rec["unknown"] == [] and rec["untrusted"] == []


@pytest.mark.parametrize(
    "path,value",
    [
        pytest.param("body.subject", "x", id="subject-not-a-list"),
        pytest.param("body.subject", ["x", 5], id="subject-entries-not-objects"),
        pytest.param("body.anchor", [{"extra": 1}], id="anchor-a-list"),
        pytest.param("body.items", {"id": "S1", "x": 1}, id="items-an-object"),
        pytest.param("body.plan", [{"x": 1}], id="plan-a-list"),
    ],
)
def test_unknown__a_known_field_of_the_wrong_shape_has_no_fields_to_list(sc, path, value):
    """A field the format defines, holding a value of the wrong shape, is a known field the
    tests judge (content, floor, complete): nothing inside it is listed."""
    sc.set("prereg", path, value)
    assert _get_record(sc.verify(), "prereg")["unknown"] == []


def test_unknown__a_null_field_is_absent(sc):
    """An unknown field whose value is null is absent (Run rules): nothing is shown."""
    sc.set("prereg", "body.surprise", None)
    sc.set("prereg", "body.subject.0.colour", None)
    assert _get_record(sc.verify(), "prereg")["unknown"] == []


def test_unknown__fields_are_listed_in_body_order(sc):
    sc.mutate("prereg", lambda body: body.update(zz=1, aa=2))
    sc.set("prereg", "body.subject.0.mid", 3)
    paths = [u["path"] for u in _get_record(sc.verify(), "prereg")["unknown"]]
    assert paths == [["body", "aa"], ["body", "subject", 0, "mid"], ["body", "zz"]]


def test_unknown__shown_for_postregs_and_rejected_preregs_alike(sc):
    """Unknown fields are shown for every file that passes format, whatever its phase and
    whether or not it meets the selfsig conditions."""
    sc.set("postreg1", "body.surprise", 1)
    sc.set("prereg", "body.surprise", 2, after_signing=True)
    report = sc.verify()
    assert _get_record(report, "postreg1")["unknown"] == [
        {"path": ["body", "surprise"], "value": 1}
    ]
    assert _get_record(report, "prereg")["unknown"] == [{"path": ["body", "surprise"], "value": 2}]
    assert len(report["rejected_preregs"]) == 1
