"""``complete`` (every committed item accounted for): docs/VERIFICATION.md `### complete`.
Naming: see conftest.py.

``sc`` is the scenario as a claim record: the prereg lists items S1, S2 and S3 and has
``due`` 2099-01-01T00:00:00Z, and postreg0, postreg1 and postreg2 account for S1, S2 and S3
with ``status`` ``reported``, each with a ceiling from the synthetic witness (its time T is
2023-11-14T22:13:21Z), so each is on time.
"""

import json

import manifest_data as d
import pytest

PASS = "asexec-verify/1 complete=PASS format=PASS selfsig=PASS"
FAIL = "asexec-verify/1 complete=FAIL format=PASS selfsig=PASS"
EMPTY = "requested but no commitment lists items"
POSTREGS = ("postreg0", "postreg1", "postreg2")
ITEMS = [{"id": "S1", "kind": "run"}, {"id": "S2", "kind": "run"}, {"id": "S3", "kind": "ablation"}]


@pytest.fixture
def sc(scenario):
    scenario.set("prereg", "body.items", ITEMS)
    for name, item in zip(POSTREGS, ("S1", "S2", "S3"), strict=True):
        scenario.set(name, "body.item_id", item)
        scenario.set(name, "body.status", "reported")
        scenario.with_ceiling(name)
    return scenario


def _get_complete(report):
    (commitment,) = report["commitments"]
    return commitment["complete"]


def _get_items(report):
    """``{id: reason or the statuses}`` for each item, in the prereg's order."""
    return {
        i["id"]: (", ".join(i["statuses"]) if i["ok"] else i["reason"])
        for i in _get_complete(report)["items"]
    }


def test_complete__pass__all(sc):
    """complete #1-#5: items is an array of objects with string ids, the ids are unique,
    each item has a counted postreg with its item_id and a known status, due parses, and
    such a postreg is on time."""
    report = sc.verify("complete")
    assert report["code"] == PASS
    assert report["results"]["complete"]["reason"] == "1/1 commitment(s) ok"
    assert _get_items(report) == {"S1": "reported", "S2": "reported", "S3": "reported"}


@pytest.mark.parametrize("status", ["excluded", "blocked"])
def test_complete__pass__3_each_status_accounts_for_an_item(sc, status):
    """complete #3: reported, excluded and blocked each account for the item."""
    sc.set("postreg1", "body.status", status)
    report = sc.verify("complete")
    assert report["code"] == PASS
    assert _get_items(report)["S2"] == status


@pytest.mark.parametrize(
    "items",
    ["S1", {"id": "S1"}, [1], [{"kind": "run"}], [{"id": 5}], [{"id": None}]],
    ids=["string", "object", "entry-not-object", "id-missing", "id-number", "id-null"],
)
def test_complete__fail__1_items_is_an_array_of_objects_with_string_ids(sc, items):
    """complete #1: a present body.items is an array of objects, each with a string id."""
    sc.set("prereg", "body.items", items)
    report = sc.verify("complete")
    assert report["code"] == FAIL
    assert _get_complete(report)["reason"] == "items is not an array of objects with a string id"


def test_complete__pass__1_kind_is_not_read(sc):
    """complete #1: an item's kind is declared, never tested."""
    sc.set("prereg", "body.items", [{"id": i, "kind": [5]} for i in ("S1", "S2", "S3")])
    assert sc.code("complete") == PASS


def test_complete__fail__2_item_ids_are_unique(sc):
    """complete #2: a prereg whose item ids repeat fails, even when every item is
    accounted for."""
    sc.set("prereg", "body.items", [*ITEMS, {"id": "S2", "kind": "again"}])
    report = sc.verify("complete")
    assert report["code"] == FAIL
    assert _get_complete(report)["reason"] == "item ids repeat: 'S2'"


def test_complete__fail__3_a_dropped_item(sc):
    """complete #3: an item no counted postreg accounts for fails, though the commitment is
    fulfilled and its chain is intact (here the last postreg, S3's, is not provided)."""
    sc.drop("postreg2")
    report = sc.verify("chain", "complete")
    assert report["code"] == "asexec-verify/1 chain=PASS complete=FAIL format=PASS selfsig=PASS"
    assert report["commitments"][0]["state"] == "fulfilled"
    assert _get_items(report) == {
        "S1": "reported",
        "S2": "reported",
        "S3": "no counted postreg names it",
    }


@pytest.mark.parametrize(
    "path,value",
    [
        ("body.status", None),
        ("body.status", "done"),
        ("body.status", "Reported"),
        ("body.status", ["reported"]),
        ("body.item_id", "s2"),
        ("body.item_id", ["S2"]),
    ],
    ids=["status-missing", "status-unknown", "status-other-case", "status-list", "item_id-other",
         "item_id-list"],
)  # fmt: skip
def test_complete__fail__3_each_item_has_a_counted_postreg_with_its_id_and_a_status(
    sc, path, value
):
    """complete #3: the postreg must carry the item's exact id and a status of reported,
    excluded or blocked."""
    sc.set("postreg1", path, value)
    report = sc.verify("complete")
    assert report["code"] == FAIL
    expected = (
        "no counted postreg names it"
        if path == "body.item_id"
        else "no counted postreg for it has a status of reported, excluded or blocked"
    )
    assert _get_items(report)["S2"] == expected


def test_complete__fail__3_a_postreg_that_does_not_count_accounts_for_nothing(sc, keypair):
    """complete #3: only counted postregs account for items: one signed by another key is
    rejected, so S2 is not accounted for."""
    sc.sign_with("postreg1", keypair)
    report = sc.verify("complete")
    assert report["code"] == FAIL
    assert _get_items(report)["S2"] == "no counted postreg names it"


def test_complete__pass__3_any_qualifying_postreg_accounts_for_an_item(sc):
    """complete #3: of several counted postregs for one item, any one that qualifies
    accounts for it: here S2 has one with an unknown status and one reported."""
    sc.set("prereg", "body.items", ITEMS[:2])
    sc.set("postreg1", "body.status", "done")
    sc.set("postreg2", "body.item_id", "S2")
    report = sc.verify("complete")
    assert report["code"] == PASS
    assert _get_items(report) == {"S1": "reported", "S2": "reported"}


def test_complete__pass__3_a_postreg_for_an_unlisted_item_is_shown_not_failed(sc):
    """complete #3: a postreg whose item_id the prereg does not list accounts for no item,
    and does not fail complete; it is listed. A postreg with no item_id is not read."""
    sc.add_postreg("extra", prev="postreg2")
    sc.set("extra", "body.item_id", "Z9")
    sc.add_postreg("summary", prev="extra")
    report = sc.verify("complete")
    assert report["code"] == PASS
    (unlisted,) = _get_complete(report)["unlisted"]
    assert unlisted["item_id"] == "Z9"
    assert unlisted["ref"] == d.ref(d.decode_payload(json.loads(sc.read("extra"))))


@pytest.mark.parametrize("due", ["next tuesday", 12345, ""], ids=["text", "number", "empty"])
def test_complete__fail__4_due_is_parseable(sc, due):
    """complete #4: a present due that is not a parseable ISO-8601 string fails, with that
    reason."""
    sc.set("prereg", "body.due", due)
    report = sc.verify("complete")
    assert report["code"] == FAIL
    assert _get_complete(report)["reason"] == "due is not a parseable ISO-8601 timestamp"


@pytest.mark.parametrize("case", ["late", "no-ceiling", "invalid-ceiling"])
def test_complete__fail__5_each_item_is_accounted_for_on_time(sc, case):
    """complete #5: with a due, an item's postreg must be shown on time, by the same
    comparison as timely: a late one (T after due), one with no ceiling and one whose
    ceiling fails the ceiling conditions do not account for it in time."""
    if case == "late":
        sc.set("prereg", "body.due", "2023-11-14T22:13:20Z")  # T is one radius later
    elif case == "no-ceiling":
        del sc.ceilings["postreg1"]
    else:
        sc.set("postreg1", "ceiling.witness_id", "nobody")
    report = sc.verify("complete")
    assert report["code"] == FAIL
    reason = {
        "late": "not shown on time: its postreg is late",
        "no-ceiling": "not shown on time: its postreg has no ceiling",
        "invalid-ceiling": "not shown on time: its postreg's ceiling does not verify",
    }[case]
    assert _get_items(report)["S2"] == reason
    assert report["commitments"][0]["state"] == "fulfilled"


def test_complete__pass__5_any_qualifying_postreg_on_time_accounts_for_an_item(sc):
    """complete #5: S2 has two qualifying postregs, one with no ceiling and one on time."""
    sc.set("prereg", "body.items", ITEMS[:2])
    sc.set("postreg2", "body.item_id", "S2")
    del sc.ceilings["postreg1"]
    assert sc.code("complete") == PASS


@pytest.mark.parametrize("absent", ["missing", "null"])
def test_complete__pass__4_items_under_a_prereg_without_due(sc, absent):
    """complete #4-#5: with no due, items are checked for a counted postreg and a status
    only, not for time (D5a): no ceiling is needed."""
    if absent == "missing":
        sc.unset("prereg", "body.due")
    else:
        sc.set("prereg", "body.due", None)
    for name in POSTREGS:
        del sc.ceilings[name]
    assert sc.code("complete") == PASS


def test_complete__fail__3_a_dropped_item_under_a_prereg_without_due(sc):
    """complete #3: with no due, a dropped item still fails."""
    sc.unset("prereg", "body.due")
    sc.drop("postreg2")
    report = sc.verify("complete")
    assert report["code"] == FAIL
    assert _get_items(report)["S3"] == "no counted postreg names it"


def test_complete__pass__all_a_prereg_without_items_is_not_examined(sc):
    """complete: a commitment whose prereg lists no items is not examined."""
    sc.add_prereg("plain")
    sc.add_postreg("plain-post", fulfills="plain")
    report = sc.verify("complete")
    assert report["code"] == PASS
    assert report["results"]["complete"]["applicable"] == 1


@pytest.mark.parametrize("items", ["missing", None, []], ids=["missing", "null", "empty"])
def test_complete__fail__empty_no_commitment_lists_items(sc, items):
    """complete (*): no commitment's prereg has at least one item, so nothing is examined."""
    if items == "missing":
        sc.unset("prereg", "body.items")
    else:
        sc.set("prereg", "body.items", items)
    report = sc.verify("complete")
    assert report["results"]["complete"] == {"result": "FAIL", "applicable": 0, "reason": EMPTY}


def test_complete__fail__empty_a_rejected_preregistration_is_not_examined(sc):
    """complete (*): a prereg that fails selfsig is no commitment, so its items are not
    read."""
    sc.set("prereg", "dsse.signatures[0].keyid", "sha-256:" + "00" * 32)
    report = sc.verify("complete")
    assert report["commitments"] == [] and len(report["rejected_preregs"]) == 1
    assert report["results"]["complete"] == {"result": "FAIL", "applicable": 0, "reason": EMPTY}
