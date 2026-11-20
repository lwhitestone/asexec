"""``timely`` (postreg ceilings against the prereg's due): docs/VERIFICATION.md `### timely`.
Naming: see conftest.py.

The synthetic witness signs MIDP 1_700_000_000 s (2023-11-14T22:13:20Z) with RADI 1 s, so a
ceiling's time T, the later end of that interval, is 2023-11-14T22:13:21Z. The scenario's
prereg has ``due`` 2099-01-01T00:00:00Z, so a postreg with a ceiling is on time.
"""

import datetime
import json

import pytest

PASS = "asexec-verify/1 format=PASS selfsig=PASS timely=PASS"
FAIL = "asexec-verify/1 format=PASS selfsig=PASS timely=FAIL"
EMPTY = "requested but no commitment with a due has a counted postreg"
POSTREGS = ("postreg0", "postreg1", "postreg2")
T = datetime.datetime(2023, 11, 14, 22, 13, 21, tzinfo=datetime.UTC).timestamp()


@pytest.fixture
def sc(scenario):
    """The all-passing scenario with a ceiling on every postreg."""
    for name in POSTREGS:
        scenario.with_ceiling(name)
    return scenario


def _due(sc, due):
    sc.set("prereg", "body.due", due)


def _commitment(report):
    (commitment,) = report["commitments"]
    return commitment


def _statuses(report):
    return [p["status"] for p in _commitment(report)["timeliness"]]


def test_timely__pass__all(sc):
    """timely #1-#4: due parses, and every counted postreg has a ceiling that meets the
    ceiling conditions and whose time is at or before due."""
    report = sc.verify("timely")
    assert report["code"] == PASS
    assert report["results"]["timely"]["reason"] == "1/1 commitment(s) ok"
    assert _statuses(report) == ["on-time"] * 3
    assert {p["no_later_than"] for p in _commitment(report)["timeliness"]} == {T}


def test_timely__pass__1_due_without_offset_is_read_as_utc(sc):
    """timely #1: a due with no offset is read as UTC, as for commitment states."""
    _due(sc, "2023-11-14T22:13:21")
    assert sc.code("timely") == PASS


@pytest.mark.parametrize(
    "due", ["next tuesday", 12345, ["a"], "", 0], ids=["text", "number", "list", "empty", "zero"]
)
def test_timely__fail__1_due_is_parseable(sc, due):
    """timely #1: a present due that is not a parseable ISO-8601 string fails, with that
    reason. The commitment is still fulfilled."""
    _due(sc, due)
    report = sc.verify("timely")
    assert report["code"] == FAIL
    commitment = _commitment(report)
    assert commitment["timely"] == {
        "examined": True,
        "ok": False,
        "reason": "due is not a parseable ISO-8601 timestamp",
    }
    assert commitment["state"] == "fulfilled"


def test_timely__fail__2_counted_postreg_has_a_ceiling(sc):
    """timely #2: a counted postreg with no ceiling fails: its ceiling is chosen at report
    time, so leaving it out must not get around the test."""
    del sc.ceilings["postreg1"]
    report = sc.verify("timely")
    assert report["code"] == FAIL
    assert _statuses(report) == ["on-time", "no-ceiling", "on-time"]


def _ceiling_of(sc, name):
    sc.write()
    return json.loads((sc.manifest_dir / f"{name}.json").read_text())["ceiling"]


@pytest.mark.parametrize(
    "case",
    [
        "unpinned-witness",
        "nonce-of-another-manifest",
        "response-tampered",
        "not-roughtime",
        "pubkey-not-pinned",
        "junk",
    ],
)
def test_timely__fail__3_ceiling_meets_the_ceiling_conditions(sc, case):
    """timely #3: a ceiling that fails a ceiling condition (an unpinned witness, a nonce for
    another body, a response that does not verify, ...) is not a time: anyone can write a
    ceiling, so it counts as no ceiling, never as on time."""
    if case == "unpinned-witness":
        sc.set("postreg1", "ceiling.witness_id", "nobody")
    elif case == "nonce-of-another-manifest":
        other = _ceiling_of(sc, "postreg0")
        sc.tamper("postreg1", lambda env: env.update(ceiling=other))
    elif case == "response-tampered":
        other = sc.sign_response(bytes(32)).hex()  # a genuine response, for another nonce
        sc.set("postreg1", "ceiling.response", other)
    elif case == "not-roughtime":
        sc.set("postreg1", "ceiling.ceiling_type", "opentimestamps")
    elif case == "pubkey-not-pinned":
        sc.set("postreg1", "ceiling.pubkey", "00" * 32)
    else:
        sc.set("postreg1", "ceiling", "a ceiling")
    report = sc.verify("timely")
    assert report["code"] == FAIL
    assert _statuses(report) == ["on-time", "invalid-ceiling", "on-time"]


@pytest.mark.parametrize("due", ["2023-01-01T00:00:00Z", "2023-11-14T22:13:20Z"])
def test_timely__fail__4_ceiling_at_or_before_due(sc, due):
    """timely #4: a ceiling after due fails. T is MIDP + RADI, the later end of the
    interval the witness signed, so a due at the midpoint (one radius before T) is missed.
    A late postreg still counts: the commitment stays fulfilled, and it is marked late."""
    _due(sc, due)
    report = sc.verify("timely")
    assert report["code"] == FAIL
    commitment = _commitment(report)
    assert commitment["state"] == "fulfilled"
    assert len(commitment["counted_postregs"]) == 3
    assert _statuses(report) == ["late"] * 3
    assert commitment["timely"]["reason"] == "a counted postreg is not shown on time"


def test_timely__pass__4_ceiling_exactly_at_due(sc):
    """timely #4: at due passes (T == due)."""
    _due(sc, "2023-11-14T22:13:21Z")
    assert sc.code("timely") == PASS


def test_timely__fail__4_the_unsigned_midpoint_and_radius_are_not_read(sc):
    """timely #4: T comes from the verified response, never from the file's own
    ceiling.midpoint and ceiling.radius, which nothing signs."""
    _due(sc, "2023-11-14T22:13:20Z")
    for name in POSTREGS:
        sc.set(name, "ceiling.midpoint", 0.0)
        sc.set(name, "ceiling.radius", 0.0)
    assert sc.code("timely") == FAIL


def test_timely__pass__2_any_counted_copy_with_a_verified_ceiling_shows_it(sc):
    """timely #2-#4: copies of one postreg (one ref) are one postreg: if any counted copy
    carries a ceiling that meets the conditions and is on time, the postreg is on time."""
    sc.write()
    with_ceiling = json.loads((sc.manifest_dir / "postreg2.json").read_text())
    del sc.ceilings["postreg2"]  # postreg2 itself now has none; its copy does
    sc.add_raw("postreg2-copy", json.dumps(with_ceiling))
    report = sc.verify("timely")
    assert report["code"] == PASS
    assert _statuses(report) == ["on-time"] * 3


def test_timely__pass__all_a_prereg_without_due_is_not_examined(sc):
    """timely: a commitment whose prereg has no due is not examined, so one open-ended claim
    does not fail timely for a whole run (D5a). Here the second commitment's postreg has no
    ceiling at all."""
    sc.add_prereg("open-ended")
    sc.unset("open-ended", "body.due")
    sc.add_postreg("open-post", fulfills="open-ended")
    report = sc.verify("timely")
    assert report["code"] == PASS
    assert report["results"]["timely"]["applicable"] == 1
    states = sorted(c["timely"]["examined"] for c in report["commitments"])
    assert states == [False, True]


@pytest.mark.parametrize("absent", ["missing", "null"])
def test_timely__fail__empty_no_prereg_has_a_due(sc, absent):
    """timely (*): no commitment has a due, so nothing is examined."""
    if absent == "missing":
        sc.unset("prereg", "body.due")
    else:
        _due(sc, None)
    report = sc.verify("timely")
    assert report["code"] == FAIL
    assert report["results"]["timely"] == {"result": "FAIL", "applicable": 0, "reason": EMPTY}


def test_timely__fail__empty_due_but_no_counted_postreg(sc):
    """timely (*): a commitment with a due and no counted postreg is not examined (its state
    says whether it was reported)."""
    for name in POSTREGS:
        sc.drop(name)
    report = sc.verify("timely")
    assert report["results"]["timely"] == {"result": "FAIL", "applicable": 0, "reason": EMPTY}


def test_timely__fail__empty_a_rejected_preregistration_is_not_examined(sc):
    """timely (*): a prereg that fails selfsig is no commitment, so its due is not read."""
    sc.set("prereg", "dsse.signatures[0].keyid", "sha-256:" + "00" * 32)
    report = sc.verify("timely")
    assert report["commitments"] == [] and len(report["rejected_preregs"]) == 1
    assert report["results"]["timely"] == {"result": "FAIL", "applicable": 0, "reason": EMPTY}
