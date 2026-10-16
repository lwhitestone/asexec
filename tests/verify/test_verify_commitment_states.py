"""Commitment states: docs/VERIFICATION.md `## Commitment states`. Naming: see conftest.py.

States are rendered in the human report, never part of the code. One test per row of
the table (``test_state__<state>__...``), then the ``due`` timezone rules.
"""

import datetime
import time

import pytest

NOW = datetime.datetime(2026, 1, 1, 12, 30, tzinfo=datetime.UTC).timestamp()


def _only_prereg(scenario, due="__keep__"):
    for name in ("postreg0", "postreg1", "postreg2"):
        scenario.drop(name)
    if due != "__keep__":
        scenario.mutate("prereg", lambda body: body.update(due=due))
        if due is None:
            scenario.mutate("prereg", lambda body: body.pop("due", None))


def _state(scenario, **kwargs):
    (commitment,) = scenario.verify(**kwargs)["commitments"]
    return commitment["state"]


def test_state__fulfilled__at_least_one_counted_postreg(scenario):
    """fulfilled: at least one counted postreg."""
    assert _state(scenario) == "fulfilled"


@pytest.mark.parametrize(
    "due", ["2099-01-01T00:00:00Z", None, "null"], ids=["future", "absent", "null"]
)
def test_state__open__no_counted_postreg_and_due_absent_or_future(scenario, due):
    """open: no counted postreg, and due is absent (missing or null) or in the future."""
    _only_prereg(scenario, None if due == "null" else due)
    if due == "null":
        scenario.set("prereg", "payload.due", None)
    assert _state(scenario, now=NOW) == "open"


@pytest.mark.parametrize(
    "due", ["2026-01-01T12:30:00Z", "2000-01-01T00:00:00Z"], ids=["at", "before"]
)
def test_state__elapsed_no_receipt__due_at_or_before_now(scenario, due):
    """elapsed-no-receipt: no counted postreg, and due is at or before now."""
    _only_prereg(scenario, due)
    assert _state(scenario, now=NOW) == "elapsed-no-receipt"


@pytest.mark.parametrize(
    "due",
    ["next tuesday", 12345, ["a"], "", 0, False],
    ids=["text", "number", "list", "empty-string", "zero", "false"],
)
def test_state__invalid_due__due_present_but_not_iso_8601_string(scenario, due):
    """invalid-due: no counted postreg, and due is present but not a parseable ISO-8601 string."""
    _only_prereg(scenario, due)
    assert _state(scenario, now=NOW) == "invalid-due"


def test_state__notarization_only__postreg_matching_no_provided_prereg(scenario):
    """notarization-only: a postreg whose fulfills matches no provided prereg."""
    scenario.drop("prereg")
    report = scenario.verify()
    assert report["commitments"] == []
    assert len(report["notarization_only"]) == 3


def test_state__is_not_part_of_the_code(scenario):
    """States are rendered only: an elapsed commitment does not change the code."""
    _only_prereg(scenario, "2000-01-01T00:00:00Z")
    assert scenario.code() == "asexec-verify/1 BDR=PASS"


def test_due__without_offset_is_read_as_utc_and_flagged(scenario, monkeypatch):
    """A due without an offset is read as UTC, in any local timezone, and flagged."""
    if not hasattr(time, "tzset"):
        pytest.skip("time.tzset is POSIX-only")
    _only_prereg(scenario, "2026-01-01T12:00:00")
    states = set()
    try:
        for tz in ("UTC", "Pacific/Kiritimati", "Pacific/Pago_Pago"):
            monkeypatch.setenv("TZ", tz)
            time.tzset()
            (commitment,) = scenario.verify(now=NOW)["commitments"]
            assert commitment["due_naive"] is True
            states.add(commitment["state"])
    finally:
        monkeypatch.undo()  # restore TZ, then re-sync libc so later tests are unaffected
        time.tzset()
    assert states == {"elapsed-no-receipt"}


def test_due__with_offset_is_not_flagged(scenario):
    """A due with an explicit offset or Z is not flagged."""
    _only_prereg(scenario)
    (commitment,) = scenario.verify(now=NOW)["commitments"]
    assert commitment["due_naive"] is False
