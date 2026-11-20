"""``order`` (the prereg's ceiling before each counted postreg's floor): docs/VERIFICATION.md
`### order`. Naming: see conftest.py.

The floor is the baked quicknet round 1000, whose time is the pinned chain's genesis
1692803367 plus 999 periods of 3 s: 1692806364 s, 2023-08-23T15:59:24Z. The prereg's ceiling
comes from a synthetic witness re-pinned to sign MIDP ten seconds before that, RADI 1 s, so
its time T (MIDP + RADI) is nine seconds before the floor. The scenario's default witness
signs 2023-11-14, after the floor: a run whose floor precedes the prereg's ceiling.

Each floor costs about a second of BLS math per run, so the scenario keeps one counted
postreg (postreg0) unless a test needs the chain.
"""

import json

import manifest_data as d
import pytest

from asexec import keys

PASS = "asexec-verify/1 format=PASS order=PASS selfsig=PASS"
FAIL = "asexec-verify/1 format=PASS order=FAIL selfsig=PASS"
EMPTY = "requested but no commitment has a counted postreg"
FLOOR_US = 1_692_806_364_000_000  # quicknet round 1000, in microseconds since the epoch
MIDP_US, RADI_US = FLOOR_US - 10_000_000, 1_000_000
CEILING_US = MIDP_US + RADI_US  # the prereg's ceiling time T: nine seconds before the floor


def _witness_at(sc, make_server, midpoint_us, radius_us=RADI_US):
    """Re-pin the scenario's witness to one that signs ``midpoint_us`` and ``radius_us``."""
    sc.server_pub, sc.sign_response = make_server(midpoint_us=midpoint_us, radius_us=radius_us)
    sc.pin_server(sc.server_pub)


@pytest.fixture
def sc(scenario, make_server):
    """A prereg with a ceiling nine seconds before round 1000, and one counted postreg whose
    floor is round 1000."""
    _witness_at(scenario, make_server, MIDP_US)
    scenario.with_ceiling("prereg")
    scenario.with_floor("postreg0")
    scenario.drop("postreg1")
    scenario.drop("postreg2")
    return scenario


def _order(report):
    (commitment,) = report["commitments"]
    return commitment["order"]


def _statuses(report):
    return [p["status"] for p in _order(report)["postregs"]]


def test_order__pass__all(sc):
    """order #1-#5: the prereg has a ceiling that meets the ceiling conditions, the counted
    postreg has a floor that meets the floor conditions, and the ceiling's time is before the
    floor's."""
    report = sc.verify("order")
    assert report["code"] == PASS
    assert report["results"]["order"]["reason"] == "1/1 commitment(s) ok"
    (post,) = [m for m in report["manifests"] if m["path"].endswith("/postreg0.json")]
    assert _order(report) == {
        "examined": True,
        "ok": True,
        "reason": None,
        "ceiling": {"status": "verified", "no_later_than_us": CEILING_US},
        "postregs": [{"ref": post["ref"], "status": "after", "no_earlier_than_us": FLOOR_US}],
    }


def test_order__pass__all_each_counted_postreg_of_a_chain(scenario, make_server):
    """order: every counted postreg is examined, each against the prereg's ceiling."""
    _witness_at(scenario, make_server, MIDP_US)
    scenario.with_ceiling("prereg")
    for name in ("postreg0", "postreg1", "postreg2"):
        scenario.with_floor(name)
    report = scenario.verify("chain", "order")
    assert report["code"] == "asexec-verify/1 chain=PASS format=PASS order=PASS selfsig=PASS"
    assert _statuses(report) == ["after"] * 3


def test_order__fail__1_prereg_has_a_ceiling(sc):
    """order #1: a prereg with no ceiling fails, with that reason. A ceiling on a postreg does
    not stand in for it: it is the prereg's time that the floor is compared with."""
    del sc.ceilings["prereg"]
    sc.with_ceiling("postreg0")
    report = sc.verify("order")
    assert report["code"] == FAIL
    order = _order(report)
    assert order["reason"] == "the pre-registration has no ceiling"
    assert order["ceiling"] == {"status": "absent", "no_later_than_us": None}
    assert _statuses(report) == ["not-compared"]


def _ceiling_of(sc, name):
    sc.write()
    return json.loads((sc.manifest_dir / f"{name}.json").read_text())["ceiling"]


@pytest.mark.parametrize(
    "case",
    [
        "unpinned-witness",
        "nonce-of-another-manifest",
        "response-for-another-nonce",
        "not-roughtime",
        "pubkey-not-pinned",
        "junk",
    ],
)
def test_order__fail__2_prereg_ceiling_meets_the_ceiling_conditions(sc, case):
    """order #2: a prereg ceiling that fails a ceiling condition is no time at all (anyone can
    write one): the commitment fails, as if it had none."""
    if case == "unpinned-witness":
        sc.set("prereg", "ceiling.witness_id", "nobody")
    elif case == "nonce-of-another-manifest":
        sc.with_ceiling("postreg0")
        other = _ceiling_of(sc, "postreg0")  # genuine, and as early, but for the postreg
        sc.tamper("prereg", lambda env: env.update(ceiling=other))
    elif case == "response-for-another-nonce":
        sc.set("prereg", "ceiling.response", sc.sign_response(bytes(32)).hex())
    elif case == "not-roughtime":
        sc.set("prereg", "ceiling.ceiling_type", "opentimestamps")
    elif case == "pubkey-not-pinned":
        sc.set("prereg", "ceiling.pubkey", "00" * 32)
    else:
        sc.set("prereg", "ceiling", "a ceiling")
    report = sc.verify("order")
    assert report["code"] == FAIL
    order = _order(report)
    assert order["reason"] == "the pre-registration's ceiling does not verify"
    assert order["ceiling"] == {"status": "invalid", "no_later_than_us": None}


def test_order__pass__2_any_copy_of_the_prereg_with_a_verified_ceiling_shows_it(
    sc, make_server, ceiling_for
):
    """order #1-#2: copies of the prereg (one ref, one signer) are one commitment: a copy
    without a ceiling, or with a later one, does not undo a copy whose ceiling verifies, and
    the earliest such time is the prereg's."""
    sc.write()
    early = json.loads((sc.manifest_dir / "prereg.json").read_text())
    late_pub, late_sign = make_server(midpoint_us=FLOOR_US + 60_000_000)  # after the floor
    sc.servers["later"] = {"pubkey": late_pub}  # a second pinned witness, for the original
    sc.ceilings["prereg"] = lambda nonce: ceiling_for(nonce, "later", late_pub, late_sign)
    sc.add_raw("prereg-early-copy", json.dumps(early))
    sc.add_raw("prereg-bare-copy", json.dumps({k: v for k, v in early.items() if k != "ceiling"}))
    report = sc.verify("ceiling", "order")
    assert report["code"] == "asexec-verify/1 ceiling=PASS format=PASS order=PASS selfsig=PASS"
    assert _order(report)["ceiling"] == {"status": "verified", "no_later_than_us": CEILING_US}
    assert len(report["commitments"]) == 1


def test_order__fail__3_counted_postreg_has_a_floor(sc):
    """order #3: a counted postreg with no floor fails: nothing shows when it was made."""
    sc.specs["postreg0"].floor = False
    report = sc.verify("order")
    assert report["code"] == FAIL
    assert _order(report)["reason"] == "a counted postreg is not shown after the pre-registration"
    assert _order(report)["postregs"][0] == {
        "ref": _order(report)["postregs"][0]["ref"],
        "status": "no-floor",
        "no_earlier_than_us": None,
    }


@pytest.mark.parametrize(
    "path,value",
    [
        pytest.param("round", 5_000_000, id="forged-later-round"),
        pytest.param("round", 999, id="forged-earlier-round"),
        pytest.param("randomness", "00" * 32, id="randomness-not-sha256-of-signature"),
        pytest.param("chain_hash", "00" * 32, id="chain-not-pinned"),
        pytest.param("floor_type", "nist", id="not-drand"),
        pytest.param("signature", "zz", id="signature-not-hex"),
        pytest.param("round", "1000", id="round-a-string"),
    ],
)
def test_order__fail__4_floor_meets_the_floor_conditions(sc, path, value):
    """order #4: a floor that fails a floor condition (the pinned chain, its BLS signature
    for its round, randomness) is no time at all: a postreg claiming a later round with
    round 1000's signature is not shown after anything."""
    sc.set("postreg0", f"body.anchor.floor.{path}", value)
    report = sc.verify("order")
    assert report["code"] == FAIL
    assert _statuses(report) == ["invalid-floor"]
    assert _order(report)["postregs"][0]["no_earlier_than_us"] is None


def test_order__fail__5_a_floor_before_the_prereg_ceiling(sc, make_server):
    """order #5: the run's floor precedes the prereg's ceiling (the witness signed the prereg
    in November, after the August round the postreg carries): the postreg is not shown after
    the prereg. Its commitment is still fulfilled."""
    _witness_at(sc, make_server, 1_700_000_000_000_000)  # the default witness: 2023-11-14
    report = sc.verify("order")
    assert report["code"] == FAIL
    order = _order(report)
    assert order["reason"] == "a counted postreg is not shown after the pre-registration"
    assert order["ceiling"]["no_later_than_us"] == 1_700_000_001_000_000
    assert order["postregs"][0]["status"] == "not-after"
    assert order["postregs"][0]["no_earlier_than_us"] == FLOOR_US
    assert report["commitments"][0]["state"] == "fulfilled"


def test_order__fail__5_precedes_is_strict(sc, make_server):
    """order #5: a ceiling time equal to the floor's, to the microsecond, does not precede it."""
    _witness_at(sc, make_server, FLOOR_US - RADI_US)
    report = sc.verify("order")
    assert report["code"] == FAIL
    assert _order(report)["ceiling"]["no_later_than_us"] == FLOOR_US
    assert _statuses(report) == ["not-after"]


def test_order__pass__5_one_microsecond_before_the_floor(sc, make_server):
    """order #5: compared exactly, in whole microseconds: one microsecond before passes."""
    _witness_at(sc, make_server, FLOOR_US - RADI_US - 1)
    assert sc.code("order") == PASS


def test_order__fail__5_the_unsigned_midpoint_and_radius_are_not_read(sc, make_server):
    """order #5: the ceiling's time comes from the verified response, never from the file's
    own ceiling.midpoint and ceiling.radius, which nothing signs."""
    _witness_at(sc, make_server, 1_700_000_000_000_000)
    sc.set("prereg", "ceiling.midpoint", 0.0)
    sc.set("prereg", "ceiling.radius", 0.0)
    assert sc.code("order") == FAIL


def test_order__pass__all_a_postreg_that_does_not_count_is_not_examined(sc):
    """order: only counted postregs are examined. One signed by another key, with no floor,
    is rejected under the commitment and does not fail order."""
    sc.add_postreg("intruder", prev="postreg0")
    sc.sign_with("intruder", keys.generate())
    report = sc.verify("order")
    assert report["code"] == PASS
    (commitment,) = report["commitments"]
    assert len(commitment["rejected_postregs"]) == 1 and len(_order(report)["postregs"]) == 1


def test_order__pass__all_a_commitment_without_counted_postregs_is_not_examined(sc):
    """order: a commitment with no counted postreg is not examined (its state says it was
    not reported), so it fails nothing, even with no ceiling."""
    sc.add_prereg("unreported")
    report = sc.verify("order")
    assert report["code"] == PASS
    assert report["results"]["order"]["applicable"] == 1
    assert sorted(c["order"]["examined"] for c in report["commitments"]) == [False, True]


def test_order__fail__empty_no_commitment_has_a_counted_postreg(sc):
    """order (*): no commitment has a counted postreg, so nothing is examined."""
    sc.drop("postreg0")
    report = sc.verify("order")
    assert report["code"] == FAIL
    assert report["results"]["order"] == {"result": "FAIL", "applicable": 0, "reason": EMPTY}


def test_order__fail__empty_a_rejected_preregistration_is_not_examined(sc):
    """order (*): a prereg that fails selfsig is no commitment, so neither its ceiling nor
    the floors of the postregs naming it are read."""
    sc.set("prereg", "dsse.signatures[0].keyid", "sha-256:" + "00" * 32)
    report = sc.verify("order")
    assert report["commitments"] == [] and len(report["rejected_preregs"]) == 1
    assert report["results"]["order"] == {"result": "FAIL", "applicable": 0, "reason": EMPTY}


def test_order__fail__empty_a_malformed_postreg_is_not_examined(sc):
    """order (*): a postreg that fails format is not counted, whatever floor it carries."""
    sc.drop("postreg0")
    sc.add_raw("bad", json.dumps(d.malformed(d.with_field(d.POSTREG, "anchor.floor", d.FLOOR))))
    report = sc.verify("order")
    assert report["results"]["order"]["applicable"] == 0
