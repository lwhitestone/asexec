"""``floor`` (drand beacon): docs/VERIFICATION.md `### floor`. Naming: see conftest.py.

Each ``verify_paths`` run does the BLS check once per floor-carrying manifest (about a
second), so the scenario carries a floor on the prereg only.
"""

import pytest

from asexec import drand

PASS = "asexec-verify/1 BDR=PASS floor=PASS"
FAIL = "asexec-verify/1 BDR=PASS floor=FAIL"


@pytest.fixture
def sc(scenario):
    """The all-passing scenario with a real drand floor on the prereg."""
    scenario.with_floor("prereg")
    return scenario


def _edit_floor(sc, **changes):
    """Change ``payload.anchor.floor`` fields (signed); a value of None deletes one."""
    for key, value in changes.items():
        path = f"payload.anchor.floor.{key}"
        if value is None:
            sc.unset("prereg", path)
        else:
            sc.set("prereg", path, value)


def test_floor__pass__all(sc):
    """floor #1-#5: drand object, pinned chain, int round and hex signature, randomness, BLS."""
    report = sc.verify("floor")
    assert report["code"] == PASS
    floor = report["manifests"][0]["floor"]
    assert floor["status"] == "verified"
    assert floor["created_no_earlier_than"] == drand.time_of_round(1000)


@pytest.mark.parametrize("absent", ["missing", "null"])
def test_floor__pass__2_chain_hash_defaults_to_quicknet(sc, absent):
    """floor #2: an absent (missing or null) chain_hash means the pinned quicknet chain."""
    if absent == "missing":
        sc.unset("prereg", "payload.anchor.floor.chain_hash")
    else:
        sc.set("prereg", "payload.anchor.floor.chain_hash", None)
    assert sc.code("floor") == PASS


@pytest.mark.parametrize("absent", ["missing", "null"])
def test_floor__pass__4_randomness_may_be_absent(sc, absent):
    """floor #4: randomness is optional (missing or null); the BLS check (#5) still holds."""
    if absent == "missing":
        sc.unset("prereg", "payload.anchor.floor.randomness")
    else:
        sc.set("prereg", "payload.anchor.floor.randomness", None)
    assert sc.code("floor") == PASS


def test_floor__pass__3_signature_hex_accepts_either_case_and_whitespace(sc):
    """floor #3: signature is hex as bytes.fromhex accepts it (Conventions, Hex)."""

    def respell(body):
        sig = body["anchor"]["floor"]["signature"].upper()
        body["anchor"]["floor"]["signature"] = sig[:8] + " " + sig[8:]

    sc.mutate("prereg", respell)
    assert sc.code("floor") == PASS


@pytest.mark.parametrize(
    "path,value",
    [
        pytest.param("payload.anchor.floor", "x", id="floor-string"),
        pytest.param("payload.anchor.floor", {}, id="floor-empty-object"),
        pytest.param("payload.anchor.floor", [], id="floor-empty-list"),
        pytest.param("payload.anchor.floor", "", id="floor-empty-string"),
        pytest.param("payload.anchor.floor", False, id="floor-false"),
        pytest.param("payload.anchor.floor", 0, id="floor-zero"),
        pytest.param("payload.anchor", [], id="anchor-empty-list"),
        pytest.param("payload.anchor", "x", id="anchor-string"),
    ],
)
def test_floor__fail__1_floor_is_an_object(sc, path, value):
    """floor #1: a present anchor.floor (anything but missing or null) is an object. The
    junk sits beside the prereg's valid floor, so were it not examined, floor would pass."""
    sc.set("postreg0", path, value)
    assert sc.code("floor") == FAIL


@pytest.mark.parametrize("case", ["type-other", "type-missing"])
def test_floor__fail__1_drand_floor_object(sc, case):
    """floor #1: anchor.floor is an object and floor_type == "drand"."""
    if case == "type-other":
        _edit_floor(sc, floor_type="other")
    else:
        _edit_floor(sc, floor_type=None)
    assert sc.code("floor") == FAIL


def test_floor__fail__2_chain_hash_is_pinned(sc):
    """floor #2: chain_hash names a chain the verifier pins."""
    _edit_floor(sc, chain_hash="00" * 32)
    assert sc.code("floor") == FAIL


@pytest.mark.parametrize(
    "field,value",
    [
        pytest.param("round", "nope", id="round-not-numeric"),
        pytest.param("round", None, id="round-missing"),
        pytest.param("round", "1000", id="round-numeric-string"),
        pytest.param("round", 1000.7, id="round-float"),
        pytest.param("signature", "zz", id="signature-not-hex"),
    ],
)
def test_floor__fail__3_round_is_int_and_signature_is_hex(sc, field, value):
    """floor #3: round is an integer and signature is hex."""
    _edit_floor(sc, **{field: value})
    assert sc.code("floor") == FAIL


def test_floor__fail__4_randomness_is_sha256_of_signature(sc):
    """floor #4: a present randomness equals sha256(signature)."""
    _edit_floor(sc, randomness="00" * 32)
    assert sc.code("floor") == FAIL


def test_floor__fail__5_signature_verifies_for_round(sc):
    """floor #5: the BLS signature verifies for this round (another round's fails)."""
    _edit_floor(sc, round=1001)
    assert sc.code("floor") == FAIL


@pytest.mark.parametrize("absent", ["missing", "null-floor", "null-anchor"])
def test_floor__fail__vacuous_no_manifest_carries_one(scenario, absent):
    """floor (*): no manifest carries an anchor.floor (missing or null), so the test fails."""
    if absent != "missing":
        path = {"null-floor": "payload.anchor.floor", "null-anchor": "payload.anchor"}[absent]
        scenario.set("prereg", path, None)
    report = scenario.verify("floor")
    assert report["code"] == FAIL
    assert report["results"]["floor"]["applicable"] == 0
