"""``ceiling`` (Roughtime witness): docs/VERIFICATION.md `### ceiling`. Naming: see conftest.py."""

import json

import manifest_data as d
import pytest

from asexec import keys, roughtime
from asexec.verifier import verify_paths

PASS = "asexec-verify/1 ceiling=PASS format=PASS selfsig=PASS"
FAIL = "asexec-verify/1 ceiling=FAIL format=PASS selfsig=PASS"
EMPTY = "requested but no manifest carries a ceiling witness"


@pytest.fixture
def sc(scenario):
    """The all-passing scenario with a ceiling witness on the prereg."""
    scenario.with_ceiling("prereg")
    return scenario


def test_ceiling__pass__all(sc):
    """ceiling #1-#5: roughtime type, the nonce of this signature, pinned witness, valid
    response."""
    report = sc.verify("ceiling")
    assert report["code"] == PASS
    assert report["manifests"][0]["ceiling"]["status"] == "verified"


@pytest.mark.parametrize("absent", ["missing", "null"])
def test_ceiling__pass__4_pubkey_may_be_absent(sc, absent):
    """ceiling #4: ceiling.pubkey is optional (missing or null); the pinned key is used."""
    if absent == "missing":
        sc.ceilings["prereg"] = lambda nonce_hex: _record(sc, nonce_hex, pubkey=None)
    else:
        sc.set("prereg", "ceiling.pubkey", None)
    assert sc.code("ceiling") == PASS


def _respelled(sc, field):
    """A valid record whose hex ``field`` is uppercased, with a space between bytes."""

    def build(nonce_hex):
        record = _record(sc, nonce_hex)
        upper = record[field].upper()
        record[field] = upper[:8] + " " + upper[8:]
        return record

    return build


def test_ceiling__pass__4_pubkey_hex_accepts_either_case_and_whitespace(sc):
    """ceiling #4: pubkey is hex as bytes.fromhex accepts it (Conventions, Hex)."""
    sc.ceilings["prereg"] = _respelled(sc, "pubkey")
    assert sc.code("ceiling") == PASS


def test_ceiling__pass__5_response_hex_accepts_either_case_and_whitespace(sc):
    """ceiling #5: response is hex as bytes.fromhex accepts it (Conventions, Hex)."""
    sc.ceilings["prereg"] = _respelled(sc, "response")
    assert sc.code("ceiling") == PASS


_PINNED = object()  # "leave ceiling.pubkey as the scenario's pinned key"


def _record(sc, nonce_hex, *, pubkey=_PINNED, sign_response=None, **changes):
    """A valid ceiling record for ``nonce_hex``, with the given fields changed."""
    record = sc.ceiling_for(
        nonce_hex, "synthetic", sc.server_pub, sign_response or sc.sign_response
    )
    if pubkey is None:
        del record["pubkey"]
    elif pubkey is not _PINNED:
        record["pubkey"] = pubkey
    record.update(changes)
    return record


def test_ceiling__fail__1_type_is_roughtime(sc):
    """ceiling #1: ceiling_type == "roughtime"."""
    sc.ceilings["prereg"] = lambda nonce_hex: _record(sc, nonce_hex, ceiling_type="ots")
    assert sc.code("ceiling") == FAIL


@pytest.mark.parametrize("value", [{}, [], "", False, 0], ids=["{}", "[]", "''", "false", "0"])
def test_ceiling__fail__1_present_falsy_ceiling_is_examined(sc, value):
    """ceiling #1: a present ceiling (anything but missing or null) needs ceiling_type. The
    junk sits beside the prereg's valid ceiling, so were it not examined, ceiling would pass."""
    sc.set("postreg0", "ceiling", value)
    assert sc.code("ceiling") == FAIL


def test_ceiling__fail__2_nonce_is_of_this_signature(sc):
    """ceiling #2: the nonce is this file's witness nonce. A genuine response for some other
    nonce fails."""
    other_nonce = "aa" * 32
    sc.ceilings["prereg"] = lambda nonce_hex: _record(sc, other_nonce)
    assert sc.code("ceiling") == FAIL


@pytest.mark.parametrize("nonce_of", ["ref", "another-signers-copy"])
def test_ceiling__fail__2_a_witness_of_the_body_alone_is_not_one_of_this_signature(
    sc, tmp_path, nonce_of
):
    """ceiling #2: a ceiling shows when this key had signed these bytes. One for the body's ref,
    or copied from the same body signed by another key, fails: else a later key would inherit
    another's time."""
    stored = json.loads(sc.read("prereg"))
    if nonce_of == "ref":
        sc.ceilings["prereg"] = lambda nonce_hex: _record(
            sc, d.derive_ref(d.decode_payload(stored)).split(":", 1)[1]
        )
        assert sc.code("ceiling") == FAIL
        return
    copy = d.sign_bytes(d.decode_payload(stored), keys.generate())
    copy["ceiling"] = stored["ceiling"]
    path = tmp_path / "copy.json"
    path.write_text(json.dumps(copy))
    report = verify_paths([str(path)], ["format", "selfsig", "ceiling"], None, servers=sc.servers)
    assert report["code"] == FAIL
    assert report["manifests"][0]["ceiling"]["status"] == "invalid"


def _respell_spaced(raw: bytes) -> bytes:
    """The same JSON value as ``raw`` (the writer's canonical bytes), spelled with spaces."""
    spaced = json.dumps(json.loads(raw), indent=1).encode()
    assert spaced != raw and json.loads(spaced) == json.loads(raw)
    return spaced


def test_ceiling__pass__2_nonce_binds_the_stored_bytes(sc):
    """ceiling #2: the nonce binds the body bytes as stored. A body stored with non-canonical
    spacing, validly signed, whose ceiling was fetched for that file, passes."""
    sc.edit_body_bytes("prereg", _respell_spaced)
    stored = d.decode_payload(json.loads(sc.read("prereg")))
    assert stored != d.make_body_bytes(json.loads(stored))  # not what the writer would store
    report = sc.verify("ceiling")
    assert report["code"] == PASS
    (prereg,) = [m for m in report["manifests"] if m["phase"] == "prereg"]
    assert prereg["ceiling"]["status"] == "verified"
    assert prereg["ref"] == d.derive_ref(stored)


def test_ceiling__fail__2_nonce_is_not_of_a_reserialized_body(sc):
    """ceiling #2: a witness for the canonical re-serialization of the same JSON value, signed,
    is not a witness for the bytes stored: nothing re-serializes the body, so it fails."""
    sc.edit_body_bytes("prereg", _respell_spaced)
    canonical_hex = d.derive_witness_nonce(d.sign(sc._body("prereg")))
    sc.ceilings["prereg"] = lambda nonce_hex: _record(sc, canonical_hex)
    report = sc.verify("ceiling")
    assert report["code"] == FAIL
    (prereg,) = [m for m in report["manifests"] if m["phase"] == "prereg"]
    assert prereg["ceiling"]["status"] == "invalid"


def test_ceiling__fail__3_witness_has_pinned_key(sc):
    """ceiling #3: witness_id has a pinned key; a key is never taken from the file."""
    sc.ceilings["prereg"] = lambda nonce_hex: _record(sc, nonce_hex, witness_id="not-pinned")
    report = sc.verify("ceiling")
    assert report["code"] == FAIL
    assert report["manifests"][0]["ceiling"]["status"] == "unpinned"


def test_ceiling__fail__4_present_pubkey_equals_pinned(sc):
    """ceiling #4: a present ceiling.pubkey must equal the pinned key."""
    other_pub = keys.generate()[1].hex()
    sc.ceilings["prereg"] = lambda nonce_hex: _record(sc, nonce_hex, pubkey=other_pub)
    assert sc.code("ceiling") == FAIL


@pytest.mark.parametrize("value", [{}, [], 0, 1, True, ["a"]], ids=repr)
def test_ceiling__fail__4_present_pubkey_equals_pinned__not_a_string(sc, value):
    """ceiling #4: a present non-string ceiling.pubkey cannot equal the pinned key."""
    sc.set("prereg", "ceiling.pubkey", value)
    assert sc.code("ceiling") == FAIL


def _tamper_srep(sc):
    """A response whose SREP changed after the delegated key signed it."""

    def sign_response(nonce):
        msg = roughtime.parse_message(sc.sign_response(nonce))
        srep = roughtime.parse_message(msg["SREP"])
        srep["RADI"] = b"\x09\x00\x00\x00"
        msg["SREP"] = roughtime.build_message(srep)
        return roughtime.build_message(msg)

    return sign_response


def _other_long_term_key(make_server):
    """A genuine response from a server whose long-term key is not the pinned one."""
    _other_pub, sign_response = make_server()
    return sign_response


def _unrooted_path(sc):
    return lambda nonce: sc.sign_response(nonce, root=b"\x00" * 64)


@pytest.mark.parametrize(
    "case", ["cert-not-by-pinned-key", "srep-signature", "merkle-path", "outside-validity-window"]
)
def test_ceiling__fail__5_response_verifies(sc, make_server, case):
    """ceiling #5: CERT.SIG, SIG, the Merkle path and the MINT/MIDP/MAXT window all hold."""
    if case == "cert-not-by-pinned-key":
        sign_response = _other_long_term_key(make_server)
    elif case == "srep-signature":
        sign_response = _tamper_srep(sc)
    elif case == "merkle-path":
        sign_response = _unrooted_path(sc)
    else:  # delegation only valid after the attested midpoint, under the pinned key
        pub, sign_response = make_server(mint=1_900_000_000_000_000)
        sc.pin_server(pub)
        sc.server_pub = pub
    sc.ceilings["prereg"] = lambda nonce_hex: _record(
        sc, nonce_hex, pubkey=None, sign_response=sign_response
    )
    assert sc.code("ceiling") == FAIL


@pytest.mark.parametrize("absent", ["missing", "null"])
def test_ceiling__fail__empty_no_manifest_carries_one(scenario, absent):
    """ceiling (*): no manifest carries a ceiling (missing or null), so the test fails."""
    if absent == "null":
        scenario.set("prereg", "ceiling", None)
    report = scenario.verify("ceiling")
    assert report["code"] == FAIL
    assert report["results"]["ceiling"]["applicable"] == 0
    assert report["results"]["ceiling"]["reason"] == EMPTY


def test_ceiling__fail__empty_malformed_manifest_not_examined(scenario):
    """ceiling (*): a malformed manifest is not examined, even if it carries a ceiling."""
    scenario.add_raw(
        "bad", json.dumps({**d.make_malformed({}), "ceiling": {"ceiling_type": "roughtime"}})
    )
    report = scenario.verify("ceiling")
    assert report["results"]["ceiling"]["applicable"] == 0
    assert report["code"] == "asexec-verify/1 ceiling=FAIL format=FAIL selfsig=PASS"
    assert report["results"]["ceiling"]["reason"] == EMPTY
