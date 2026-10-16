"""``ceiling`` (Roughtime witness): docs/VERIFICATION.md `### ceiling`. Naming: see conftest.py."""

import pytest

from asexec import keys, roughtime

PASS = "asexec-verify/1 BDR=PASS ceiling=PASS"
FAIL = "asexec-verify/1 BDR=PASS ceiling=FAIL"


@pytest.fixture
def sc(scenario):
    """The all-passing scenario with a ceiling witness on the prereg."""
    scenario.with_ceiling("prereg")
    return scenario


def test_ceiling__pass__all(sc):
    """ceiling #1-#5: roughtime type, nonce == ref(payload), pinned witness, valid response."""
    report = sc.verify("ceiling")
    assert report["code"] == PASS
    assert report["manifests"][0]["ceiling"]["status"] == "verified"


def test_ceiling__pass__4_pubkey_may_be_absent(sc):
    """ceiling #4: ceiling.pubkey is optional; the pinned key is used, never the file's."""
    sc.ceilings["prereg"] = lambda nonce_hex: _record(sc, nonce_hex, pubkey=None)
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


def test_ceiling__fail__2_nonce_equals_ref_of_payload(sc):
    """ceiling #2: nonce == ref(payload). A genuine response for some other nonce fails."""
    other_nonce = "aa" * 32
    sc.ceilings["prereg"] = lambda nonce_hex: _record(sc, other_nonce)
    assert sc.code("ceiling") == FAIL


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


def test_ceiling__fail__vacuous_no_manifest_carries_one(scenario):
    """ceiling (*): no manifest carries a ceiling, so the test fails rather than passing."""
    report = scenario.verify("ceiling")
    assert report["code"] == FAIL
    assert report["results"]["ceiling"]["applicable"] == 0


def test_ceiling__fail__vacuous_malformed_manifest_not_examined(scenario):
    """ceiling (*): a malformed manifest is not examined, even if it carries a ceiling."""
    scenario.add_raw(
        "bad", '{"payload": {}, "signature": {}, "ceiling": {"ceiling_type": "roughtime"}}'
    )
    report = scenario.verify("ceiling")
    assert report["results"]["ceiling"]["applicable"] == 0
    assert report["code"] == "asexec-verify/1 BDR=FAIL ceiling=FAIL"
