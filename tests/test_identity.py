"""Identity hook: .well-known build + binding check (network mocked)."""
from asexec import identity, keys


def test_build_wellknown_shape():
    priv, pub = keys.generate()
    kid = keys.keyid_for(pub)
    doc = identity.build_wellknown([{"keyid": kid, "pubkey": pub.hex()}], domain="lab.example")
    assert doc["asexec_identity_version"] == 1
    assert doc["domain"] == "lab.example"
    assert doc["keys"][0]["keyid"] == kid
    assert doc["keys"][0]["alg"] == "ed25519"


def test_verify_binding_positive_and_negative(monkeypatch):
    priv, pub = keys.generate()
    kid = keys.keyid_for(pub)
    doc = identity.build_wellknown([{"keyid": kid, "pubkey": pub.hex()}])
    monkeypatch.setattr(identity, "fetch_wellknown", lambda domain, timeout=10: doc)

    ok = identity.verify_binding("lab.example", keyid=kid)
    assert ok["bound"] is True and ok["matched"]["keyid"] == kid

    other = keys.keyid_for(keys.generate()[1])
    bad = identity.verify_binding("lab.example", keyid=other)
    assert bad["bound"] is False
    assert "point-in-time" in bad["caveat"]
