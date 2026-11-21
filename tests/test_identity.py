"""Identity hook: .well-known build + binding check (network mocked)."""

import io
import json

import pytest

from asexec import identity, keys
from asexec.errors import AsexecError, NetworkError


def test_build_wellknown_shape():
    priv, pub = keys.generate()
    kid = keys.keyid_for(pub)
    doc = identity.build_wellknown([{"keyid": kid, "pubkey": pub.hex()}], domain="lab.example")
    assert doc["asexec_identity_version"] == 1
    assert doc["domain"] == "lab.example"
    assert doc["keys"][0]["keyid"] == kid
    assert doc["keys"][0]["alg"] == "ed25519"


def test_match_binding_positive_and_negative(monkeypatch):
    priv, pub = keys.generate()
    kid = keys.keyid_for(pub)
    doc = identity.build_wellknown([{"keyid": kid, "pubkey": pub.hex()}])
    monkeypatch.setattr(identity, "fetch_wellknown", lambda domain, timeout=10: doc)

    ok = identity.match_binding("lab.example", keyid=kid)
    assert ok["bound"] is True and ok["matched"]["keyid"] == kid

    other = keys.keyid_for(keys.generate()[1])
    bad = identity.match_binding("lab.example", keyid=other)
    assert bad["bound"] is False
    assert "point-in-time" in bad["caveat"]


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()


def test_fetch_wellknown_builds_https_url_and_parses(monkeypatch):
    seen = []

    def fake(url, timeout):
        seen.append((url, timeout))
        return _Resp(json.dumps({"keys": []}).encode())

    monkeypatch.setattr(identity.urllib.request, "urlopen", fake)
    assert identity.fetch_wellknown("lab.example/", timeout=3) == {"keys": []}
    assert seen == [("https://lab.example/.well-known/asexec.json", 3)]


def test_fetch_wellknown_errors_map_to_network_error(monkeypatch):
    def fake(url, timeout):
        raise OSError("tls handshake failed")

    monkeypatch.setattr(identity.urllib.request, "urlopen", fake)
    with pytest.raises(NetworkError, match="lab.example"):
        identity.fetch_wellknown("lab.example")


def test_fetch_wellknown_refuses_a_document_that_is_not_json(monkeypatch):
    """What was fetched is not JSON: the fetch worked, the document is not one."""
    monkeypatch.setattr(identity.urllib.request, "urlopen", lambda url, timeout: _Resp(b"no"))
    with pytest.raises(AsexecError, match="is not an asexec identity document") as e:
        identity.fetch_wellknown("lab.example")
    assert not isinstance(e.value, NetworkError)


def test_match_binding_by_pubkey(monkeypatch):
    _, pub = keys.generate()
    doc = identity.build_wellknown([{"keyid": "k", "pubkey": pub.hex()}])
    monkeypatch.setattr(identity, "fetch_wellknown", lambda domain, timeout=10: doc)
    assert identity.match_binding("d", pubkey_hex=pub.hex())["bound"] is True
