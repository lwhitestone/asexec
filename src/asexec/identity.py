"""Key <-> domain binding via a ``.well-known`` self-assertion.

The manifest ``identity`` slot is an open list of assertions, so richer schemes
(web-of-trust, key transparency, external anchoring) can be added later as new
assertion types with no core change. asexec is not a CA - a domain owner
asserts which keys speak for it; a verifier checks against the domain's
existing TLS-served ``.well-known``.

Caveat (surfaced to the user): the check is point-in-time. A domain can rotate
or drop keys; a historical binding needs an archived snapshot.
"""

from __future__ import annotations

import json
import urllib.request

from .constants import (
    FORMATS,
    IDENTITY_DOCUMENT_VERSION,
    IDENTITY_WELL_KNOWN_PATH,
    MANIFEST_PAYLOAD_TYPE,
)
from .errors import AsexecError, NetworkError
from .manifest import parse_json


def build_wellknown(keyid_pubkey_pairs: list[dict[str, str]], domain: str | None = None) -> dict:
    """Build the ``.well-known/asexec.json`` document a domain publishes."""
    alg = FORMATS[MANIFEST_PAYLOAD_TYPE]["signing_key_alg"]  # the format signing writes
    doc: dict = {
        "asexec_identity_version": IDENTITY_DOCUMENT_VERSION,
        "keys": [
            {"alg": alg, "keyid": p["keyid"], "public_key": p["pubkey"]} for p in keyid_pubkey_pairs
        ],
    }
    if domain:
        doc["domain"] = domain
    return doc


def write_wellknown(doc: dict, path: str) -> None:
    with open(path, "w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")


def _wellknown_url(domain: str) -> str:
    return f"https://{domain.rstrip('/')}/{IDENTITY_WELL_KNOWN_PATH}"


def fetch_wellknown(domain: str, timeout: int = 10) -> dict:
    """HTTPS GET https://<domain>/.well-known/asexec.json (network; identity-check only)."""
    url = _wellknown_url(domain)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            data = resp.read()
    except Exception as e:
        raise NetworkError(f"could not fetch {url}: {e}") from e
    try:  # a manifest file's JSON rules, so a document reads the same on every Python
        return parse_json(data.decode("utf-8"))
    except UnicodeDecodeError as e:
        raise AsexecError(
            f"{url} is not an asexec identity document: not UTF-8 text ({e})"
        ) from None
    except (ValueError, AsexecError) as e:
        raise AsexecError(f"{url} is not an asexec identity document: {e}") from None


def match_binding(
    domain: str, keyid: str | None = None, pubkey_hex: str | None = None, timeout: int = 10
) -> dict:
    """Check whether a key is asserted by a domain. Returns a result dict."""
    doc = fetch_wellknown(domain, timeout=timeout)
    listed = _listed_keys(doc, _wellknown_url(domain))
    match = None
    for k in listed:
        if keyid and k.get("keyid") == keyid:
            match = k
            break
        if pubkey_hex and k.get("public_key") == pubkey_hex:
            match = k
            break
    return {
        "domain": domain,
        "bound": match is not None,
        "matched": match,
        "listed_count": len(listed),
        "caveat": "point-in-time: the domain can change its published keys; "
        "a historical binding needs an archived snapshot.",
    }


def _listed_keys(doc, url: str) -> list[dict]:
    """The key entries an identity document lists (none if it has no ``keys``). A document
    that is not an object holding an array of objects raises ``AsexecError``: what a domain
    serves is not trusted to have the shape it should."""
    why = None
    if not isinstance(doc, dict):
        why = "not a JSON object"
    else:
        listed = doc.get("keys")
        if listed is None:
            return []
        if not (isinstance(listed, list) and all(isinstance(k, dict) for k in listed)):
            why = "'keys' is not an array of objects"
    if why:
        raise AsexecError(f"{url} is not an asexec identity document: {why}")
    return listed
