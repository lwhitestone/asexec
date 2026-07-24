"""Key <-> domain binding via a ``.well-known`` self-assertion.

This is the ONE concrete identity mechanism in v1, and it is a *hook*: the
manifest ``identity`` slot is an open list of assertions, so richer schemes
(web-of-trust, key transparency, external anchoring) can be added later as new
assertion types with no core change. asexec is not a CA — a domain owner
asserts which keys speak for it; a verifier checks against the domain's
existing TLS-served ``.well-known``.

Caveat (surfaced to the user): the check is POINT-IN-TIME. A domain can rotate
or drop keys; a historical binding needs an archived snapshot.
"""

from __future__ import annotations

import json
import urllib.request
from typing import Dict, List, Optional

from .errors import NetworkError

WELL_KNOWN_PATH = ".well-known/asexec.json"
_ASSERTION_VERSION = 1


def build_wellknown(keyid_pubkey_pairs: List[Dict[str, str]], domain: Optional[str] = None) -> Dict:
    """Build the ``.well-known/asexec.json`` document a domain publishes."""
    doc: Dict = {
        "asexec_identity_version": _ASSERTION_VERSION,
        "keys": [
            {"alg": "ed25519", "keyid": p["keyid"], "public_key": p["pubkey"]}
            for p in keyid_pubkey_pairs
        ],
    }
    if domain:
        doc["domain"] = domain
    return doc


def write_wellknown(doc: Dict, path: str) -> None:
    with open(path, "w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")


def fetch_wellknown(domain: str, timeout: int = 10) -> Dict:
    """HTTPS GET https://<domain>/.well-known/asexec.json (network; identity-check only)."""
    url = f"https://{domain.rstrip('/')}/{WELL_KNOWN_PATH}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return json.load(resp)
    except Exception as e:
        raise NetworkError(f"could not fetch {url}: {e}")


def verify_binding(domain: str, keyid: Optional[str] = None,
                   pubkey_hex: Optional[str] = None, timeout: int = 10) -> Dict:
    """Check whether a key is asserted by a domain. Returns a result dict."""
    doc = fetch_wellknown(domain, timeout=timeout)
    listed = doc.get("keys", [])
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
