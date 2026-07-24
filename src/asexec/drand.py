"""drand freshness anchor (optional, default-on).

Embedding a drand round proves a manifest was created *no earlier than* that
round's time — a FRESHNESS / anti-precomputation floor. It is NOT an
anti-backdating mechanism (that needs a ceiling; v1's ceiling is the witnessed
public repo). See 00-context.md §3a and 02-brainstorm.md.

Verification is fully offline: the quicknet chain parameters are pinned as
constants here (no network fetch at verify time). Only fetching a fresh round
*at sign time* touches the network. A ``{chain_hash: params}`` map lets old
manifests survive a future drand network rotation.
"""

from __future__ import annotations

import hashlib
import json
import urllib.request
from typing import Dict, Optional

from .errors import NetworkError

# --- pinned chain parameters (verify-time constants; never fetched) ---------
QUICKNET_HASH = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"

CHAINS: Dict[str, dict] = {
    QUICKNET_HASH: {
        "beacon_id": "quicknet",
        "public_key": (
            "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c"
            "8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb"
            "5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a"
        ),
        "genesis_time": 1692803367,
        "period": 3,
        "scheme": "bls-unchained-g1-rfc9380",
    },
}

DEFAULT_CHAIN = QUICKNET_HASH

# RFC 9380 ciphersuite DST for BLS signatures on G1 (minimal-signature-size).
_DST = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"

_API_MIRRORS = [
    "https://api.drand.sh",
    "https://api2.drand.sh",
    "https://api3.drand.sh",
]


def time_of_round(round_no: int, chain_hash: str = DEFAULT_CHAIN) -> int:
    p = CHAINS[chain_hash]
    return p["genesis_time"] + (round_no - 1) * p["period"]


def round_at_time(ts: int, chain_hash: str = DEFAULT_CHAIN) -> int:
    p = CHAINS[chain_hash]
    if ts < p["genesis_time"]:
        return 1
    return (ts - p["genesis_time"]) // p["period"] + 1


def fetch_round(round_no: Optional[int] = None, chain_hash: str = DEFAULT_CHAIN) -> dict:
    """Fetch a round (default: latest) from a public drand mirror. SIGN-TIME ONLY."""
    suffix = "latest" if round_no is None else str(round_no)
    last_err = None
    for base in _API_MIRRORS:
        url = f"{base}/{chain_hash}/public/{suffix}"
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                data = json.load(resp)
            return {
                "beacon": CHAINS[chain_hash]["beacon_id"],
                "chain_hash": chain_hash,
                "round": int(data["round"]),
                "randomness": data["randomness"],
                "signature": data["signature"],
            }
        except Exception as e:  # try next mirror
            last_err = e
    raise NetworkError(f"could not fetch drand round from any mirror: {last_err}")


def floor_record(round_data: dict) -> dict:
    """Wrap a fetched round into a typed ``anchor.floor`` record.

    The floor is the signed, sign-time *freshness beacon*: it proves the
    manifest was created **no earlier than** this round's public moment. It is
    a beacon (a value fixed at T, independent of the manifest), which is why it
    can be embedded in the signed body — unlike the ceiling witness.
    """
    return {
        "floor_type": "drand",
        "chain_hash": round_data["chain_hash"],
        "round": int(round_data["round"]),
        "signature": round_data["signature"],
        "randomness": round_data["randomness"],
    }


def fetch_floor(chain_hash: str = DEFAULT_CHAIN) -> dict:
    """Fetch the latest round and return it as an ``anchor.floor`` record. SIGN-TIME ONLY."""
    return floor_record(fetch_round(chain_hash=chain_hash))


def verify_floor(floor: dict) -> dict:
    """Offline verification of an ``anchor.floor`` record.

    Returns ``{status, ...}`` where status is ``verified`` / ``invalid`` /
    ``unsupported`` (an unknown ``floor_type``).
    """
    ftype = floor.get("floor_type")
    if ftype != "drand":
        return {"status": "unsupported", "floor_type": ftype}
    try:
        chain = floor.get("chain_hash", DEFAULT_CHAIN)
        ok = verify_round(int(floor["round"]), floor["signature"],
                          floor.get("randomness"), chain_hash=chain)
        t = time_of_round(int(floor["round"]), chain)
        return {"status": "verified" if ok else "invalid", "floor_type": "drand",
                "round": int(floor["round"]), "created_no_earlier_than": t}
    except Exception as e:
        return {"status": "invalid", "error": str(e)}


def verify_round(
    round_no: int,
    signature_hex: str,
    randomness_hex: Optional[str] = None,
    chain_hash: str = DEFAULT_CHAIN,
) -> bool:
    """Offline BLS verification of a quicknet round.

    Checks (a) randomness == sha256(signature) if provided, and (b) the
    BLS12-381 signature over sha256(round) against the pinned group public key.
    """
    if chain_hash not in CHAINS:
        return False
    params = CHAINS[chain_hash]

    sig_bytes = bytes.fromhex(signature_hex)
    if randomness_hex is not None:
        if hashlib.sha256(sig_bytes).hexdigest() != randomness_hex:
            return False

    # Lazy import: BLS math is only needed when actually verifying a round.
    from py_ecc.optimized_bls12_381 import pairing, G2
    from py_ecc.bls.hash_to_curve import hash_to_G1
    from py_ecc.bls.point_compression import decompress_G1, decompress_G2

    pub = bytes.fromhex(params["public_key"])  # 96-byte compressed G2
    try:
        pk = decompress_G2(
            (int.from_bytes(pub[:48], "big"), int.from_bytes(pub[48:], "big"))
        )
        sig = decompress_G1(int.from_bytes(sig_bytes, "big"))  # 48-byte compressed G1
    except Exception:
        return False

    msg = hashlib.sha256(round_no.to_bytes(8, "big")).digest()
    h = hash_to_G1(msg, _DST, hashlib.sha256)
    # e(sig, G2_gen) == e(H(m), pubkey)
    return pairing(G2, sig) == pairing(pk, h)
