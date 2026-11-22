"""drand freshness anchor.

Embedding a drand round proves a manifest was created *no earlier than* that
round's time; it is a "freshness"/anti-precomputation floor.

Verification is fully offline: the quicknet chain parameters are pinned as
constants in ``chains.py`` (no network fetch at verify time). Only fetching a fresh round
*at sign time* touches the network. A ``{chain_hash: params}`` map lets old
manifests survive a future drand network rotation.
"""

from __future__ import annotations

import hashlib
import json
import urllib.request

from .chains import CHAINS, QUICKNET_HASH
from .errors import NetworkError
from .models import Floor, FloorInput
from .parsing import MAX_NESTING_DEPTH, parse_json

# The chain signing uses: --floor fetches from it, and --floor-round must be a round of it.
# The CLI passes it to every sign-time helper (none has a default). Verify never reads it.
SIGNING_CHAIN = QUICKNET_HASH

# A signature is a G1 point in its one compressed encoding, this many bytes.
_G1_SIGNATURE_LENGTH = 48

# RFC 9380 ciphersuite DST for BLS signatures on G1 (minimal-signature-size).
_DST = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"

_API_MIRRORS = [
    "https://api.drand.sh",
    "https://api2.drand.sh",
    "https://api3.drand.sh",
]


def compute_round_time(round_no: int, chain_hash: str) -> int:
    p = CHAINS[chain_hash]
    return p["genesis_time"] + (round_no - 1) * p["period"]


def fetch_latest_round(chain_hash: str) -> dict:
    """Fetch the latest round of ``chain_hash`` from a public drand mirror, verified
    (``build_verified_floor``). SIGN-TIME ONLY."""
    last_err = None
    for base in _API_MIRRORS:
        url = f"{base}/{chain_hash}/public/latest"
        try:
            with urllib.request.urlopen(url, timeout=10) as resp:
                raw = resp.read()
            data = parse_json(raw.decode(json.detect_encoding(raw)), MAX_NESTING_DEPTH)
            floor = build_verified_floor(data, chain_hash)  # one that fails: try the next mirror
            return {
                "beacon": CHAINS[chain_hash]["beacon_id"],
                "chain_hash": chain_hash,
                "round": floor["round"],
                "randomness": floor["randomness"],
                "signature": floor["signature"],
            }
        except Exception as e:  # try next mirror
            last_err = e
    raise NetworkError(f"could not fetch drand round from any mirror: {last_err}")


def build_floor_record(round_data: dict) -> dict:
    """Wrap a fetched round into a typed ``anchor.floor`` record.

    The floor is the signed, sign-time *freshness beacon*: it proves the
    manifest was created **no earlier than** this round's public moment. It is
    a beacon (a value fixed at T, independent of the manifest), and can be
    embedded in the signed body. Raises ``ValidationError`` if the round is not a
    well-formed drand round (``models.Floor``).
    """
    return Floor(
        floor_type="drand",
        chain_hash=round_data["chain_hash"],
        round=int(round_data["round"]),
        signature=round_data["signature"],
        randomness=round_data["randomness"],
    ).model_dump(mode="json", exclude_none=True)


def build_verified_floor(round_data: dict, chain_hash: str) -> dict:
    """An ``anchor.floor`` record for a fetched round, verified offline at signing.

    ``round_data`` is a round as drand's HTTP API returns it (``round``, ``randomness``,
    ``signature``) for ``chain_hash``, the chain the caller signs with. The
    record must meet every floor condition, as verify judges it (``verify_floor``): a pinned
    chain, an integer round, lowercase hex, ``randomness == sha256(signature)``, and a BLS
    signature for the round under the pinned key. Raises ``ValueError`` otherwise (a
    pydantic ``ValidationError`` is one), so an unverifiable round is never signed."""
    floor = Floor(  # strict: a round of "1000" or true is not an integer, here as in verify
        floor_type="drand",
        chain_hash=chain_hash,
        round=round_data["round"],
        signature=round_data["signature"],
        randomness=round_data["randomness"],
    ).model_dump(mode="json", exclude_none=True)
    if verify_floor(FloorInput.model_validate(floor))["status"] != "verified":
        beacon = CHAINS[chain_hash]["beacon_id"]
        raise ValueError(
            f"round {floor['round']} does not verify against the pinned {beacon} chain "
            "(its BLS signature for that round, or randomness = sha256(signature))"
        )
    return floor


def fetch_floor(chain_hash: str) -> dict:
    """Fetch the latest round of ``chain_hash`` as an ``anchor.floor`` record. SIGN-TIME
    ONLY."""
    return build_floor_record(fetch_latest_round(chain_hash))


def verify_floor(floor: FloorInput) -> dict:
    """Offline verification of a parsed ``anchor.floor``: floor #4 (randomness equals
    sha256(signature)) and #5 (BLS). Its shape is ``models.FloorInput``'s job.

    Returns ``{status, ...}`` where status is ``verified`` / ``invalid``. Never raises.
    """
    try:
        ok = verify_round(
            floor.round, floor.signature, floor.randomness, chain_hash=floor.chain_hash
        )
        t = compute_round_time(floor.round, floor.chain_hash)
    except Exception as e:  # e.g. a round too large for 8 bytes
        return {"status": "invalid", "error": str(e)}
    return {
        "status": "verified" if ok else "invalid",
        "floor_type": "drand",
        "round": floor.round,
        "created_no_earlier_than": t,
    }


def verify_round(
    round_no: int,
    signature_hex: str,
    randomness_hex: str | None,
    *,
    chain_hash: str,
) -> bool:
    """Offline BLS verification of a round of ``chain_hash``.

    Checks (a) randomness == sha256(signature) unless ``randomness_hex`` is None (a floor
    may leave it out), (b) the signature is the 48-byte encoding of a point in G1, and (c)
    it is the BLS12-381 signature over sha256(round) under that chain's pinned group public
    key. With (b) a round has one signature, and so one randomness.
    """
    if chain_hash not in CHAINS:
        return False
    params = CHAINS[chain_hash]

    sig_bytes = bytes.fromhex(signature_hex)
    # decompress_G1 is strict about 48 bytes, but ignores any bit above them
    if len(sig_bytes) != _G1_SIGNATURE_LENGTH:
        return False
    if randomness_hex is not None:
        if hashlib.sha256(sig_bytes).hexdigest() != randomness_hex:
            return False

    # Lazy import: BLS math is only needed when actually verifying a round.
    from py_ecc.bls.hash_to_curve import hash_to_G1
    from py_ecc.bls.point_compression import decompress_G1, decompress_G2
    from py_ecc.optimized_bls12_381 import G2, curve_order, is_inf, multiply, pairing

    pub = bytes.fromhex(params["public_key"])  # 96-byte compressed G2
    try:
        pk = decompress_G2((int.from_bytes(pub[:48], "big"), int.from_bytes(pub[48:], "big")))
        sig = decompress_G1(int.from_bytes(sig_bytes, "big"))  # 48-byte compressed G1
    except Exception:
        return False
    # decompress_G1 checks the curve, not the subgroup, and a point outside G1 can pair as the
    # genuine signature does
    if not is_inf(multiply(sig, curve_order)):
        return False

    msg = hashlib.sha256(round_no.to_bytes(8, "big")).digest()
    h = hash_to_G1(msg, _DST, hashlib.sha256)
    # e(sig, G2_gen) == e(H(m), pubkey)
    return pairing(G2, sig) == pairing(pk, h)
