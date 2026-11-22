"""The pinned drand chains: the one dependency ``fields`` (floor #2) and ``drand`` share.

It imports nothing from asexec, so ``drand`` can import the models that check against it.
"""

from __future__ import annotations

# --- pinned chain parameters (verify-time constants; never fetched) ---------
# Keyed by chain hash. The values come from https://api.drand.sh/<hash>/info and are pinned
# as literals in tests/test_drand.py. A floor names its chain (body.anchor.floor.chain_hash)
# and verify never picks one. An entry is never edited or removed, so old manifests keep
# verifying. To add, switch or withdraw a chain, see "Pinned trust roots" in
# docs/DEVELOPMENT.md.
QUICKNET_HASH = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"

CHAINS: dict[str, dict] = {
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
