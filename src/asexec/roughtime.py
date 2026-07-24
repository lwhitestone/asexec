"""Roughtime ceiling witness (optional, opt-in).

A **ceiling** proves a manifest was created *no later than* time T. Unlike the
drand floor (a public *beacon*, embeddable in the signed body), a ceiling needs
an external **witness** that ingested ``hash(M)`` and attested a time — so it
attaches at the ENVELOPE level (its nonce is ``ref(payload)``, which cannot live
inside the body it hashes). 0.2.0 uses Roughtime: a server signs a response
committing to the client's nonce and a timestamp, under a long-lived key we
**pin**. Verification is therefore fully offline against a pinned constant —
exactly like a drand round — trading proof-of-work's "trust no one" for a
signature-witness's "trust these signers about time" (a *different* trust class,
surfaced explicitly by the verifier).

Wire format (this implementation — spec'd here so any third party reproduces it)
--------------------------------------------------------------------------------
A Roughtime *message* is a tag→value map serialized as::

    uint32(N)                      # number of tags
    uint32[N-1]                    # cumulative end-offsets of values 0..N-2
    tag[N]                         # 4-byte tags, ascending by little-endian uint32
    bytes                          # concatenated values (each 4-byte aligned)

A server **response** message carries:
  - ``SIG``  : Ed25519 sig by the *delegated* (online) key over
               ``RESPONSE_CONTEXT || SREP``.
  - ``NONC`` : (optional echo)
  - ``PATH`` : concatenated 64-byte sibling hashes of the Merkle path.
  - ``SREP`` : signed response = message{``RADI``,``MIDP``,``ROOT``}.
  - ``CERT`` : message{``DELE``, ``SIG``} — the delegation.
  - ``INDX`` : uint32 leaf index of this nonce in the Merkle tree.

  ``DELE`` = message{``MINT``,``MAXT``,``PUBK``}: the long-term key delegates the
  online key ``PUBK`` for the validity window [``MINT``,``MAXT``]. ``CERT.SIG``
  is the long-term key's signature over ``DELEGATION_CONTEXT || DELE``.

Timestamps (``MIDP``,``MINT``,``MAXT``) are uint64 **microseconds** since the
Unix epoch; ``RADI`` is uint32 microseconds. The Merkle tree uses SHA-512:
leaf ``H(0x00 || nonce)``, interior ``H(0x01 || left || right)``.

Verification (offline)
----------------------
  1. Resolve the server's long-term public key from the pinned ``SERVERS`` map
     by ``witness_id`` — the key comes from a PINNED CONSTANT, never from the
     attestation itself (that is what makes it a trust anchor).
  2. ``CERT.SIG`` verifies ``DELE`` under the pinned long-term key.
  3. ``SIG`` verifies ``SREP`` under the delegated key ``DELE.PUBK``.
  4. The Merkle path (``PATH``,``INDX``) roots the client nonce at ``SREP.ROOT``.
  5. ``DELE.MINT <= SREP.MIDP <= DELE.MAXT`` (the online key was valid then).
  6. The nonce equals ``ref(payload)`` (checked by the caller).

**Reconciliation status:** the wire format is confirmed against a *live*
``int08h-Roughtime`` response — a real captured response is baked as an offline
fixture (``tests/test_roughtime.py``) and verifies against the pinned key with
no network, alongside the wire-accurate synthetic fixtures. The other pinned
servers were not reached during capture (UDP reachability, not a known format
mismatch), so end-to-end interop is proven for int08h and *expected but
unproven* for the rest; ``fetch_ceiling`` fails safe if any server's variant
differs.
"""

from __future__ import annotations

import hashlib
import socket
import struct
from typing import Dict, List, Optional

from . import keys
from .errors import NetworkError, VerificationError

# --- pinned Roughtime servers (one source of truth for both verify and fetch).
# ``pubkey`` is the long-term public key used as the VERIFY-time trust anchor (a
# pinned constant, never taken from the wire); ``host``/``port`` are for the
# sign-time fetch client. ``variant`` records the wire protocol so verify can
# dispatch once more than one is supported (today only IETF-Roughtime is).
#
# Provenance: the official Roughtime ecosystem list
# (https://raw.githubusercontent.com/cloudflare/roughtime/master/ecosystem.json).
# ALPHA CAVEAT: pinned for prototype expediency; the wire format has not yet been
# reconciled against a *live* capture from these servers (the tracked follow-up),
# so a real fetch→verify round trip may fail safe until that lands.
SERVERS: Dict[str, Dict[str, object]] = {
    "Cloudflare-Roughtime-2": {
        "host": "roughtime.cloudflare.com", "port": 2003, "variant": "IETF-Roughtime",
        "pubkey": bytes.fromhex(
            "d060fb737c8ff3111ce19976cdeb8dd9294bbc3555a1c8ec3d22fcfd197fef38"),
    },
    "int08h-Roughtime": {
        "host": "roughtime.int08h.com", "port": 2002, "variant": "IETF-Roughtime",
        "pubkey": bytes.fromhex(
            "016e6e0284d24c37c6e4d7d8d5b4e1d3c1949ceaa545bf875616c9dce0c9bec1"),
    },
    "roughtime.se": {
        "host": "roughtime.se", "port": 2002, "variant": "IETF-Roughtime",
        "pubkey": bytes.fromhex(
            "4b70337d92790a349d909db564919bc6a7583ff4a813c7d7298d3e6a272c7a12"),
    },
    "time.txryan.com": {
        "host": "time.txryan.com", "port": 2002, "variant": "IETF-Roughtime",
        "pubkey": bytes.fromhex(
            "881563c60ff58fbcb5fa44144c161d4da6f10a9a5eb14ff4ec3e0f303264d960"),
    },
}

DELEGATION_CONTEXT = b"RoughTime v1 delegation signature--\x00"
RESPONSE_CONTEXT = b"RoughTime v1 response signature\x00"

NONCE_LEN = 32          # our nonce = sha-256(body): 32 bytes
_TREE_LEAF = b"\x00"
_TREE_NODE = b"\x01"
_REQUEST_MIN_LEN = 1024  # amplification defense (padding)


# --------------------------------------------------------------------------- #
# message framing
# --------------------------------------------------------------------------- #
def _tag_bytes(tag: str) -> bytes:
    b = tag.encode("ascii")
    if len(b) > 4:
        raise ValueError(f"tag too long: {tag!r}")
    return b + b"\x00" * (4 - len(b))


def _tag_key(tag: str) -> int:
    return int.from_bytes(_tag_bytes(tag), "little")


def build_message(fields: Dict[str, bytes]) -> bytes:
    """Serialize a tag→value map to a Roughtime message (tags ascending)."""
    items = sorted(fields.items(), key=lambda kv: _tag_key(kv[0]))
    n = len(items)
    for _tag, val in items:
        if len(val) % 4 != 0:
            raise ValueError("Roughtime values must be 4-byte aligned")
    out = struct.pack("<I", n)
    offset = 0
    for _tag, val in items[:-1]:
        offset += len(val)
        out += struct.pack("<I", offset)
    for tag, _val in items:
        out += _tag_bytes(tag)
    for _tag, val in items:
        out += val
    return out


def parse_message(data: bytes) -> Dict[str, bytes]:
    """Parse a Roughtime message into a tag→value map. Strict: raises on malformed."""
    if len(data) < 4:
        raise VerificationError("roughtime message too short")
    (n,) = struct.unpack_from("<I", data, 0)
    if n == 0 or n > 1024:
        raise VerificationError("roughtime message: implausible tag count")
    header_len = 4 + (n - 1) * 4 + n * 4  # count + offsets + tags
    if len(data) < header_len:
        raise VerificationError("roughtime message: header truncated")
    pos = 4
    offsets = []
    for _ in range(n - 1):
        (off,) = struct.unpack_from("<I", data, pos)
        offsets.append(off)
        pos += 4
    tags = []
    for _ in range(n):
        tags.append(data[pos:pos + 4])
        pos += 4
    values_start = pos
    bounds = [0] + offsets + [len(data) - values_start]
    if any(bounds[i] > bounds[i + 1] for i in range(len(bounds) - 1)):
        raise VerificationError("roughtime message: non-monotonic offsets")
    # All values are 4-byte aligned (the wire spec); enforce on parse so a
    # crafted message can't smuggle misaligned/overlapping field boundaries.
    if any(b % 4 != 0 for b in bounds):
        raise VerificationError("roughtime message: unaligned value offset")
    # Tags MUST be strictly ascending by little-endian uint32. This both pins a
    # canonical order and rejects duplicate tags (a duplicate would otherwise
    # silently overwrite an earlier value in the dict).
    keys = [int.from_bytes(t, "little") for t in tags]
    if any(keys[i] >= keys[i + 1] for i in range(len(keys) - 1)):
        raise VerificationError("roughtime message: tags not strictly ascending")
    fields: Dict[str, bytes] = {}
    for i, tag in enumerate(tags):
        start = values_start + bounds[i]
        end = values_start + bounds[i + 1]
        if end > len(data):
            raise VerificationError("roughtime message: value out of bounds")
        fields[tag.rstrip(b"\x00").decode("ascii")] = data[start:end]
    return fields


# --------------------------------------------------------------------------- #
# Merkle tree
# --------------------------------------------------------------------------- #
def _sha512(*parts: bytes) -> bytes:
    h = hashlib.sha512()
    for p in parts:
        h.update(p)
    return h.digest()


def _uint(fields: Dict[str, bytes], tag: str, size: int) -> int:
    """Read a fixed-width little-endian unsigned int, enforcing its exact length.

    A wrong-length field is a rejection, not a silently-reinterpreted value: a
    truncated `MINT`/`MAXT`/`MIDP` would otherwise decode to a different number
    and could skew the validity-window check.
    """
    v = fields[tag]
    if len(v) != size:
        raise VerificationError(f"roughtime {tag} must be {size} bytes, got {len(v)}")
    return int.from_bytes(v, "little")


def merkle_root(nonce: bytes, path: bytes, index: int) -> bytes:
    """Recompute the Merkle root from the client nonce, path, and leaf index."""
    if len(path) % 64 != 0:
        raise VerificationError("roughtime PATH not a multiple of 64 bytes")
    node = _sha512(_TREE_LEAF, nonce)
    for i in range(0, len(path), 64):
        sibling = path[i:i + 64]
        if index & 1:
            node = _sha512(_TREE_NODE, sibling, node)
        else:
            node = _sha512(_TREE_NODE, node, sibling)
        index >>= 1
    return node


# --------------------------------------------------------------------------- #
# verification
# --------------------------------------------------------------------------- #
def verify_response(response: bytes, nonce: bytes, long_term_pubkey: bytes) -> Dict[str, float]:
    """Verify a raw Roughtime response against a nonce and a PINNED long-term key.

    Returns ``{"midpoint": <unix seconds>, "radius": <seconds>}`` on success;
    raises ``VerificationError`` on any failed check (fail-safe — a parse or
    signature problem is a rejection, never a silent pass).
    """
    msg = parse_message(response)
    for req in ("SIG", "SREP", "CERT", "INDX", "PATH"):
        if req not in msg:
            raise VerificationError(f"roughtime response missing {req}")

    # 1+2. delegation: long-term key signs DELE.
    cert = parse_message(msg["CERT"])
    if "DELE" not in cert or "SIG" not in cert:
        raise VerificationError("roughtime CERT missing DELE/SIG")
    if not keys.verify(long_term_pubkey, DELEGATION_CONTEXT + cert["DELE"], cert["SIG"]):
        raise VerificationError("roughtime CERT signature invalid (long-term key)")
    dele = parse_message(cert["DELE"])
    for req in ("MINT", "MAXT", "PUBK"):
        if req not in dele:
            raise VerificationError(f"roughtime DELE missing {req}")
    online_key = dele["PUBK"]
    if len(online_key) != 32:
        raise VerificationError("roughtime DELE.PUBK not 32 bytes")
    mint = _uint(dele, "MINT", 8)
    maxt = _uint(dele, "MAXT", 8)

    # 3. response: delegated key signs SREP.
    if not keys.verify(online_key, RESPONSE_CONTEXT + msg["SREP"], msg["SIG"]):
        raise VerificationError("roughtime SREP signature invalid (delegated key)")
    srep = parse_message(msg["SREP"])
    for req in ("ROOT", "MIDP", "RADI"):
        if req not in srep:
            raise VerificationError(f"roughtime SREP missing {req}")
    midp = _uint(srep, "MIDP", 8)
    radi = _uint(srep, "RADI", 4)

    # 4. Merkle path roots this nonce.
    index = _uint(msg, "INDX", 4)
    if merkle_root(nonce, msg["PATH"], index) != srep["ROOT"]:
        raise VerificationError("roughtime Merkle path does not root the nonce")

    # 5. the online key was valid at the attested midpoint.
    if not (mint <= midp <= maxt):
        raise VerificationError("roughtime midpoint outside delegation validity window")

    return {"midpoint": midp / 1e6, "radius": radi / 1e6}


def verify_ceiling(ceiling: Dict[str, object], expected_nonce: str,
                   servers: Optional[Dict[str, Dict[str, object]]] = None) -> Dict[str, object]:
    """Verify an envelope ``ceiling`` record and its binding to ``expected_nonce``.

    ``expected_nonce`` is the manifest's ``ref`` (``sha-256:<hex>``); the ceiling
    binds iff its nonce equals that digest. The long-term key is resolved from
    the pinned ``servers`` map (default ``SERVERS``) by ``witness_id``, NOT taken
    from the record.
    """
    servers = SERVERS if servers is None else servers
    out: Dict[str, object] = {"status": "invalid",
                              "witness_id": ceiling.get("witness_id"),
                              "midpoint": ceiling.get("midpoint"),
                              "radius": ceiling.get("radius")}
    if ceiling.get("ceiling_type") != "roughtime":
        out["status"] = "unsupported"
        out["error"] = f"unknown ceiling_type {ceiling.get('ceiling_type')!r}"
        return out

    want_hex = expected_nonce.split(":", 1)[-1]
    if ceiling.get("nonce") != want_hex:
        out["error"] = "ceiling nonce does not bind to this manifest (nonce != ref)"
        return out

    witness_id = ceiling.get("witness_id")
    entry = servers.get(witness_id) if isinstance(witness_id, str) else None
    pinned = entry.get("pubkey") if entry else None
    if not isinstance(pinned, (bytes, bytearray)):
        out["status"] = "unpinned"
        out["error"] = (f"no pinned long-term key for witness {witness_id!r}; "
                        "cannot verify against a trust anchor")
        return out
    # If the record advertises a long-term pubkey, it must match the pinned one.
    adv = ceiling.get("pubkey")
    if isinstance(adv, str) and bytes.fromhex(adv) != pinned:
        out["error"] = "record long-term pubkey does not match the pinned key"
        return out

    try:
        nonce = bytes.fromhex(want_hex)
        response = bytes.fromhex(ceiling["response"])  # type: ignore[index]
        info = verify_response(response, nonce, pinned)
    except (VerificationError, KeyError, ValueError) as e:
        out["error"] = str(e)
        return out

    out["status"] = "verified"
    out["midpoint"] = info["midpoint"]
    out["radius"] = info["radius"]
    return out


# --------------------------------------------------------------------------- #
# sign-time client (network) — implemented to spec; unreconciled with real
# servers (the deferred follow-up). Fails safe if a server's variant differs.
# --------------------------------------------------------------------------- #
def build_request(nonce: bytes, version: int = 1) -> bytes:
    """Build a padded Roughtime request message for a nonce."""
    fields = {"VER": struct.pack("<I", version), "NONC": nonce}
    msg = build_message(fields)
    if len(msg) < _REQUEST_MIN_LEN:
        # Adding ZZZZ grows the header by 8 bytes (one offset entry + one tag)
        # on top of its value; account for both so the result is >= the minimum.
        need = _REQUEST_MIN_LEN - len(msg) - 8
        fields["ZZZZ"] = b"\x00" * (((need + 3) // 4) * 4 if need > 0 else 0)
        msg = build_message(fields)
    return msg


def fetch_ceiling(nonce_ref: str, servers: Optional[Dict[str, Dict[str, object]]] = None,
                  timeout: float = 5.0) -> Dict[str, object]:
    """Fetch a ceiling witness for ``nonce_ref`` (``sha-256:<hex>``). SIGN-TIME, NETWORK.

    ``servers`` is the unified ``SERVERS`` map (``witness_id -> {host, port,
    pubkey, ...}``); defaults to the pinned ``SERVERS``. Returns an envelope
    ceiling record. Raises ``NetworkError`` if no server answers with a response
    that verifies against its pinned key.
    """
    servers = SERVERS if servers is None else servers
    if not servers:
        raise NetworkError("no Roughtime servers configured to fetch a ceiling from")
    nonce = bytes.fromhex(nonce_ref.split(":", 1)[-1])
    request = build_request(nonce)
    last_err: Optional[Exception] = None
    for witness_id, entry in servers.items():
        host, port, pubkey = entry["host"], entry["port"], entry["pubkey"]
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            try:
                sock.sendto(request, (host, port))
                data, _ = sock.recvfrom(4096)
            finally:
                sock.close()
            response = _strip_framing(data)
            info = verify_response(response, nonce, pubkey)
            return {
                "ceiling_type": "roughtime",
                "witness_id": witness_id,
                "pubkey": pubkey.hex(),
                "nonce": nonce.hex(),
                "midpoint": info["midpoint"],
                "radius": info["radius"],
                "response": response.hex(),
            }
        except Exception as e:  # try the next server
            last_err = e
    raise NetworkError(f"no Roughtime server produced a verifiable response: {last_err}")


def _strip_framing(packet: bytes) -> bytes:
    """Strip the optional ``ROUGHTIM`` + length UDP framing, if present."""
    if packet[:8] == b"ROUGHTIM":
        (length,) = struct.unpack_from("<I", packet, 8)
        return packet[12:12 + length]
    return packet
