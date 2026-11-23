"""Identifiers asexec defines: one definition each, none repeated elsewhere in the code.

External protocol values (drand's DST, Roughtime's contexts and tags) stay with the code
that speaks those protocols; asexec does not get to choose them.

``tests/test_constants.py`` pins every value here as a literal and classifies how each one
may change. Read it before editing this file.

Names start with what they belong to and end with what they are. Keep them alphabetical.
"""

# Appears in: identity document (asexec_identity_version). Written by identity emit, read by
# nothing yet. Versions the document's shape.
IDENTITY_DOCUMENT_VERSION = 1

# Appears in: identity URL (https://<domain>/<path>). Fetched by identity match. No manifest
# field records it: identity match takes the domain from --domain.
IDENTITY_WELL_KNOWN_PATH = ".well-known/asexec.json"

# Appears in: manifest file (dsse.payloadType). Written by signing, read by format #3 to select
# the format. Also in the PAE, so the signature covers it. A released format N is vN, and goes
# with MANIFEST_PREDICATE_TYPE /vN. scripts/release.sh rewrites this literal in each release
# commit (a beta or a 0.3.x writes its own type, any other release its line's vN), and main
# keeps that value until the next release commit. A format not yet released is keyed in FORMATS
# by this name, so its key moves with the literal. While main writes a released type, a new
# format can't be keyed by this name too: the two keys would collide (#59).
MANIFEST_PAYLOAD_TYPE = "application/vnd.asexec.0.4.0b1+json"

# The rules of each format verify reads, keyed by ``payloadType``. A file is read only under
# the entry its own ``dsse.payloadType`` names, never another; one that names none fails
# ``format``. Signing uses the newest entry, ``MANIFEST_PAYLOAD_TYPE``'s.
# Only the entry under development, the one no release has shipped yet, is keyed by the name
# ``MANIFEST_PAYLOAD_TYPE``: until 0.4.0 that is the one entry, and the release commit of each
# 0.3.x or beta re-keys it. The 0.4.0 release commit (``scripts/release.sh``, before any later
# release commit rewrites the literal) makes its key the literal
# "application/vnd.asexec.v1+json", which never changes after that. From then on a released
# entry is never edited or re-keyed, and a new format adds an entry. (Out of alphabetical order,
# beside the type it is keyed by.)
FORMATS: dict[str, dict] = {
    MANIFEST_PAYLOAD_TYPE: {
        # Appears in: manifest file and body (dsse.signatures[0].keyid, body.fulfills,
        # body.prev_hash). Read by selfsig #4 and by matching. Starts every ref and keyid
        # (sha-256:<hex>); ref itself is computed, never stored.
        "digest_ref_prefix": "sha-256:",
        # Appears in: key files (alg) and identity documents (keys[].alg). Checked when a key
        # file is loaded. Not in a manifest: a DSSE signature entry is keyid and sig only.
        "signing_key_alg": "ed25519",
        # Appears in: signing input only (the PAE's first field), never stored. Used by signing
        # and selfsig #3. DSSE's own, which DSSE tooling requires, so asexec does not version
        # it; the payloadType beside it in the PAE ties a signature to this format.
        "signing_pae_version": b"DSSEv1",
    },
}

# Appears in: manifest body (body.predicateType). Written by signing, read by no test. Names
# the body for in-toto consumers; verify selects the format by dsse.payloadType.
MANIFEST_PREDICATE_TYPE = "https://asexec.org/manifest/v1"

# Appears in: manifest body (body.subject[].hash_alg, body.plan.hash_alg,
# body.evidence[].hash_alg). The writer's default, read by no test: verify reads each entry's
# own hash_alg and has no fallback.
SUBJECT_DEFAULT_HASH_ALG = "sha-256"

# Appears in: verify code (first token). Printed by verify. Versions the code's format,
# independently of the signed bytes.
VERIFY_CODE_VERSION = "asexec-verify/1"
