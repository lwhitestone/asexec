"""Identifiers asexec defines: one definition each, none repeated elsewhere in the code.

External protocol values (drand's DST, Roughtime's contexts and tags) stay with the code
that speaks those protocols; asexec does not get to choose them.

``tests/test_constants.py`` pins every value here as a literal and classifies how each one
may change. Read it before editing this file.

Names start with what they belong to and end with what they are. Keep them alphabetical.
A ``_VERSION`` value carries a version that changes with the format; a value with no version
in it is not called one.
"""

# Version of the identity document's shape (``asexec_identity_version``).
IDENTITY_DOCUMENT_VERSION = 1

# Where a domain publishes its identity document.
IDENTITY_WELL_KNOWN_PATH = ".well-known/asexec.json"

# Media type of the signed payload (an asexec manifest body), written to ``dsse.payloadType``,
# and the format signing writes: the key of its ``FORMATS`` entry. Format N is ``vN``, and goes with
# ``MANIFEST_PREDICATE_TYPE`` ``/vN``. ``scripts/release.sh`` rewrites this literal in each
# release commit (a beta writes its own type); the entry under development is keyed by this
# name, so its key moves with it.
MANIFEST_PAYLOAD_TYPE = "application/vnd.asexec.v1+json"

# The rules of each format verify reads, keyed by ``payloadType``. A file is read only under
# the entry its own ``dsse.payloadType`` names, never another; one that names none fails
# ``format``. Signing uses the newest entry, ``MANIFEST_PAYLOAD_TYPE``'s.
# Only the entry under development, the one no release has shipped yet, is keyed by the name
# ``MANIFEST_PAYLOAD_TYPE``: until 0.4.0 that is the one entry, and each beta's release commit
# re-keys it. The 0.4.0 release commit (``scripts/release.sh``, before any later release
# commit rewrites the literal) makes its key the literal "application/vnd.asexec.v1+json",
# which never changes after that. From then on a released entry is never edited or re-keyed,
# and a new format adds an entry. (Out of alphabetical order, beside the type it is keyed by.)
FORMATS: dict[str, dict] = {
    MANIFEST_PAYLOAD_TYPE: {
        # Starts every ``ref`` and ``keyid``: ``sha-256:<hex>``. It names the hash behind them.
        "digest_ref_prefix": "sha-256:",
        # The signature algorithm of this format, named in key files and identity documents.
        # A manifest names none (a DSSE signature entry is keyid and sig): it is the format's.
        "signing_key_alg": "ed25519",
        # First field of the PAE signing input: DSSE's own, which standard DSSE tooling
        # requires, so asexec does not version it. The payloadType beside it in the PAE is
        # what ties a signature to this format.
        "signing_pae_version": b"DSSEv1",
    },
}

# Written to the ``predicateType`` field of every manifest body: the only format identifier
# in the body.
MANIFEST_PREDICATE_TYPE = "https://asexec.org/manifest/v1"

# The ``hash_alg`` signing hashes a subject entry with when the signer does not choose one.
# Signing writes it into every entry, so verify never reads this: it has no fallback, and
# reads each entry's own ``hash_alg``.
SUBJECT_DEFAULT_HASH_ALG = "sha-256"

# The first token of the verify code. It versions the *code format*, independently of the
# signed bytes.
VERIFY_CODE_VERSION = "asexec-verify/1"
