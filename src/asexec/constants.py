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

# Media type of the signed payload (an asexec manifest body), and the format signing writes:
# the key of its ``FORMATS`` entry. Format N is ``vN``, and goes with
# ``MANIFEST_PREDICATE_TYPE`` ``/vN``. A release commit may rewrite this literal (a beta
# writes its own type); ``FORMATS`` is keyed by this name, so its key moves with it.
MANIFEST_PAYLOAD_TYPE = "application/vnd.asexec.v1+json"

# The rules of each format verify reads, keyed by ``payloadType``. A file is read only under
# the entry its own ``payloadType`` names, never another; one that names none fails
# ``format``. Signing uses the newest entry, ``MANIFEST_PAYLOAD_TYPE``'s. A new format adds an
# entry, and existing entries are never edited. (Out of alphabetical order: its key is the
# name above.)
FORMATS: dict[str, dict] = {
    MANIFEST_PAYLOAD_TYPE: {
        # Starts every ``ref`` and ``keyid``: ``sha-256:<hex>``. It names the hash behind them.
        "digest_ref_prefix": "sha-256:",
        # The signature algorithm named in key files, signature blocks and identity documents.
        "signing_key_alg": "ed25519",
        # First field of the PAE signing input. It ties a signature to this format, so one
        # made for another format can't pass as ours. Standard DSSE uses "DSSEv1" here.
        "signing_pae_version": b"asexec-PAE/v1",
        # The algorithm ``content`` reads a subject with when the manifest names none.
        "subject_default_hash_alg": "sha-256",
    },
}

# Written to the ``predicateType`` field of every manifest body: the only format identifier
# in the body.
MANIFEST_PREDICATE_TYPE = "https://asexec.org/manifest/v1"

# The ``hash_alg`` signing hashes a subject with when the signer does not choose one. Signing
# always writes ``hash_alg`` beside a subject, so verify never reads this: its fallback is the
# format's own ``subject_default_hash_alg``.
SUBJECT_DEFAULT_HASH_ALG = "sha-256"

# The first token of the verify code. It versions the *code format*, independently of the
# signed bytes.
VERIFY_CODE_VERSION = "asexec-verify/1"
