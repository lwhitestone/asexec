"""Identifiers asexec defines: one definition each, none repeated elsewhere in the code.

External protocol values (drand's DST, Roughtime's contexts and tags) stay with the code
that speaks those protocols; asexec does not get to choose them.

``tests/test_constants.py`` pins every value here as a literal and classifies how each one
may change. Read it before editing this file.

Names start with what they belong to and end with what they are. Keep them alphabetical.
A ``_VERSION`` value carries a version that changes with the format; a value with no version
in it is not called one.
"""

# Starts every ``ref`` and ``keyid``: ``sha-256:<hex>``. It names the hash behind them.
DIGEST_REF_PREFIX = "sha-256:"

# Version of the identity document's shape (``asexec_identity_version``).
IDENTITY_DOCUMENT_VERSION = 1

# Where a domain publishes its identity document.
IDENTITY_WELL_KNOWN_PATH = ".well-known/asexec.json"

# Media type of the signed payload (an asexec manifest body).
MANIFEST_PAYLOAD_TYPE = "application/vnd.asexec+json"

# Written to the ``predicateType`` field of every manifest body.
MANIFEST_PREDICATE_TYPE = "https://asexec.dev/manifest"

# Written to the ``schema_id`` field of every manifest body.
MANIFEST_SCHEMA_ID = "asexec"

# The signature algorithm named in key files, signature blocks and identity documents.
SIGNING_KEY_ALG = "ed25519"

# First field of the PAE signing input. It ties a signature to this format, so one made
# for another format can't pass as ours. Standard DSSE uses "DSSEv1" in the same position.
SIGNING_PAE_VERSION = b"asexec-PAE/v1"

# The algorithm named by ``hash_alg`` when a signer or a manifest does not choose one.
SUBJECT_DEFAULT_HASH_ALG = "sha-256"

# The first token of the verify code. It versions the *code format*, independently of the
# signed bytes.
VERIFY_CODE_VERSION = "asexec-verify/1"
