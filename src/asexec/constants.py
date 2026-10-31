"""Identifiers asexec defines: one definition each, none repeated elsewhere in the code.

External protocol values (drand's DST, Roughtime's contexts and tags) stay with the code
that speaks those protocols; asexec does not get to choose them.

``tests/test_constants.py`` pins every value here as a literal and documents what each one
reaches and how to change it. Read it before editing this file.
"""

# Domain-separation prefix for our PAE construction (cf. DSSE's "DSSEv1").
PAE_PREFIX = b"asexec-PAE/v1"

# Media type of the signed payload (an asexec manifest body).
PAYLOAD_TYPE = "application/vnd.asexec+json"

# Format frame written into every manifest body.
SCHEMA_VERSION = "asexec"
PREDICATE_TYPE = "https://asexec.dev/manifest"

# The grammar version for the verify code. Independent of the schema/PAE versions - it
# versions the *code format*, not the signed bytes.
CODE_VERSION = "asexec-verify/1"

# The hash behind every ``ref`` and ``keyid``, which spell it ``sha-256:<hex>``.
DIGEST_PREFIX = "sha-256:"

# The algorithm named by ``hash_alg`` when a signer or a manifest does not choose one.
DEFAULT_HASH_ALG = "sha-256"

# The signature algorithm named in key files, signature blocks and identity documents.
KEY_ALG = "ed25519"

# The identity document a domain publishes.
WELL_KNOWN_PATH = ".well-known/asexec.json"
IDENTITY_ASSERTION_VERSION = 1
