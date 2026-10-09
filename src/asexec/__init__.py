"""asexec - a pre-registration & notarization primitive for AI evaluations.

Local-first, pseudonymous, offline-verifiable. An evaluator signs a
*pre-registration* before a run and *post-registrations* (receipts) after,
publishing them to a public git repo whose witnessed history is the (social)
ceiling that gives "pre" its meaning; an optional drand floor and Roughtime
ceiling add cryptographic time bounds. A third party can verify the
commitment -> fulfillment / gap offline against the published files, with a
verify code that names exactly which tests ran. Verification proves internal
consistency, not who signed or that the pre-registration was complete.

See the module docstrings and the README for what this does!
"""

__version__ = "0.3.14"

SCHEMA_VERSION = "asexec"
PREDICATE_TYPE = "https://asexec.dev/manifest"

__all__ = ["__version__", "SCHEMA_VERSION", "PREDICATE_TYPE"]
