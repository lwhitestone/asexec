"""asexec — a pre-registration & notarization primitive for AI evaluations.

Local-first, pseudonymous, offline-verifiable. An evaluator signs a
*pre-registration* before a run and *receipts* after, publishing them to a
public git repo whose witnessed history is the (social) ceiling that gives
"pre" its meaning. A third party can verify the commitment -> fulfillment /
gap offline, trusting only a keypair and the published files.

See the module docstrings and the README for what this does — and, loudly,
what it does NOT — prove.
"""

__version__ = "0.2.0"

SCHEMA_VERSION = "asexec"
PREDICATE_TYPE = "https://asexec.dev/manifest"

__all__ = ["__version__", "SCHEMA_VERSION", "PREDICATE_TYPE"]
