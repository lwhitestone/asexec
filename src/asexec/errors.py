"""Exception types for asexec."""


class AsexecError(Exception):
    """Base class for all asexec errors."""


class VerificationError(AsexecError):
    """A cryptographic or structural verification check failed."""


class ManifestError(AsexecError):
    """A manifest is malformed or missing a mandatory field."""


class HashAlgError(AsexecError):
    """An unknown or unavailable content-hash algorithm was requested."""


class NetworkError(AsexecError):
    """A required network fetch (drand at sign time, or .well-known) failed."""
