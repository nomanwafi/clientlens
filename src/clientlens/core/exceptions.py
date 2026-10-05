"""ClientLens exception hierarchy."""


class ClientLensError(Exception):
    """Base error for all ClientLens failures."""


class AuthorizationRequired(ClientLensError):
    """Raised when a scan is attempted without the authorization flag."""


class InvalidTarget(ClientLensError):
    """Raised when a target domain/URL is malformed or unusable."""


class ProbeError(ClientLensError):
    """Raised when a probe fails unexpectedly.

    Probes should catch their own errors and emit a finding instead;
    this escapes only for genuinely unrecoverable failures.
    """


class RateLimitExceeded(ClientLensError):
    """Raised when the request budget for a target is exhausted."""
