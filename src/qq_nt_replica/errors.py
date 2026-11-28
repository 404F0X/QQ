"""Explicit input, support-domain, and unavailable-capability errors."""


class InputError(ValueError):
    """An input does not match the explicit Python/JSON contract."""


class LibraryLimitError(InputError):
    """Input exceeds this library's supported normal-memory domain."""


class CapabilityUnavailable(NotImplementedError):
    """A capability has not been implemented or proved by this replica."""
