"""Domain-specific errors with stable CLI exit codes."""

from __future__ import annotations


class PreviewShieldError(Exception):
    """Base class for expected PreviewShield failures."""

    exit_code = 4


class ConfigurationError(PreviewShieldError):
    """Raised when a policy file or CLI configuration is invalid."""

    exit_code = 2


class NetworkSafetyError(PreviewShieldError):
    """Raised when a target violates the safe network boundary."""

    exit_code = 3


class ScanError(PreviewShieldError):
    """Raised when a safe target cannot be scanned."""

    exit_code = 3


class ReportError(PreviewShieldError):
    """Raised when a report cannot be rendered or written."""

    exit_code = 4


class PolicyViolationError(PreviewShieldError):
    """Used by integrations when a scan crosses the configured threshold."""

    exit_code = 1
