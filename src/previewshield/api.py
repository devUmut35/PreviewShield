"""Small stable Python API for embedding PreviewShield in other tools."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from previewshield.diffing import diff_targets
from previewshield.models import DiffReport, ScanReport, Severity
from previewshield.policy import Policy
from previewshield.scanner import scan as scan_target


def scan(  # noqa: PLR0913 - explicit keyword options keep the public API discoverable
    target: str,
    *,
    policy: Policy | None = None,
    paths: Sequence[str] | None = None,
    request_headers: Mapping[str, str] | None = None,
    fail_on: Severity | None = None,
    allow_private: bool | None = None,
) -> ScanReport:
    """Scan a target using the same engine as the command-line interface."""

    return scan_target(
        target,
        policy=policy,
        paths=paths,
        request_headers=request_headers,
        fail_on=fail_on,
        allow_private=allow_private,
    )


def diff(  # noqa: PLR0913 - mirrors scan options across both comparison targets
    baseline: str,
    preview: str,
    *,
    policy: Policy | None = None,
    paths: Sequence[str] | None = None,
    request_headers: Mapping[str, str] | None = None,
    fail_on: Severity | None = None,
    allow_private: bool | None = None,
) -> DiffReport:
    """Compare a preview deployment with a production baseline."""

    return diff_targets(
        baseline,
        preview,
        policy=policy,
        paths=paths,
        request_headers=request_headers,
        fail_on=fail_on,
        allow_private=allow_private,
    )


__all__ = ["diff", "scan"]
