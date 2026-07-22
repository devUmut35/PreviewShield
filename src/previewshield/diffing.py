"""Baseline-versus-preview security regression analysis."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from previewshield.models import (
    DeltaKind,
    DiffReport,
    Finding,
    FindingDelta,
    ScanReport,
    Severity,
)
from previewshield.policy import Policy, default_policy
from previewshield.scanner import SCHEMA_VERSION, scan
from previewshield.utils import utc_now


def diff_targets(  # noqa: PLR0913 - identical scan controls are intentional
    baseline_url: str,
    preview_url: str,
    *,
    policy: Policy | None = None,
    paths: Sequence[str] | None = None,
    request_headers: Mapping[str, str] | None = None,
    fail_on: Severity | None = None,
    allow_private: bool | None = None,
) -> DiffReport:
    """Scan two deployments with identical inputs and compare their findings."""

    active_policy = policy or default_policy()
    threshold = fail_on or active_policy.fail_on
    baseline = scan(
        baseline_url,
        policy=active_policy,
        paths=paths,
        request_headers=request_headers,
        fail_on=threshold,
        allow_private=allow_private,
    )
    preview = scan(
        preview_url,
        policy=active_policy,
        paths=paths,
        request_headers=request_headers,
        fail_on=threshold,
        allow_private=allow_private,
    )
    return compare(baseline, preview, policy=active_policy, fail_on=threshold)


def compare(
    baseline: ScanReport,
    preview: ScanReport,
    *,
    policy: Policy | None = None,
    fail_on: Severity | None = None,
) -> DiffReport:
    """Compare two completed scans by stable route-and-rule fingerprints."""

    active_policy = policy or default_policy()
    threshold = fail_on or active_policy.fail_on
    baseline_findings = _by_fingerprint(baseline.findings)
    preview_findings = _by_fingerprint(preview.findings)
    deltas: list[FindingDelta] = []
    for fingerprint in sorted(set(baseline_findings) | set(preview_findings)):
        before = baseline_findings.get(fingerprint)
        after = preview_findings.get(fingerprint)
        deltas.append(_classify(fingerprint, before, after))

    delta_tuple = tuple(deltas)
    if active_policy.diff_mode == "absolute":
        passed = not any(finding.severity.rank >= threshold.rank for finding in preview.findings)
    else:
        passed = not any(
            delta.finding.severity.rank >= threshold.rank
            for delta in delta_tuple
            if delta.kind is DeltaKind.REGRESSION
        )
    return DiffReport(
        schema_version=SCHEMA_VERSION,
        tool_version=preview.tool_version,
        generated_at=utc_now(),
        policy_name=active_policy.name,
        baseline=baseline,
        preview=preview,
        deltas=delta_tuple,
        fail_on=threshold,
        passed=passed,
    )


def _by_fingerprint(findings: Sequence[Finding]) -> dict[str, Finding]:
    """Select the highest-severity instance if a route emits a duplicate identity."""

    result: dict[str, Finding] = {}
    for finding in findings:
        existing = result.get(finding.fingerprint)
        if existing is None or finding.severity.rank > existing.severity.rank:
            result[finding.fingerprint] = finding
    return result


def _classify(
    fingerprint: str,
    baseline: Finding | None,
    preview: Finding | None,
) -> FindingDelta:
    if baseline is None and preview is not None:
        return FindingDelta(DeltaKind.REGRESSION, fingerprint, preview=preview)
    if baseline is not None and preview is None:
        return FindingDelta(DeltaKind.RESOLVED, fingerprint, baseline=baseline)
    if baseline is None or preview is None:  # pragma: no cover - union guarantees one side
        raise ValueError("A comparison fingerprint must exist in at least one report.")
    if preview.severity.rank > baseline.severity.rank:
        kind = DeltaKind.REGRESSION
    elif _content_signature(preview) == _content_signature(baseline):
        kind = DeltaKind.UNCHANGED
    else:
        kind = DeltaKind.CHANGED
    return FindingDelta(kind, fingerprint, baseline=baseline, preview=preview)


def _content_signature(finding: Finding) -> tuple[object, ...]:
    return (
        finding.rule_id,
        finding.title,
        finding.severity,
        finding.category,
        finding.message,
        finding.remediation,
        finding.subject,
        finding.evidence,
        finding.references,
    )


__all__ = ["compare", "diff_targets"]
