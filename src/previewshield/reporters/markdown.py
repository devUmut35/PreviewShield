"""Concise GitHub-flavored Markdown reports."""

from __future__ import annotations

from collections.abc import Sequence

from previewshield.models import DiffReport, Finding, FindingDelta, ScanReport, Severity
from previewshield.reporters import (
    Report,
    _markdown_value,
    _safe_evidence,
    _safe_url,
    _sorted_deltas,
    _sorted_findings,
)

_MAX_TABLE_ROWS = 25
_MAX_FIXES = 10


def _status(passed: bool) -> str:
    return "PASS :white_check_mark:" if passed else "FAIL :x:"


def _finding_row(finding: Finding) -> str:
    return " | ".join(
        (
            f"| **{finding.severity.value.upper()}**",
            _markdown_value(finding.rule_id, limit=100),
            _markdown_value(_safe_url(finding.target), limit=300),
            f"{_markdown_value(finding.title, limit=200)} — "
            f"{_markdown_value(finding.message, limit=300)} |",
        )
    )


def _findings_table(findings: Sequence[Finding]) -> list[str]:
    lines = [
        "| Severity | Rule | Target | Finding |",
        "| --- | --- | --- | --- |",
    ]
    visible = findings[:_MAX_TABLE_ROWS]
    lines.extend(_finding_row(finding) for finding in visible)
    if len(findings) > len(visible):
        lines.append(
            f"\n_{len(findings) - len(visible)} additional findings omitted from this summary._"
        )
    return lines


def _fixes(findings: Sequence[Finding]) -> list[str]:
    if not findings:
        return []
    lines = ["", "### Recommended fixes", ""]
    for finding in findings[:_MAX_FIXES]:
        fix = _markdown_value(finding.remediation, limit=500)
        lines.append(f"- {_markdown_value(finding.rule_id, limit=100)}: {fix}")
        evidence = _safe_evidence(finding.evidence)
        if evidence:
            lines.append(f"  - Evidence: {_markdown_value(evidence, limit=240)}")
    if len(findings) > _MAX_FIXES:
        lines.append(
            f"- _{len(findings) - _MAX_FIXES} additional fixes are available in the full report._"
        )
    return lines


def _counts(report: ScanReport) -> str:
    return " · ".join(
        f"{severity.value} **{report.counts[severity.value]}**" for severity in Severity
    )


def _render_scan(report: ScanReport) -> str:
    findings = _sorted_findings(report.findings)
    lines = [
        "## PreviewShield security scan",
        "",
        f"**{_status(report.passed)}** · Score **{report.score}/100** · "
        f"Grade **{_markdown_value(report.grade, limit=20)}**",
        "",
        f"Target: {_markdown_value(_safe_url(report.target), limit=500)}  ",
        f"Policy: {_markdown_value(report.policy_name, limit=200)}  ",
        f"Failure threshold: **{report.fail_on.value}**",
        "",
        _counts(report),
    ]
    if findings:
        lines.extend(("", f"### Findings ({len(findings)})", ""))
        lines.extend(_findings_table(findings))
        lines.extend(_fixes(findings))
    else:
        lines.extend(("", "No security findings were detected."))
    return "\n".join(lines) + "\n"


def _delta_note(delta: FindingDelta) -> str:
    if delta.baseline is None or delta.preview is None:
        return ""
    if delta.baseline.severity is delta.preview.severity:
        return ""
    return f" ({delta.baseline.severity.value} → {delta.preview.severity.value})"


def _delta_table(deltas: Sequence[FindingDelta]) -> list[str]:
    lines = [
        "| Severity | Rule | Target | Finding |",
        "| --- | --- | --- | --- |",
    ]
    visible = deltas[:_MAX_TABLE_ROWS]
    for delta in visible:
        finding = delta.finding
        message = f"{finding.message}{_delta_note(delta)}"
        lines.append(
            " | ".join(
                (
                    f"| **{finding.severity.value.upper()}**",
                    _markdown_value(finding.rule_id, limit=100),
                    _markdown_value(_safe_url(finding.target), limit=300),
                    f"{_markdown_value(finding.title, limit=200)} — "
                    f"{_markdown_value(message, limit=300)} |",
                )
            )
        )
    if len(deltas) > len(visible):
        lines.append(
            f"\n_{len(deltas) - len(visible)} additional changes omitted from this summary._"
        )
    return lines


def _render_diff(report: DiffReport) -> str:
    deltas = _sorted_deltas(report.deltas)
    regressions = tuple(delta for delta in deltas if delta.kind.value == "regression")
    resolved = tuple(delta for delta in deltas if delta.kind.value == "resolved")
    changed = tuple(delta for delta in deltas if delta.kind.value == "changed")
    lines = [
        "## PreviewShield security diff",
        "",
        f"**{_status(report.passed)}** · **{len(regressions)}** regressions · "
        f"**{len(resolved)}** resolved · **{len(changed)}** changed",
        "",
        f"Baseline: {_markdown_value(_safe_url(report.baseline.target), limit=500)} "
        f"(**{report.baseline.score}/100**, {_markdown_value(report.baseline.grade, limit=20)})  ",
        f"Preview: {_markdown_value(_safe_url(report.preview.target), limit=500)} "
        f"(**{report.preview.score}/100**, {_markdown_value(report.preview.grade, limit=20)})  ",
        f"Policy: {_markdown_value(report.policy_name, limit=200)}",
    ]
    if regressions:
        lines.extend(("", f"### Regressions ({len(regressions)})", ""))
        lines.extend(_delta_table(regressions))
        lines.extend(_fixes(tuple(delta.finding for delta in regressions)))
    else:
        lines.extend(("", "### Regressions", "", "No security regressions were detected."))
    if resolved:
        lines.extend(("", f"### Resolved ({len(resolved)})", ""))
        lines.extend(_delta_table(resolved))
    if changed:
        lines.extend(("", f"### Other changes ({len(changed)})", ""))
        lines.extend(_delta_table(changed))
    return "\n".join(lines) + "\n"


def render_markdown(report: Report) -> str:
    """Render a compact Markdown summary suitable for a pull request comment."""

    if isinstance(report, ScanReport):
        return _render_scan(report)
    return _render_diff(report)


render = render_markdown

__all__ = ["render", "render_markdown"]
