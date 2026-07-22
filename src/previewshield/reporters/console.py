"""Human-readable, ANSI-free console reports."""

from __future__ import annotations

from previewshield.models import DiffReport, Finding, ScanReport, Severity
from previewshield.reporters import (
    Report,
    _safe_evidence,
    _safe_text,
    _safe_url,
    _sorted_deltas,
    _sorted_findings,
)


def _console_value(value: str, *, limit: int = 500) -> str:
    return (
        _safe_text(value, limit=limit)
        .replace("\t", " ")
        .replace("\u2028", " ")
        .replace("\u2029", " ")
    )


def _status(passed: bool) -> str:
    return "PASS" if passed else "FAIL"


def _counts_line(report: ScanReport) -> str:
    return "  ".join(f"{severity.value}: {report.counts[severity.value]}" for severity in Severity)


def _finding_lines(finding: Finding, *, prefix: str = "") -> list[str]:
    lines = [
        f"{prefix}[{finding.severity.value.upper()}] {_console_value(finding.rule_id, limit=100)} "
        f"- {_console_value(finding.title)}",
        f"{prefix}  Target: {_safe_url(finding.target)}",
        f"{prefix}  Issue: {_console_value(finding.message)}",
        f"{prefix}  Fix: {_console_value(finding.remediation)}",
    ]
    evidence = _safe_evidence(finding.evidence)
    if evidence:
        lines.append(f"{prefix}  Evidence: {_console_value(evidence, limit=240)}")
    return lines


def _render_scan(report: ScanReport) -> str:
    lines = [
        f"PreviewShield scan: {_status(report.passed)}",
        f"Target: {_safe_url(report.target)}",
        f"Policy: {_console_value(report.policy_name)}",
        f"Score: {report.score}/100  Grade: {_console_value(report.grade, limit=20)}",
        f"Failure threshold: {report.fail_on.value}",
        f"Findings: {_counts_line(report)}",
    ]
    findings = _sorted_findings(report.findings)
    if not findings:
        lines.extend(("", "No security findings."))
    else:
        lines.extend(("", f"Security findings ({len(findings)}):"))
        for finding in findings:
            lines.extend(_finding_lines(finding, prefix="  "))
    return "\n".join(lines) + "\n"


def _render_diff(report: DiffReport) -> str:
    changed = sum(delta.kind.value == "changed" for delta in report.deltas)
    lines = [
        f"PreviewShield diff: {_status(report.passed)}",
        f"Baseline: {_safe_url(report.baseline.target)} "
        f"({_console_value(report.baseline.grade, limit=20)}, {report.baseline.score}/100)",
        f"Preview: {_safe_url(report.preview.target)} "
        f"({_console_value(report.preview.grade, limit=20)}, {report.preview.score}/100)",
        f"Policy: {_console_value(report.policy_name)}",
        f"Failure threshold: {report.fail_on.value}",
        f"Changes: {len(report.regressions)} regressions, {len(report.resolved)} resolved, "
        f"{changed} changed, {len(report.unchanged)} unchanged",
    ]
    deltas = _sorted_deltas(report.deltas)
    visible = tuple(delta for delta in deltas if delta.kind.value != "unchanged")
    if not visible:
        lines.extend(("", "No security changes."))
    else:
        current_kind = ""
        for delta in visible:
            kind = delta.kind.value
            if kind != current_kind:
                lines.extend(
                    ("", f"{kind.upper()} ({sum(item.kind is delta.kind for item in visible)}):")
                )
                current_kind = kind
            lines.extend(_finding_lines(delta.finding, prefix="  "))
    return "\n".join(lines) + "\n"


def render_console(report: Report) -> str:
    """Render a report without terminal control sequences or ANSI styling."""

    if isinstance(report, ScanReport):
        return _render_scan(report)
    return _render_diff(report)


render = render_console

__all__ = ["render", "render_console"]
