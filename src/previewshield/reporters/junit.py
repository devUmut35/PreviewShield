"""JUnit XML output for CI test-report integrations."""

from __future__ import annotations

# ElementTree is used only for XML generation, never for parsing input.
import xml.etree.ElementTree as ET  # nosec B405
from typing import TypeAlias

from previewshield.models import Finding, ScanReport
from previewshield.reporters import (
    Report,
    _safe_evidence,
    _safe_text,
    _safe_url,
    _sorted_deltas,
    _sorted_findings,
)

Case: TypeAlias = tuple[str, Finding | None, bool, str]
_XML_LOW_START = 0x20
_XML_LOW_END = 0xD7FF
_XML_MIDDLE_START = 0xE000
_XML_MIDDLE_END = 0xFFFD
_XML_HIGH_START = 0x10000
_XML_HIGH_END = 0x10FFFF


def _xml_text(value: str, *, limit: int = 2_000) -> str:
    safe = _safe_text(value, limit=limit)
    return "".join(
        character
        for character in safe
        if character in "\t\n\r"
        or _XML_LOW_START <= ord(character) <= _XML_LOW_END
        or _XML_MIDDLE_START <= ord(character) <= _XML_MIDDLE_END
        or _XML_HIGH_START <= ord(character) <= _XML_HIGH_END
    )


def _cases(report: Report) -> tuple[Case, ...]:
    if isinstance(report, ScanReport):
        findings = _sorted_findings(report.findings)
        if not findings:
            return (("scan completed without findings", None, False, "clean"),)
        return tuple(
            (
                f"{_safe_text(finding.rule_id, limit=100)} at {_safe_url(finding.target)}",
                finding,
                finding.severity.rank >= report.fail_on.rank,
                "finding",
            )
            for finding in findings
        )

    visible = tuple(
        delta for delta in _sorted_deltas(report.deltas) if delta.kind.value != "unchanged"
    )
    if not visible:
        return (("diff completed without security changes", None, False, "clean"),)
    return tuple(
        (
            f"{_safe_text(delta.finding.rule_id, limit=100)} at {_safe_url(delta.finding.target)}",
            delta.finding,
            delta.kind.value == "regression" and delta.finding.severity.rank >= report.fail_on.rank,
            delta.kind.value,
        )
        for delta in visible
    )


def _details(finding: Finding, status: str) -> str:
    lines = [
        f"Status: {status}",
        f"Severity: {finding.severity.value}",
        f"Target: {_safe_url(finding.target)}",
        f"Issue: {_safe_text(finding.message)}",
        f"Remediation: {_safe_text(finding.remediation)}",
    ]
    evidence = _safe_evidence(finding.evidence)
    if evidence:
        lines.append(f"Evidence: {evidence}")
    return _xml_text("\n".join(lines), limit=4_000)


def _add_properties(suite: ET.Element, report: Report) -> None:
    properties = ET.SubElement(suite, "properties")
    target = report.target if isinstance(report, ScanReport) else report.preview.target
    values = {
        "previewshield.kind": "scan" if isinstance(report, ScanReport) else "diff",
        "previewshield.passed": str(report.passed).lower(),
        "previewshield.policy": _safe_text(report.policy_name, limit=200),
        "previewshield.target": _safe_url(target),
        "previewshield.version": _safe_text(report.tool_version, limit=100),
    }
    for name in sorted(values):
        ET.SubElement(
            properties,
            "property",
            {"name": name, "value": _xml_text(values[name])},
        )


def render_junit(report: Report) -> str:
    """Render deterministic JUnit XML with threshold-crossing findings as failures."""

    cases = _cases(report)
    failures = sum(case[2] for case in cases)
    suite = ET.Element(
        "testsuite",
        {
            "name": "PreviewShield",
            "tests": str(len(cases)),
            "failures": str(failures),
            "errors": "0",
            "skipped": "0",
            "time": "0",
            "timestamp": _xml_text(report.generated_at, limit=100),
        },
    )
    _add_properties(suite, report)
    for name, finding, failed, status in cases:
        case = ET.SubElement(
            suite,
            "testcase",
            {
                "name": _xml_text(name, limit=500),
                "classname": "previewshield.security",
                "time": "0",
            },
        )
        if finding is None:
            continue
        details = _details(finding, status)
        if failed:
            failure = ET.SubElement(
                case,
                "failure",
                {
                    "message": _xml_text(finding.title, limit=500),
                    "type": "PreviewShieldSecurityFinding",
                },
            )
            failure.text = details
        else:
            system_out = ET.SubElement(case, "system-out")
            system_out.text = details

    ET.indent(suite, space="  ")
    document = ET.tostring(suite, encoding="unicode", xml_declaration=True)
    return f"{document}\n"


render = render_junit

__all__ = ["render", "render_junit"]
