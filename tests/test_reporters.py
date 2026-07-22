from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import replace

import pytest

from previewshield.models import (
    DeltaKind,
    DiffReport,
    Finding,
    FindingDelta,
    ResponseSnapshot,
    RouteReport,
    ScanReport,
    Severity,
)
from previewshield.reporters import render, supported_formats

_SENTINEL = "request-secret-4f7c9e"
_TARGET = f"https://user:password@preview.example.test/account?token={_SENTINEL}#private"


def _finding(
    *,
    rule_id: str = "PS-HEADER-001",
    severity: Severity = Severity.HIGH,
    target: str = _TARGET,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="Missing <script>alert('x')</script> | CSP",
        severity=severity,
        category="headers",
        message=f"The value token={_SENTINEL} is unsafe; `do not render this`.",
        remediation="Set Content-Security-Policy to default-src 'self'.",
        target=target,
        subject="content-security-policy",
        evidence="X-Evidence: " + ("e" * 600) + "\x1b[31m",
        references=(f"https://docs.example.test/csp?api_key={_SENTINEL}#details",),
    )


def _scan(
    *,
    target: str = _TARGET,
    findings: tuple[Finding, ...] | None = None,
    passed: bool = False,
    score: int = 72,
    grade: str = "C",
) -> ScanReport:
    active_findings = (_finding(target=target),) if findings is None else findings
    snapshot = ResponseSnapshot(
        requested_url=target,
        final_url=target,
        status_code=200,
        reason="OK <network>",
        headers={
            "content-security-policy": ("default-src 'none'",),
            "set-cookie": (f"session={_SENTINEL}; Secure; HttpOnly",),
            "x-debug-token": (_SENTINEL,),
        },
        resolved_ip="203.0.113.10",
        elapsed_ms=42,
    )
    return ScanReport(
        schema_version="1.0",
        tool_version="1.2.3",
        generated_at="2026-07-22T10:00:00Z",
        policy_name="default <policy>",
        target=target,
        routes=(RouteReport(snapshot=snapshot, findings=active_findings),),
        score=score,
        grade=grade,
        fail_on=Severity.MEDIUM,
        passed=passed,
    )


def _diff() -> DiffReport:
    regression = _finding()
    resolved = replace(
        _finding(rule_id="PS-TLS-002", severity=Severity.MEDIUM),
        title="Legacy TLS",
        message="TLS 1.0 was accepted.",
        evidence="TLSv1",
        subject="tls",
    )
    unchanged = replace(
        _finding(rule_id="PS-INFO-003", severity=Severity.LOW),
        title="Informational header",
        message="A server header is visible.",
        evidence="server: example",
        subject="server",
    )
    baseline = _scan(
        target="https://production.example.test/",
        findings=(resolved, unchanged),
        passed=False,
        score=78,
        grade="C+",
    )
    preview = _scan(findings=(regression, unchanged), score=70, grade="C-")
    return DiffReport(
        schema_version="1.0",
        tool_version="1.2.3",
        generated_at="2026-07-22T10:01:00Z",
        policy_name="default <policy>",
        baseline=baseline,
        preview=preview,
        deltas=(
            FindingDelta(
                kind=DeltaKind.UNCHANGED,
                fingerprint=unchanged.fingerprint,
                baseline=unchanged,
                preview=unchanged,
            ),
            FindingDelta(
                kind=DeltaKind.RESOLVED,
                fingerprint=resolved.fingerprint,
                baseline=resolved,
            ),
            FindingDelta(
                kind=DeltaKind.REGRESSION,
                fingerprint=regression.fingerprint,
                preview=regression,
            ),
        ),
        fail_on=Severity.MEDIUM,
        passed=False,
    )


def test_registry_supports_every_format_for_scan_and_diff() -> None:
    assert supported_formats() == ("console", "html", "json", "junit", "markdown", "sarif")

    for report in (_scan(), _diff()):
        for format_name in supported_formats():
            first = render(report, format_name)
            assert first
            assert first.endswith("\n")
            assert first == render(report, format_name)

    assert render(_scan(), "MD") == render(_scan(), "markdown")
    assert render(_scan(), ".json") == render(_scan(), "json")
    assert render(_scan(), "xml") == render(_scan(), "junit")
    with pytest.raises(ValueError, match="Unsupported report format"):
        render(_scan(), "pdf")


def test_all_formats_remove_request_secrets_and_cap_evidence() -> None:
    long_fragment = "e" * 300
    for report in (_scan(), _diff()):
        for format_name in supported_formats():
            output = render(report, format_name)
            assert _SENTINEL not in output
            assert "user:password" not in output
            assert "?token=" not in output
            assert "?api_key=" not in output
            assert "\x1b" not in output
            assert long_fragment not in output


def test_json_is_pretty_schema_shaped_and_redacts_sensitive_headers() -> None:
    output = render(_scan(), "json")
    payload = json.loads(output)

    assert output.startswith("{\n  ")
    assert payload["schema_version"] == "1.0"
    assert payload["target"] == "https://preview.example.test/account"
    snapshot = payload["routes"][0]["snapshot"]
    assert snapshot["requested_url"] == "https://preview.example.test/account"
    assert snapshot["headers"]["set-cookie"] == ["[REDACTED]"]
    assert snapshot["headers"]["x-debug-token"] == ["[REDACTED]"]
    assert snapshot["headers"]["content-security-policy"] == ["default-src 'none'"]
    assert len(payload["routes"][0]["findings"][0]["evidence"]) <= 240


def test_markdown_is_github_table_safe_and_diff_is_concise() -> None:
    output = render(_diff(), "markdown")

    assert output.startswith("## PreviewShield security diff")
    assert "### Regressions (1)" in output
    assert "### Resolved (1)" in output
    assert "UNCHANGED" not in output
    assert "&#124;" in output
    assert "`PS-HEADER-001`" in output


def test_console_is_plain_and_orders_regressions_before_resolved() -> None:
    output = render(_diff(), "console")

    assert output.startswith("PreviewShield diff: FAIL")
    assert "\x1b[" not in output
    assert output.index("REGRESSION (1):") < output.index("RESOLVED (1):")
    assert "Target: https://preview.example.test/account" in output


def test_sarif_is_github_compatible_and_diff_contains_only_regressions() -> None:
    payload = json.loads(render(_diff(), "sarif"))
    run = payload["runs"][0]

    assert payload["version"] == "2.1.0"
    assert payload["$schema"].endswith("sarif-2.1.0.json")
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert len(run["results"]) == 1
    result = run["results"][0]
    assert result["ruleId"] == "PS-HEADER-001"
    assert result["baselineState"] == "new"
    assert result["level"] == "error"
    location = result["locations"][0]
    assert location["physicalLocation"]["artifactLocation"]["uri"] == ".previewshield.yml"
    assert location["physicalLocation"]["region"]["startLine"] == 1
    assert location["logicalLocations"][0]["kind"] == "webTarget"
    fingerprint = result["partialFingerprints"]["previewshieldFingerprint/v1"]
    assert re.fullmatch(r"[a-f0-9]{24}", fingerprint)
    assert result["partialFingerprints"]["primaryLocationLineHash"] == fingerprint


def test_junit_is_valid_xml_and_escapes_network_markup() -> None:
    output = render(_diff(), "junit")
    root = ET.fromstring(output)  # noqa: S314 - parses only locally generated XML

    assert root.tag == "testsuite"
    assert root.attrib["tests"] == "2"
    assert root.attrib["failures"] == "1"
    assert len(root.findall("testcase")) == 2
    assert len(root.findall("testcase/failure")) == 1
    assert "<script>" not in output
    assert "&lt;script&gt;" in output


def test_html_is_self_contained_and_escapes_untrusted_markup() -> None:
    output = render(_scan(), "html")

    assert output.startswith("<!doctype html>")
    assert "Content-Security-Policy" in output
    assert output.count("<style>") == 1
    assert "<script>" not in output
    assert "&lt;script&gt;" in output
    assert 'src="http' not in output
    assert 'href="http' not in output
