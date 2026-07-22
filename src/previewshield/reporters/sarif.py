"""SARIF 2.1.0 output for GitHub code scanning."""

from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

from previewshield.models import Finding, ScanReport, Severity
from previewshield.reporters import (
    Report,
    _safe_evidence,
    _safe_text,
    _safe_url,
    _sorted_findings,
    _stable_fingerprint,
)

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_INFORMATION_URI = "https://github.com/devUmut35/PreviewShield"
_GLOBAL_LOCATION = ".previewshield.yml"
_RULE_ID_CHARACTER = re.compile(r"[^A-Za-z0-9._-]+")


def _level(severity: Severity) -> str:
    if severity in {Severity.CRITICAL, Severity.HIGH}:
        return "error"
    if severity is Severity.MEDIUM:
        return "warning"
    return "note"


def _security_severity(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "9.5",
        Severity.HIGH: "8.0",
        Severity.MEDIUM: "5.5",
        Severity.LOW: "3.0",
        Severity.INFO: "0.0",
    }[severity]


def _rule_id(finding: Finding) -> str:
    safe = _RULE_ID_CHARACTER.sub("-", _safe_text(finding.rule_id, limit=200)).strip("-")
    return safe or f"previewshield-{_stable_fingerprint(finding)}"


def _help_uri(finding: Finding) -> str | None:
    for reference in finding.references:
        safe = _safe_url(reference)
        if urlsplit(safe).scheme in {"http", "https"}:
            return safe
    return None


def _rule(finding: Finding) -> dict[str, object]:
    rule: dict[str, object] = {
        "id": _rule_id(finding),
        "name": _rule_id(finding),
        "shortDescription": {"text": _safe_text(finding.title, limit=500)},
        "fullDescription": {"text": _safe_text(finding.message)},
        "help": {"text": _safe_text(finding.remediation)},
        "properties": {
            "precision": "high",
            "problem.severity": finding.severity.value,
            "security-severity": _security_severity(finding.severity),
            "tags": ["security", _safe_text(finding.category, limit=100)],
        },
    }
    help_uri = _help_uri(finding)
    if help_uri is not None:
        rule["helpUri"] = help_uri
    return rule


def _result(
    finding: Finding,
    *,
    rule_index: int,
    baseline_state: str | None = None,
) -> dict[str, object]:
    fingerprint = _stable_fingerprint(finding)
    properties: dict[str, object] = {
        "category": _safe_text(finding.category, limit=100),
        "severity": finding.severity.value,
        "subject": _safe_text(finding.subject, limit=200),
        "target": _safe_url(finding.target),
        "remediation": _safe_text(finding.remediation),
    }
    evidence = _safe_evidence(finding.evidence)
    if evidence:
        properties["evidence"] = evidence
    result: dict[str, object] = {
        "ruleId": _rule_id(finding),
        "ruleIndex": rule_index,
        "level": _level(finding.severity),
        "kind": "fail",
        "message": {
            "text": f"{_safe_text(finding.title, limit=500)}: {_safe_text(finding.message)}"
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": _GLOBAL_LOCATION},
                    "region": {"startLine": 1},
                },
                "logicalLocations": [
                    {
                        "fullyQualifiedName": _safe_url(finding.target),
                        "kind": "webTarget",
                    }
                ],
            }
        ],
        "fingerprints": {"previewshield/v1": fingerprint},
        "partialFingerprints": {
            "primaryLocationLineHash": fingerprint,
            "previewshieldFingerprint/v1": fingerprint,
        },
        "properties": properties,
    }
    if baseline_state is not None:
        result["baselineState"] = baseline_state
        properties["deltaKind"] = "regression"
    return result


def _selected_findings(report: Report) -> tuple[tuple[Finding, str | None], ...]:
    if isinstance(report, ScanReport):
        return tuple((finding, None) for finding in _sorted_findings(report.findings))
    regressions = sorted(
        report.regressions,
        key=lambda delta: (
            -delta.finding.severity.rank,
            delta.finding.rule_id.casefold(),
            delta.finding.target.casefold(),
            delta.finding.fingerprint,
        ),
    )
    return tuple(
        (delta.finding, "new" if delta.baseline is None else "updated") for delta in regressions
    )


def render_sarif(report: Report) -> str:
    """Render SARIF with repository-level results and stable GitHub fingerprints.

    Diff reports intentionally contain only regressions, making an uploaded SARIF
    run actionable and preventing resolved or unchanged observations from appearing
    as current alerts. Web findings use the policy file as a stable repository-level
    anchor because GitHub code scanning requires a physical location for every alert.
    """

    selected = _selected_findings(report)
    representative: dict[str, Finding] = {}
    for finding, _baseline_state in selected:
        representative.setdefault(_rule_id(finding), finding)
    rule_ids = sorted(representative)
    rule_indexes = {rule_id: index for index, rule_id in enumerate(rule_ids)}
    rules = [_rule(representative[rule_id]) for rule_id in rule_ids]
    results = [
        _result(
            finding,
            rule_index=rule_indexes[_rule_id(finding)],
            baseline_state=baseline_state,
        )
        for finding, baseline_state in selected
    ]
    target = report.target if isinstance(report, ScanReport) else report.preview.target
    payload: dict[str, object] = {
        "$schema": _SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PreviewShield",
                        "semanticVersion": _safe_text(report.tool_version, limit=100),
                        "informationUri": _INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "exitCode": 0 if report.passed else 1,
                    }
                ],
                "results": results,
                "properties": {
                    "policy": _safe_text(report.policy_name, limit=200),
                    "reportKind": "scan" if isinstance(report, ScanReport) else "diff",
                    "target": _safe_url(target),
                },
            }
        ],
    }
    return f"{json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)}\n"


render = render_sarif

__all__ = ["render", "render_sarif"]
