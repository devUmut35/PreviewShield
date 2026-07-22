from __future__ import annotations

from typing import Any

import pytest

from previewshield import diffing
from previewshield.models import (
    DeltaKind,
    Finding,
    ResponseSnapshot,
    RouteReport,
    ScanReport,
    Severity,
)
from previewshield.policy import default_policy, policy_from_mapping


def finding(
    rule_id: str,
    host: str,
    path: str,
    severity: Severity,
    *,
    message: str = "Observation",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=f"Finding {rule_id}",
        severity=severity,
        category="test",
        message=message,
        remediation="Fix it.",
        target=f"https://{host}{path}",
        subject="response",
    )


def report(host: str, findings: tuple[Finding, ...], *, passed: bool = True) -> ScanReport:
    url = f"https://{host}/"
    snapshot = ResponseSnapshot(
        requested_url=url,
        final_url=url,
        status_code=200,
        reason="OK",
        headers={},
        resolved_ip="203.0.113.10",
        elapsed_ms=1,
    )
    return ScanReport(
        schema_version="1.0",
        tool_version="1.0.0",
        generated_at="2026-01-01T00:00:00Z",
        policy_name="test",
        target=url,
        routes=(RouteReport(snapshot=snapshot, findings=findings),),
        score=100,
        grade="A+",
        fail_on=Severity.HIGH,
        passed=passed,
    )


def test_compare_classifies_every_delta_kind_across_different_hosts() -> None:
    baseline = report(
        "prod.example",
        (
            finding("PS9001", "prod.example", "/same", Severity.HIGH),
            finding("PS9002", "prod.example", "/resolved", Severity.HIGH),
            finding("PS9003", "prod.example", "/changed", Severity.LOW),
            finding("PS9004", "prod.example", "/worse", Severity.LOW),
        ),
    )
    preview = report(
        "preview.example",
        (
            finding("PS9001", "preview.example", "/same", Severity.HIGH),
            finding(
                "PS9003",
                "preview.example",
                "/changed",
                Severity.LOW,
                message="Changed evidence",
            ),
            finding("PS9004", "preview.example", "/worse", Severity.HIGH),
            finding("PS9005", "preview.example", "/new", Severity.HIGH),
        ),
    )

    result = diffing.compare(baseline, preview, policy=default_policy())
    by_rule = {delta.finding.rule_id: delta.kind for delta in result.deltas}

    assert by_rule == {
        "PS9001": DeltaKind.UNCHANGED,
        "PS9002": DeltaKind.RESOLVED,
        "PS9003": DeltaKind.CHANGED,
        "PS9004": DeltaKind.REGRESSION,
        "PS9005": DeltaKind.REGRESSION,
    }
    assert result.passed is False


def test_regression_mode_ignores_preexisting_findings() -> None:
    baseline_finding = finding("PS9001", "prod.example", "/", Severity.CRITICAL)
    preview_finding = finding("PS9001", "preview.example", "/", Severity.CRITICAL)

    result = diffing.compare(
        report("prod.example", (baseline_finding,), passed=False),
        report("preview.example", (preview_finding,), passed=False),
        policy=default_policy(),
    )

    assert result.unchanged
    assert result.regressions == ()
    assert result.passed is True


def test_absolute_mode_fails_on_preexisting_preview_finding() -> None:
    policy = policy_from_mapping({"version": 1, "diff": {"mode": "absolute"}})
    baseline_finding = finding("PS9001", "prod.example", "/", Severity.HIGH)
    preview_finding = finding("PS9001", "preview.example", "/", Severity.HIGH)

    result = diffing.compare(
        report("prod.example", (baseline_finding,)),
        report("preview.example", (preview_finding,)),
        policy=policy,
        fail_on=Severity.HIGH,
    )

    assert result.passed is False


def test_lowered_severity_is_changed_not_regression() -> None:
    result = diffing.compare(
        report(
            "prod.example",
            (finding("PS9001", "prod.example", "/", Severity.HIGH),),
        ),
        report(
            "preview.example",
            (finding("PS9001", "preview.example", "/", Severity.LOW),),
        ),
        policy=default_policy(),
    )

    assert result.deltas[0].kind is DeltaKind.CHANGED
    assert result.passed is True


def test_duplicate_fingerprint_uses_highest_severity() -> None:
    duplicate_low = finding("PS9001", "prod.example", "/", Severity.LOW)
    duplicate_high = finding("PS9001", "prod.example", "/", Severity.HIGH)
    preview_high = finding("PS9001", "preview.example", "/", Severity.HIGH)

    result = diffing.compare(
        report("prod.example", (duplicate_low, duplicate_high)),
        report("preview.example", (preview_high,)),
    )

    assert result.deltas[0].kind is DeltaKind.UNCHANGED


def test_diff_targets_scans_both_sides_with_the_same_options(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict[str, Any]]] = []
    baseline = report("prod.example", ())
    preview = report("preview.example", ())

    def fake_scan(target: str, **kwargs: Any) -> ScanReport:
        calls.append((target, kwargs))
        return baseline if target == "prod.example" else preview

    monkeypatch.setattr(diffing, "scan", fake_scan)
    policy = default_policy()

    result = diffing.diff_targets(
        "prod.example",
        "preview.example",
        policy=policy,
        paths=("/", "/health"),
        request_headers={"X-Test": "safe"},
        fail_on=Severity.MEDIUM,
        allow_private=True,
    )

    assert result.passed is True
    assert [target for target, _kwargs in calls] == ["prod.example", "preview.example"]
    assert calls[0][1] == calls[1][1]
