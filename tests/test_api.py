from __future__ import annotations

from typing import Any

import pytest

from previewshield import api
from previewshield.models import DiffReport, ResponseSnapshot, RouteReport, ScanReport, Severity


def scan_report() -> ScanReport:
    url = "https://example.com/"
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
        routes=(RouteReport(snapshot=snapshot),),
        score=100,
        grade="A+",
        fail_on=Severity.HIGH,
        passed=True,
    )


def test_scan_wrapper_forwards_keyword_options(monkeypatch: pytest.MonkeyPatch) -> None:
    expected = scan_report()
    observed: dict[str, Any] = {}

    def fake_scan(target: str, **kwargs: Any) -> ScanReport:
        observed["target"] = target
        observed.update(kwargs)
        return expected

    monkeypatch.setattr(api, "scan_target", fake_scan)

    assert api.scan("example.com", paths=("/health",), allow_private=True) is expected
    assert observed["target"] == "example.com"
    assert observed["paths"] == ("/health",)
    assert observed["allow_private"] is True


def test_diff_wrapper_forwards_both_targets(monkeypatch: pytest.MonkeyPatch) -> None:
    scan = scan_report()
    expected = DiffReport(
        schema_version="1.0",
        tool_version="1.0.0",
        generated_at="2026-01-01T00:00:00Z",
        policy_name="test",
        baseline=scan,
        preview=scan,
        deltas=(),
        fail_on=Severity.HIGH,
        passed=True,
    )
    observed: dict[str, Any] = {}

    def fake_diff(baseline: str, preview: str, **kwargs: Any) -> DiffReport:
        observed.update(baseline=baseline, preview=preview, **kwargs)
        return expected

    monkeypatch.setattr(api, "diff_targets", fake_diff)

    assert api.diff("prod.example", "preview.example", fail_on=Severity.MEDIUM) is expected
    assert observed["baseline"] == "prod.example"
    assert observed["preview"] == "preview.example"
    assert observed["fail_on"] is Severity.MEDIUM
