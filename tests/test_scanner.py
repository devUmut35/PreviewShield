from __future__ import annotations

from collections.abc import Mapping

import pytest

import previewshield.scanner as scanner_module
from previewshield.exceptions import ConfigurationError
from previewshield.models import Finding, ResponseSnapshot, Severity
from previewshield.network import NetworkOptions
from previewshield.policy import default_policy, policy_from_mapping


def response(url: str) -> ResponseSnapshot:
    return ResponseSnapshot(
        requested_url=url,
        final_url=url,
        status_code=200,
        reason="OK",
        headers={},
        resolved_ip="203.0.113.10",
        elapsed_ms=4,
    )


def high_finding(url: str) -> Finding:
    return Finding(
        rule_id="PS9999",
        title="Test finding",
        severity=Severity.HIGH,
        category="test",
        message="A test observation.",
        remediation="Fix it.",
        target=url,
    )


def test_scan_preserves_an_explicit_target_path(monkeypatch: pytest.MonkeyPatch) -> None:
    requested: list[str] = []

    def fake_fetch(
        url: str,
        options: NetworkOptions,
        request_headers: Mapping[str, str] | None = None,
    ) -> ResponseSnapshot:
        requested.append(url)
        assert options.allow_private is False
        assert request_headers == {"X-Test": "safe"}
        return response(url)

    monkeypatch.setattr(scanner_module, "fetch", fake_fetch)
    monkeypatch.setattr(scanner_module, "evaluate", lambda _response, _policy: ())

    report = scanner_module.scan(
        "https://Preview.Example.dev/app?mode=test",
        request_headers={"X-Test": "safe"},
    )

    assert requested == ["https://preview.example.dev/app?mode=test"]
    assert report.target == "https://preview.example.dev/app?mode=test"
    assert report.score == 100
    assert report.grade == "A+"
    assert report.passed is True


def test_multi_route_score_and_threshold(monkeypatch: pytest.MonkeyPatch) -> None:
    requested: list[str] = []

    def fake_fetch(
        url: str,
        _options: NetworkOptions,
        request_headers: Mapping[str, str] | None = None,
    ) -> ResponseSnapshot:
        assert request_headers is None
        requested.append(url)
        return response(url)

    def fake_evaluate(item: ResponseSnapshot, _policy: object) -> tuple[Finding, ...]:
        return (high_finding(item.final_url),) if item.final_url.endswith("/admin") else ()

    monkeypatch.setattr(scanner_module, "fetch", fake_fetch)
    monkeypatch.setattr(scanner_module, "evaluate", fake_evaluate)

    report = scanner_module.scan(
        "example.com/base",
        paths=("/", "/admin", "/admin"),
        fail_on=Severity.HIGH,
    )

    assert requested == ["https://example.com/", "https://example.com/admin"]
    assert report.score == 92
    assert report.grade == "A"
    assert report.passed is False

    tolerant = scanner_module.scan(
        "example.com",
        paths=("/admin",),
        fail_on=Severity.CRITICAL,
    )
    assert tolerant.passed is True


def test_network_policy_and_private_override_are_forwarded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[NetworkOptions] = []
    policy = policy_from_mapping(
        {
            "version": 1,
            "network": {
                "timeout_seconds": 3.5,
                "max_redirects": 2,
                "allow_private": False,
                "allowed_hosts": ["localhost"],
                "user_agent": "Scanner test",
            },
        }
    )

    def fake_fetch(
        url: str,
        options: NetworkOptions,
        request_headers: Mapping[str, str] | None = None,
    ) -> ResponseSnapshot:
        assert request_headers is None
        observed.append(options)
        return response(url)

    monkeypatch.setattr(scanner_module, "fetch", fake_fetch)
    monkeypatch.setattr(scanner_module, "evaluate", lambda _response, _policy: ())

    scanner_module.scan("localhost", policy=policy, allow_private=True)

    assert observed == [
        NetworkOptions(
            timeout=3.5,
            max_redirects=2,
            allow_private=True,
            user_agent="Scanner test",
            allowed_hosts=("localhost",),
        )
    ]


def test_allowed_host_policy_blocks_before_network(monkeypatch: pytest.MonkeyPatch) -> None:
    policy = policy_from_mapping({"version": 1, "network": {"allowed_hosts": ["*.example.com"]}})
    called = False

    def fake_fetch(
        url: str,
        options: NetworkOptions,
        request_headers: Mapping[str, str] | None = None,
    ) -> ResponseSnapshot:
        del url, options, request_headers
        nonlocal called
        called = True
        return response("https://unexpected.invalid/")

    monkeypatch.setattr(scanner_module, "fetch", fake_fetch)

    with pytest.raises(ConfigurationError, match="allowed_hosts"):
        scanner_module.scan("https://example.net", policy=policy)
    assert called is False


@pytest.mark.parametrize(
    "target",
    [
        "ftp://example.com",
        "https://user:secret@example.com",
        "https://example.com/#fragment",
        "not a valid host",
    ],
)
def test_invalid_targets_are_rejected(target: str) -> None:
    with pytest.raises(ConfigurationError):
        scanner_module.scan(target, policy=default_policy())


@pytest.mark.parametrize("path", ["https://evil.example/", "/../admin", "/ok#fragment"])
def test_unsafe_paths_are_rejected(path: str) -> None:
    with pytest.raises(ConfigurationError):
        scanner_module.scan("example.com", paths=(path,))
