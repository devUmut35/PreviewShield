from __future__ import annotations

import pytest

from previewshield.checks import evaluate
from previewshield.models import RedirectHop, ResponseSnapshot, Severity, TLSInfo
from previewshield.policy import default_policy, policy_from_mapping


def snapshot(  # noqa: PLR0913 - compact fixture factory for rule combinations
    *,
    requested_url: str = "https://example.com/",
    final_url: str = "https://example.com/",
    status_code: int = 200,
    headers: dict[str, tuple[str, ...]] | None = None,
    redirects: tuple[RedirectHop, ...] = (),
    tls: TLSInfo | None = None,
) -> ResponseSnapshot:
    return ResponseSnapshot(
        requested_url=requested_url,
        final_url=final_url,
        status_code=status_code,
        reason="OK",
        headers=headers or {},
        resolved_ip="203.0.113.10",
        elapsed_ms=12,
        redirects=redirects,
        tls=tls,
    )


def secure_headers() -> dict[str, tuple[str, ...]]:
    return {
        "strict-transport-security": ("max-age=31536000; includeSubDomains",),
        "content-security-policy": (
            "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        ),
        "x-content-type-options": ("nosniff",),
        "referrer-policy": ("strict-origin-when-cross-origin",),
        "permissions-policy": ("camera=(), microphone=()",),
    }


def finding_ids(response: ResponseSnapshot) -> set[str]:
    return {finding.rule_id for finding in evaluate(response, default_policy())}


def test_hardened_response_has_no_findings() -> None:
    response = snapshot(
        headers=secure_headers(),
        tls=TLSInfo(
            version="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            certificate_days_remaining=90,
        ),
    )

    assert evaluate(response, default_policy()) == ()


def test_missing_basics_and_plaintext_are_detected() -> None:
    response = snapshot(
        requested_url="http://example.com/",
        final_url="http://example.com/",
    )

    assert {
        "PS0001",
        "PS1101",
        "PS1201",
        "PS1202",
        "PS1203",
        "PS1204",
    } <= finding_ids(response)
    assert "PS1001" not in finding_ids(response)


def test_hsts_and_csp_weaknesses_are_detected() -> None:
    response = snapshot(
        headers={
            "strict-transport-security": ("max-age=60",),
            "content-security-policy": (
                "script-src * 'unsafe-inline' 'unsafe-eval'; object-src https:;",
            ),
            "x-content-type-options": ("nosniff",),
            "referrer-policy": ("unsafe-url",),
            "permissions-policy": ("camera=()",),
            "x-frame-options": ("SAMEORIGIN",),
        }
    )

    ids = finding_ids(response)
    assert {"PS1002", "PS1102", "PS1103", "PS1104", "PS1105", "PS1106", "PS1107"} <= ids
    referrer = next(
        item for item in evaluate(response, default_policy()) if item.rule_id == "PS1203"
    )
    assert referrer.severity is Severity.MEDIUM


def test_disabled_or_invalid_hsts_is_high_severity() -> None:
    for value in ("max-age=0", "includeSubDomains"):
        headers = secure_headers()
        headers["strict-transport-security"] = (value,)
        finding = next(
            item
            for item in evaluate(snapshot(headers=headers), default_policy())
            if item.rule_id == "PS1002"
        )
        assert finding.severity is Severity.HIGH


@pytest.mark.parametrize(
    "values",
    [
        ("max-age=0", "max-age=31536000"),
        ("max-age=31536000; max-age=0",),
    ],
)
def test_hsts_uses_first_field_and_rejects_duplicate_directives(
    values: tuple[str, ...],
) -> None:
    headers = secure_headers()
    headers["strict-transport-security"] = values

    finding = next(
        item
        for item in evaluate(snapshot(headers=headers), default_policy())
        if item.rule_id == "PS1002"
    )
    assert finding.severity is Severity.HIGH


@pytest.mark.parametrize("value", ['max-age="31536000"', "max-age=" + "9" * 5000])
def test_hsts_accepts_quoted_and_very_large_valid_ages(value: str) -> None:
    headers = secure_headers()
    headers["strict-transport-security"] = (value,)

    assert "PS1002" not in finding_ids(snapshot(headers=headers))


@pytest.mark.parametrize(
    "script_sources",
    [
        "script-src 'unsafe-inline'; script-src 'nonce-valid'",
        "script-src 'unsafe-inline' 'nonce-'",
    ],
)
def test_duplicate_directives_and_malformed_nonces_do_not_hide_unsafe_inline(
    script_sources: str,
) -> None:
    headers = secure_headers()
    headers["content-security-policy"] = (
        f"default-src 'self'; object-src 'none'; base-uri 'none'; "
        f"frame-ancestors 'none'; {script_sources}",
    )

    assert "PS1103" in finding_ids(snapshot(headers=headers))


def test_valid_nonce_suppresses_unsafe_inline_observation() -> None:
    headers = secure_headers()
    headers["content-security-policy"] = (
        "default-src 'self'; object-src 'none'; base-uri 'none'; "
        "frame-ancestors 'none'; script-src 'unsafe-inline' 'nonce-YWJjZA=='",
    )

    assert "PS1103" not in finding_ids(snapshot(headers=headers))


def test_report_only_csp_is_not_treated_as_enforcement() -> None:
    response = snapshot(headers={"content-security-policy-report-only": ("default-src 'none'",)})

    finding = next(
        item for item in evaluate(response, default_policy()) if item.rule_id == "PS1101"
    )
    assert finding.evidence == "report-only policy detected"


@pytest.mark.parametrize("value", ["", "garbage"])
def test_empty_or_ineffective_csp_is_treated_as_missing(value: str) -> None:
    headers = secure_headers()
    headers["content-security-policy"] = (value,)

    finding = next(
        item
        for item in evaluate(snapshot(headers=headers), default_policy())
        if item.rule_id == "PS1101"
    )
    assert finding.severity is Severity.HIGH


def test_non_document_response_skips_document_only_headers() -> None:
    response = snapshot(
        headers={
            "content-type": ("application/json; charset=utf-8",),
            "strict-transport-security": ("max-age=31536000",),
        }
    )

    ids = finding_ids(response)
    assert "PS1202" in ids
    assert {"PS1101", "PS1201", "PS1203", "PS1204"}.isdisjoint(ids)


@pytest.mark.parametrize("status_code", [204, 205, 304])
def test_no_content_response_skips_representation_headers(status_code: int) -> None:
    response = snapshot(
        status_code=status_code,
        headers={"strict-transport-security": ("max-age=31536000",)},
    )

    ids = finding_ids(response)
    assert {"PS1101", "PS1201", "PS1202", "PS1203", "PS1204"}.isdisjoint(ids)


def test_hsts_is_not_required_for_ip_literal_hosts() -> None:
    response = snapshot(
        requested_url="https://127.0.0.1/",
        final_url="https://127.0.0.1/",
    )

    assert "PS1001" not in finding_ids(response)


def test_frame_ancestors_wildcard_does_not_count_as_clickjacking_protection() -> None:
    headers = secure_headers()
    headers["content-security-policy"] = (
        "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors *",
    )

    assert "PS1201" in finding_ids(snapshot(headers=headers))


def test_scheme_qualified_any_host_is_not_clickjacking_protection() -> None:
    headers = secure_headers()
    headers["content-security-policy"] = (
        "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors https://*",
    )

    ids = finding_ids(snapshot(headers=headers))
    assert {"PS1104", "PS1201"} <= ids


def test_scoped_frame_ancestor_wildcard_still_constrains_framing() -> None:
    headers = secure_headers()
    headers["content-security-policy"] = (
        "default-src 'self'; object-src 'none'; base-uri 'none'; "
        "frame-ancestors https://*.trusted.example",
    )

    ids = finding_ids(snapshot(headers=headers))
    assert "PS1104" in ids
    assert "PS1201" not in ids


def test_referrer_policy_uses_the_last_recognized_fallback() -> None:
    headers = secure_headers()
    headers["referrer-policy"] = ("unsafe-url, no-referrer",)
    assert "PS1203" not in finding_ids(snapshot(headers=headers))

    headers["referrer-policy"] = ("no-referrer, unsafe-url",)
    finding = next(
        item
        for item in evaluate(snapshot(headers=headers), default_policy())
        if item.rule_id == "PS1203"
    )
    assert finding.severity is Severity.MEDIUM


def test_cors_and_cookie_failures_do_not_expose_cookie_values() -> None:
    headers = secure_headers()
    headers.update(
        {
            "access-control-allow-origin": ("*",),
            "access-control-allow-credentials": ("true",),
            "set-cookie": (
                "session=super-secret; Path=/",
                "cross=another-secret; SameSite=None; HttpOnly",
                "__Host-bad=value; Secure; Domain=example.com; Path=/",
                "invalid=value; Secure; HttpOnly; SameSite=Surprise",
            ),
        }
    )

    findings = evaluate(snapshot(headers=headers), default_policy())
    ids = {finding.rule_id for finding in findings}
    assert {"PS1301", "PS1401", "PS1402", "PS1403", "PS1404", "PS1405"} <= ids
    assert "super-secret" not in " ".join(finding.evidence or "" for finding in findings)
    assert "another-secret" not in " ".join(finding.message for finding in findings)
    assert next(item for item in findings if item.rule_id == "PS1301").severity is Severity.MEDIUM
    assert next(item for item in findings if item.rule_id == "PS1401").severity is Severity.MEDIUM
    assert any(item.rule_id == "PS1403" and item.subject == "cookie:invalid" for item in findings)


def test_specific_cors_origin_requires_vary_origin() -> None:
    headers = secure_headers()
    headers["access-control-allow-origin"] = ("https://app.example",)

    assert "PS1303" in finding_ids(snapshot(headers=headers))
    headers["vary"] = ("Accept-Encoding, Origin",)
    assert "PS1303" not in finding_ids(snapshot(headers=headers))


def test_tls_and_response_health_checks() -> None:
    headers = secure_headers()
    headers.update({"server": ("Example/1",), "x-powered-by": ("Example",)})
    response = snapshot(
        status_code=503,
        headers=headers,
        tls=TLSInfo(
            version="TLSv1.0",
            cipher="RC4-MD5",
            certificate_days_remaining=-1,
        ),
    )

    findings = evaluate(response, default_policy())
    ids = {finding.rule_id for finding in findings}
    assert {"PS1501", "PS1502", "PS1503", "PS1601", "PS1602"} <= ids
    certificate = next(item for item in findings if item.rule_id == "PS1502")
    assert certificate.severity is Severity.CRITICAL


def test_client_error_and_redirect_downgrade_are_detected() -> None:
    headers = secure_headers()
    response = snapshot(
        status_code=404,
        headers=headers,
        redirects=(
            RedirectHop(
                url="https://example.com/",
                status_code=302,
                location="http://example.com/login",
                resolved_ip="203.0.113.10",
            ),
        ),
    )

    assert {"PS0002", "PS1603"} <= finding_ids(response)


def test_custom_required_header_override_and_disable() -> None:
    policy = policy_from_mapping(
        {
            "version": 1,
            "checks": {
                "required_headers": {"X-Robots-Tag": {"contains": "noindex", "severity": "low"}},
                "severity_overrides": {"CUSTOM.X_ROBOTS_TAG": "critical"},
                "disabled": ["PS1204"],
            },
        }
    )
    headers = secure_headers()
    headers.pop("permissions-policy")

    findings = evaluate(snapshot(headers=headers), policy)
    custom = next(item for item in findings if item.rule_id == "CUSTOM.X_ROBOTS_TAG")
    assert custom.severity is Severity.CRITICAL
    assert "PS1204" not in {finding.rule_id for finding in findings}

    headers["x-robots-tag"] = ("noindex, nofollow",)
    assert "CUSTOM.X_ROBOTS_TAG" not in {
        finding.rule_id for finding in evaluate(snapshot(headers=headers), policy)
    }
