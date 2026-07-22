from __future__ import annotations

import http.client
import json
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any

import pytest

from previewshield import cli
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
from previewshield.webui import server as webui
from previewshield.webui import service


def _scan_report(*, finding: Finding | None = None) -> ScanReport:
    url = "https://example.com/"
    snapshot = ResponseSnapshot(
        requested_url=url,
        final_url=url,
        status_code=200,
        reason="OK",
        headers={},
        resolved_ip="203.0.113.10",
        elapsed_ms=4,
    )
    findings = () if finding is None else (finding,)
    return ScanReport(
        schema_version="1.0",
        tool_version="1.0.0",
        generated_at="2026-01-01T00:00:00Z",
        policy_name="browser-test",
        target=url,
        routes=(RouteReport(snapshot=snapshot, findings=findings),),
        score=100 if finding is None else 70,
        grade="A+" if finding is None else "C",
        fail_on=Severity.HIGH,
        passed=finding is None,
    )


def _diff_report() -> DiffReport:
    finding = Finding(
        rule_id="PS1101",
        title="CSP missing",
        severity=Severity.HIGH,
        category="browser",
        message="token=do-not-leak",
        remediation="Add an enforced CSP.",
        target="https://preview.example/?token=do-not-leak",
    )
    baseline = _scan_report()
    preview = _scan_report(finding=finding)
    return DiffReport(
        schema_version="1.0",
        tool_version="1.0.0",
        generated_at="2026-01-01T00:00:00Z",
        policy_name="browser-test",
        baseline=baseline,
        preview=preview,
        deltas=(
            FindingDelta(
                kind=DeltaKind.REGRESSION,
                fingerprint=finding.fingerprint,
                preview=finding,
            ),
        ),
        fail_on=Severity.HIGH,
        passed=False,
    )


@contextmanager
def _running_server(
    *,
    private_targets_enabled: bool = False,
) -> Iterator[webui.PreviewShieldUIServer]:
    ui_server = webui.create_ui_server(0, private_targets_enabled=private_targets_enabled)
    thread = threading.Thread(target=ui_server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()
    try:
        yield ui_server
    finally:
        ui_server.shutdown()
        ui_server.server_close()
        thread.join(timeout=2)


def _request(
    ui_server: webui.PreviewShieldUIServer,
    method: str,
    path: str,
    *,
    body: bytes | None = None,
    headers: Mapping[str, str] | None = None,
) -> tuple[int, dict[str, str], bytes]:
    port = int(ui_server.server_address[1])
    connection = http.client.HTTPConnection(
        "127.0.0.1",
        port,
        timeout=webui.CLIENT_SOCKET_TIMEOUT + 2,
    )
    request_headers = dict(headers or {})
    connection.request(method, path, body=body, headers=request_headers)
    response = connection.getresponse()
    response_body = response.read()
    response_headers = {name.lower(): value for name, value in response.getheaders()}
    connection.close()
    return response.status, response_headers, response_body


def _session(ui_server: webui.PreviewShieldUIServer) -> tuple[str, dict[str, str]]:
    status, headers, body = _request(ui_server, "GET", "/")
    assert status == 200
    assert b"PreviewShield" in body
    cookie = headers["set-cookie"].split(";", 1)[0]
    auth = {
        "Cookie": cookie,
        "Origin": ui_server.origin,
        "X-PreviewShield-CSRF": ui_server.csrf_token,
        "Content-Type": "application/json",
    }
    return cookie, auth


def test_service_scan_forwards_validated_browser_options(monkeypatch: pytest.MonkeyPatch) -> None:
    expected = _scan_report()
    observed: dict[str, Any] = {}

    def fake_scan(target: str, **kwargs: Any) -> ScanReport:
        observed.update(target=target, **kwargs)
        return expected

    monkeypatch.setattr(service.api, "scan", fake_scan)
    payload = {
        "target": " example.com ",
        "profile": "strict",
        "paths": ["/", "/health", "/"],
        "fail_on": "medium",
        "allow_private": False,
        "authorized_private": False,
    }

    assert service.execute_scan(payload, private_targets_enabled=False) is expected
    assert observed["target"] == "example.com"
    assert observed["paths"] == ("/", "/health")
    assert observed["fail_on"] is Severity.MEDIUM
    assert observed["allow_private"] is False
    assert observed["policy"].profile == "strict"


def test_service_diff_and_private_target_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    expected = _diff_report()
    observed: dict[str, Any] = {}

    def fake_diff(baseline: str, preview: str, **kwargs: Any) -> DiffReport:
        observed.update(baseline=baseline, preview=preview, **kwargs)
        return expected

    monkeypatch.setattr(service.api, "diff", fake_diff)
    payload = {
        "baseline": "http://127.0.0.1:3000",
        "preview": "http://127.0.0.1:4000",
        "paths": ["/"],
        "allow_private": True,
        "authorized_private": True,
    }

    with pytest.raises(service.UIInputError, match="Restart with --allow-private-targets"):
        service.execute_diff(payload, private_targets_enabled=False)

    payload["authorized_private"] = False
    with pytest.raises(service.UIInputError, match="Confirm authorization"):
        service.execute_diff(payload, private_targets_enabled=True)

    payload["authorized_private"] = True
    assert service.execute_diff(payload, private_targets_enabled=True) is expected
    assert observed["baseline"] == "http://127.0.0.1:3000"
    assert observed["preview"] == "http://127.0.0.1:4000"
    assert observed["allow_private"] is True


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ([], "JSON object"),
        ({"target": "example.com", "mystery": True}, "Unknown option"),
        ({"target": ""}, "non-empty string"),
        ({"target": "example.com", "profile": "maximum"}, "profile must be one of"),
        ({"target": "example.com", "allow_private": "yes"}, "must be true or false"),
        ({"target": "example.com", "paths": "not-a-list"}, "JSON list"),
        ({"target": "example.com", "paths": []}, "at least one route"),
        ({"target": "example.com", "paths": ["/"] * 21}, "at most 20"),
        ({"target": "example.com", "paths": ["\x00"]}, "safe characters"),
    ],
)
def test_service_rejects_invalid_payloads(payload: object, message: str) -> None:
    with pytest.raises(service.UIInputError, match=message):
        service.execute_scan(payload, private_targets_enabled=False)


def test_root_assets_use_session_and_security_headers() -> None:
    with _running_server(private_targets_enabled=True) as ui_server:
        status, headers, body = _request(ui_server, "GET", "/")
        assert status == 200
        assert ui_server.csrf_token.encode() in body
        assert b'data-private-enabled="true"' in body
        assert "HttpOnly" in headers["set-cookie"]
        assert "SameSite=Strict" in headers["set-cookie"]
        assert headers["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in headers["content-security-policy"]
        assert "access-control-allow-origin" not in headers

        status, _, script = _request(ui_server, "GET", "/app.js")
        assert status == 200
        assert b"innerHTML" not in script

        status, _, logic = _request(ui_server, "GET", "/logic.mjs")
        assert status == 200
        assert b"export function githubAction" in logic

        status, _, _ = _request(ui_server, "HEAD", "/styles.css")
        assert status == 200


def test_bad_host_unknown_routes_and_methods_are_rejected() -> None:
    with _running_server() as ui_server:
        status, _, _ = _request(ui_server, "GET", "/", headers={"Host": "attacker.test"})
        assert status == 400
        assert _request(ui_server, "GET", "/missing")[0] == 404
        status, headers, _ = _request(ui_server, "OPTIONS", "/api/v1/scan")
        assert status == 405
        assert headers["allow"] == "GET, HEAD, POST"


def test_post_requires_session_origin_csrf_and_json() -> None:
    with _running_server() as ui_server:
        body = json.dumps({"target": "example.com", "paths": ["/"]}).encode()
        base = {"Content-Type": "application/json"}
        assert _request(ui_server, "POST", "/api/v1/scan", body=body, headers=base)[0] == 403

        cookie, auth = _session(ui_server)
        missing_origin = dict(auth)
        missing_origin.pop("Origin")
        assert (
            _request(ui_server, "POST", "/api/v1/scan", body=body, headers=missing_origin)[0] == 403
        )

        wrong_csrf = dict(auth)
        wrong_csrf["X-PreviewShield-CSRF"] = "wrong"
        assert _request(ui_server, "POST", "/api/v1/scan", body=body, headers=wrong_csrf)[0] == 403

        wrong_type = {
            "Cookie": cookie,
            "Origin": ui_server.origin,
            "X-PreviewShield-CSRF": ui_server.csrf_token,
            "Content-Type": "text/plain",
        }
        assert _request(ui_server, "POST", "/api/v1/scan", body=body, headers=wrong_type)[0] == 415


def test_scan_response_is_sanitized_and_reports_are_downloadable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(webui, "execute_scan", lambda *_args, **_kwargs: _diff_report().preview)
    with _running_server() as ui_server:
        cookie, auth = _session(ui_server)
        payload = json.dumps({"target": "preview.example", "paths": ["/"]}).encode()
        status, _, body = _request(
            ui_server,
            "POST",
            "/api/v1/scan",
            body=payload,
            headers=auth,
        )
        assert status == 200
        response = json.loads(body)
        assert response["kind"] == "scan"
        assert response["report"]["passed"] is False
        assert "do-not-leak" not in body.decode()
        report_id = response["result_id"]

        export_headers = {
            "Cookie": cookie,
            "X-PreviewShield-CSRF": ui_server.csrf_token,
        }
        status, headers, report_body = _request(
            ui_server,
            "GET",
            f"/api/v1/reports/{report_id}/html",
            headers=export_headers,
        )
        assert status == 200
        assert headers["content-disposition"].endswith('"previewshield-report.html"')
        assert b"PreviewShield" in report_body
        assert b"do-not-leak" not in report_body

        assert (
            _request(
                ui_server,
                "GET",
                f"/api/v1/reports/{report_id}/json",
                headers={"Cookie": cookie, "X-PreviewShield-CSRF": "wrong"},
            )[0]
            == 403
        )
        assert (
            _request(
                ui_server,
                "GET",
                "/api/v1/reports/aaaaaaaaaaaaaaaaaaaa/json",
                headers=export_headers,
            )[0]
            == 404
        )


def test_diff_endpoint_invalid_json_and_busy_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(webui, "execute_diff", lambda *_args, **_kwargs: _diff_report())
    with _running_server() as ui_server:
        _, auth = _session(ui_server)
        assert _request(ui_server, "POST", "/api/v1/diff", body=b"{", headers=auth)[0] == 400

        payload = json.dumps(
            {"baseline": "example.com", "preview": "preview.example", "paths": ["/"]}
        ).encode()
        assert ui_server.scan_slots.acquire(blocking=False)
        assert ui_server.scan_slots.acquire(blocking=False)
        try:
            assert _request(ui_server, "POST", "/api/v1/diff", body=payload, headers=auth)[0] == 429
        finally:
            ui_server.scan_slots.release()
            ui_server.scan_slots.release()

        status, _, body = _request(
            ui_server,
            "POST",
            "/api/v1/diff",
            body=payload,
            headers=auth,
        )
        assert status == 200
        assert json.loads(body)["kind"] == "diff"


def test_report_store_is_bounded() -> None:
    ui_server = webui.create_ui_server(0)
    try:
        identifiers = [ui_server.store_report(_scan_report()) for _ in range(webui.MAX_REPORTS + 1)]
        assert ui_server.report(identifiers[0]) is None
        assert ui_server.report(identifiers[-1]) is not None

        retained_size = webui.MAX_REPORT_BYTES - (2 * 1024 * 1024)
        budget_ids = [
            ui_server.store_report(_scan_report(), size_bytes=retained_size) for _ in range(3)
        ]
        assert ui_server.report(budget_ids[0]) is None
        assert ui_server.report(budget_ids[-1]) is not None

        with pytest.raises(ValueError, match="report size must be between"):
            ui_server.store_report(_scan_report(), size_bytes=webui.MAX_REPORT_BYTES + 1)
    finally:
        ui_server.server_close()


def test_oversized_ui_report_is_not_retained(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(webui, "execute_scan", lambda *_args, **_kwargs: _scan_report())
    monkeypatch.setattr(webui, "MAX_REPORT_BYTES", 32)
    monkeypatch.setattr(
        webui,
        "render",
        lambda *_args, **_kwargs: '{"report":"' + ("x" * 64) + '"}',
    )
    with _running_server() as ui_server:
        _, auth = _session(ui_server)
        payload = json.dumps({"target": "example.com", "paths": ["/"]}).encode()
        status, _, body = _request(
            ui_server,
            "POST",
            "/api/v1/scan",
            body=payload,
            headers=auth,
        )
        assert status == 422
        assert b"too large for the local interface" in body


def test_cli_ui_command_and_port_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    observed: dict[str, object] = {}

    def fake_serve_ui(**kwargs: object) -> None:
        observed.update(kwargs)

    monkeypatch.setattr("previewshield.webui.serve_ui", fake_serve_ui)
    assert cli.main(["ui", "--port", "9000", "--no-open", "--allow-private-targets"]) == 0
    assert observed == {
        "port": 9000,
        "open_browser": False,
        "private_targets_enabled": True,
    }
    assert cli.main(["ui", "--port", "80"]) == 2


def test_create_server_rejects_invalid_port() -> None:
    with pytest.raises(ValueError, match="between 0 and 65535"):
        webui.create_ui_server(-1)
