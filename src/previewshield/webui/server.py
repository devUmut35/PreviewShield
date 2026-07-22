"""Hardened loopback HTTP server for the PreviewShield browser interface."""

from __future__ import annotations

import json
import re
import secrets
import threading
import webbrowser
from collections import OrderedDict
from collections.abc import Mapping
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from typing import cast
from urllib.parse import urlsplit

from previewshield.exceptions import (
    ConfigurationError,
    NetworkSafetyError,
    PreviewShieldError,
    ScanError,
)
from previewshield.reporters import Report, render
from previewshield.webui.service import execute_diff, execute_scan

MAX_REQUEST_BYTES = 32 * 1024
MAX_REPORTS = 5
MAX_REPORT_BYTES = 8 * 1024 * 1024
MAX_STORED_REPORT_BYTES = 16 * 1024 * 1024
CLIENT_SOCKET_TIMEOUT = 8.0
REJECTED_BODY_DRAIN_TIMEOUT = 0.25
MAX_PORT = 65_535
SESSION_COOKIE = "previewshield_ui"
UI_CSP = (
    "default-src 'self'; base-uri 'none'; connect-src 'self'; font-src 'self'; "
    "form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; "
    "object-src 'none'; script-src 'self'; style-src 'self'"
)
LOCKED_CSP = "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
_ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/logic.mjs": ("logic.mjs", "text/javascript; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/fonts/archivo-black.ttf": ("fonts/archivo-black.ttf", "font/ttf"),
    "/fonts/ibm-plex-mono.ttf": ("fonts/ibm-plex-mono.ttf", "font/ttf"),
}
_REPORT_PATH = re.compile(
    r"^/api/v1/reports/(?P<report_id>[A-Za-z0-9_-]{20,64})/"
    r"(?P<format>html|json|junit|markdown|sarif)$"
)
_REPORT_METADATA = {
    "html": ("text/html; charset=utf-8", "html"),
    "json": ("application/json; charset=utf-8", "json"),
    "junit": ("application/xml; charset=utf-8", "xml"),
    "markdown": ("text/markdown; charset=utf-8", "md"),
    "sarif": ("application/sarif+json; charset=utf-8", "sarif"),
}


class PreviewShieldUIServer(ThreadingHTTPServer):
    """Single-user loopback server with bounded in-memory reports."""

    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 8

    def __init__(
        self,
        server_address: tuple[str, int],
        *,
        private_targets_enabled: bool,
    ) -> None:
        super().__init__(server_address, PreviewShieldUIHandler)
        self.private_targets_enabled = private_targets_enabled
        self.session_token = secrets.token_urlsafe(32)
        self.csrf_token = secrets.token_urlsafe(32)
        self.scan_slots = threading.BoundedSemaphore(value=2)
        self._report_lock = threading.Lock()
        self._reports: OrderedDict[str, tuple[Report, int]] = OrderedDict()
        self._stored_report_bytes = 0

    @property
    def origin(self) -> str:
        """Return the one browser origin accepted by the server."""

        _, port = self.server_address[:2]
        return f"http://127.0.0.1:{port}"

    @property
    def expected_host(self) -> str:
        """Return the exact Host header accepted by the server."""

        _, port = self.server_address[:2]
        return f"127.0.0.1:{port}"

    def store_report(self, report: Report, *, size_bytes: int | None = None) -> str:
        """Keep a small number of reports in memory for browser downloads."""

        if size_bytes is None:
            size_bytes = len(render(report, "json").encode("utf-8"))
        if not 0 <= size_bytes <= MAX_REPORT_BYTES:
            raise ValueError(f"report size must be between 0 and {MAX_REPORT_BYTES} bytes")

        with self._report_lock:
            report_id = secrets.token_urlsafe(18)
            while report_id in self._reports:  # pragma: no cover - cryptographically improbable
                report_id = secrets.token_urlsafe(18)
            self._reports[report_id] = (report, size_bytes)
            self._stored_report_bytes += size_bytes
            while (
                len(self._reports) > MAX_REPORTS
                or self._stored_report_bytes > MAX_STORED_REPORT_BYTES
            ):
                _, (_, evicted_size) = self._reports.popitem(last=False)
                self._stored_report_bytes -= evicted_size
            return report_id

    def report(self, report_id: str) -> Report | None:
        """Return one session report without exposing it across processes or restarts."""

        with self._report_lock:
            stored = self._reports.get(report_id)
            if stored is not None:
                self._reports.move_to_end(report_id)
                return stored[0]
            return None


class PreviewShieldUIHandler(BaseHTTPRequestHandler):
    """Serve static UI assets and authenticated scan requests."""

    protocol_version = "HTTP/1.1"
    server_version = "PreviewShieldUI"
    sys_version = ""

    @property
    def ui_server(self) -> PreviewShieldUIServer:
        return cast(PreviewShieldUIServer, self.server)

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(CLIENT_SOCKET_TIMEOUT)

    def do_GET(self) -> None:
        if not self._host_is_valid():
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Invalid Host header."})
            return
        path = urlsplit(self.path).path
        match = _REPORT_PATH.fullmatch(path)
        if match is not None:
            self._serve_report(match.group("report_id"), match.group("format"))
            return
        asset = _ASSETS.get(path)
        if asset is None:
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Not found."})
            return
        self._serve_asset(path, asset[0], asset[1])

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_POST(self) -> None:  # noqa: PLR0911, PLR0912, PLR0915
        if not self._host_is_valid():
            self._reject_unread(HTTPStatus.BAD_REQUEST, "Invalid Host header.")
            return
        path = urlsplit(self.path).path
        if path not in {"/api/v1/scan", "/api/v1/diff"}:
            self._reject_unread(HTTPStatus.NOT_FOUND, "Not found.")
            return
        if not self._post_is_authorized():
            self._reject_unread(HTTPStatus.FORBIDDEN, "Invalid local UI session.")
            return
        if self.headers.get("Transfer-Encoding") is not None:
            self._reject_unread(HTTPStatus.BAD_REQUEST, "Transfer-Encoding is not supported.")
            return
        if self.headers.get_content_type() != "application/json":
            self._reject_unread(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "JSON is required.")
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._reject_unread(HTTPStatus.BAD_REQUEST, "Invalid Content-Length.")
            return
        if not 0 < content_length <= MAX_REQUEST_BYTES:
            self._reject_unread(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Request is too large.")
            return

        try:
            payload = json.loads(self.rfile.read(content_length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "Invalid JSON."})
            return

        if not self.ui_server.scan_slots.acquire(blocking=False):
            self._send_json(
                HTTPStatus.TOO_MANY_REQUESTS,
                {"ok": False, "error": "Two scans are already running."},
            )
            return

        try:
            report: Report
            if path == "/api/v1/scan":
                kind = "scan"
                report = execute_scan(
                    payload,
                    private_targets_enabled=self.ui_server.private_targets_enabled,
                )
            else:
                kind = "diff"
                report = execute_diff(
                    payload,
                    private_targets_enabled=self.ui_server.private_targets_enabled,
                )
            report_json = render(report, "json")
            report_size = len(report_json.encode("utf-8"))
            if report_size > MAX_REPORT_BYTES:
                self._send_json(
                    HTTPStatus.UNPROCESSABLE_ENTITY,
                    {
                        "ok": False,
                        "error": "The generated report is too large for the local interface.",
                    },
                )
                return
            report_payload = json.loads(report_json)
            report_id = self.ui_server.store_report(report, size_bytes=report_size)
            self._send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "kind": kind,
                    "result_id": report_id,
                    "report": report_payload,
                    "formats": list(_REPORT_METADATA),
                },
            )
        except ConfigurationError as error:
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(error)})
        except NetworkSafetyError as error:
            self._send_json(HTTPStatus.UNPROCESSABLE_ENTITY, {"ok": False, "error": str(error)})
        except ScanError as error:
            self._send_json(HTTPStatus.BAD_GATEWAY, {"ok": False, "error": str(error)})
        except PreviewShieldError as error:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"ok": False, "error": str(error)})
        except Exception as error:  # noqa: BLE001 - UI boundary hides target and secret details
            print(f"PreviewShield UI request failed: {type(error).__name__}")
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"ok": False, "error": "The scan failed unexpectedly. Check the terminal."},
            )
        finally:
            self.ui_server.scan_slots.release()

    def do_OPTIONS(self) -> None:
        self._method_not_allowed()

    def do_PUT(self) -> None:
        self._method_not_allowed()

    def do_PATCH(self) -> None:
        self._method_not_allowed()

    def do_DELETE(self) -> None:
        self._method_not_allowed()

    def _serve_asset(self, request_path: str, asset_name: str, content_type: str) -> None:
        try:
            body = resources.files("previewshield.webui.assets").joinpath(asset_name).read_bytes()
        except (FileNotFoundError, ModuleNotFoundError):
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"ok": False, "error": "A packaged UI asset is missing."},
            )
            return
        if request_path == "/":
            body = body.replace(b"{{CSRF_TOKEN}}", self.ui_server.csrf_token.encode("ascii"))
            private_enabled = b"true" if self.ui_server.private_targets_enabled else b"false"
            body = body.replace(b"{{PRIVATE_TARGETS_ENABLED}}", private_enabled)
            body = body.replace(b"{{CSP}}", UI_CSP.encode("ascii"))
            self._send_bytes(
                HTTPStatus.OK,
                body,
                content_type,
                establish_session=True,
                content_security_policy=UI_CSP,
            )
            return
        self._send_bytes(
            HTTPStatus.OK,
            body,
            content_type,
            content_security_policy=UI_CSP,
        )

    def _serve_report(self, report_id: str, format_name: str) -> None:
        if not self._session_and_csrf_are_valid():
            self._send_json(
                HTTPStatus.FORBIDDEN,
                {"ok": False, "error": "Invalid local UI session."},
            )
            return
        report = self.ui_server.report(report_id)
        if report is None:
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "Report not found."})
            return
        content_type, extension = _REPORT_METADATA[format_name]
        try:
            body = render(report, format_name).encode("utf-8")
        except (UnicodeError, ValueError, PreviewShieldError):
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"ok": False, "error": "The report could not be rendered."},
            )
            return
        self._send_bytes(
            HTTPStatus.OK,
            body,
            content_type,
            content_security_policy=LOCKED_CSP,
            extra_headers={
                "Content-Disposition": f'attachment; filename="previewshield-report.{extension}"'
            },
        )

    def _host_is_valid(self) -> bool:
        return secrets.compare_digest(self.headers.get("Host", ""), self.ui_server.expected_host)

    def _post_is_authorized(self) -> bool:
        origin = self.headers.get("Origin", "")
        return (
            secrets.compare_digest(
                origin,
                self.ui_server.origin,
            )
            and self._session_and_csrf_are_valid()
        )

    def _session_and_csrf_are_valid(self) -> bool:
        csrf = self.headers.get("X-PreviewShield-CSRF", "")
        if not secrets.compare_digest(csrf, self.ui_server.csrf_token):
            return False
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except ValueError:
            return False
        session = cookie.get(SESSION_COOKIE)
        return session is not None and secrets.compare_digest(
            session.value,
            self.ui_server.session_token,
        )

    def _security_headers(self, content_security_policy: str) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", content_security_policy)
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header(
            "Permissions-Policy",
            "camera=(), geolocation=(), microphone=(), payment=()",
        )
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")

    def _send_bytes(  # noqa: PLR0913
        self,
        status: HTTPStatus,
        body: bytes,
        content_type: str,
        *,
        establish_session: bool = False,
        content_security_policy: str = LOCKED_CSP,
        extra_headers: Mapping[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self._security_headers(content_security_policy)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if establish_session:
            self.send_header(
                "Set-Cookie",
                (
                    f"{SESSION_COOKIE}={self.ui_server.session_token}; "
                    "HttpOnly; SameSite=Strict; Path=/"
                ),
            )
        if extra_headers is not None:
            for name, value in extra_headers.items():
                self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            try:
                self.wfile.write(body)
            except (BrokenPipeError, TimeoutError):
                return

    def _send_json(self, status: HTTPStatus, payload: Mapping[str, object]) -> None:
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        self._send_bytes(status, body, "application/json; charset=utf-8")

    def _reject_unread(self, status: HTTPStatus, message: str) -> None:
        self.close_connection = True
        body = json.dumps(
            {"ok": False, "error": message},
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        self._send_bytes(
            status,
            body,
            "application/json; charset=utf-8",
            extra_headers={"Connection": "close"},
        )
        self._discard_bounded_request_body()

    def _discard_bounded_request_body(self) -> None:
        if self.headers.get("Transfer-Encoding") is not None:
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return
        if not 0 < content_length <= MAX_REQUEST_BYTES:
            return
        try:
            self.connection.settimeout(REJECTED_BODY_DRAIN_TIMEOUT)
            self.rfile.read(content_length)
        except OSError:
            return

    def _method_not_allowed(self) -> None:
        self.close_connection = True
        self._send_bytes(
            HTTPStatus.METHOD_NOT_ALLOWED,
            b'{"ok":false,"error":"Method not allowed."}',
            "application/json; charset=utf-8",
            extra_headers={"Allow": "GET, HEAD, POST"},
        )

    def log_message(self, format_string: str, *args: object) -> None:
        return


def create_ui_server(
    port: int = 8765,
    *,
    private_targets_enabled: bool = False,
) -> PreviewShieldUIServer:
    """Create a loopback-only server. Port zero selects an available test port."""

    if not 0 <= port <= MAX_PORT:
        raise ValueError("port must be between 0 and 65535")
    return PreviewShieldUIServer(
        ("127.0.0.1", port),
        private_targets_enabled=private_targets_enabled,
    )


def serve_ui(
    *,
    port: int = 8765,
    open_browser: bool = True,
    private_targets_enabled: bool = False,
) -> None:
    """Run the local browser interface until interrupted."""

    server = create_ui_server(port, private_targets_enabled=private_targets_enabled)
    url = f"{server.origin}/"
    print(f"PreviewShield UI is ready at {url}")
    print("The interface is local-only. Press Ctrl+C to stop it.")
    if private_targets_enabled:
        print("Private target access is enabled for this session; scan only trusted systems.")
    if open_browser:
        opener = threading.Timer(0.15, webbrowser.open, args=(url,), kwargs={"new": 2})
        opener.daemon = True
        opener.start()
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print("\nStopping PreviewShield UI.")
    finally:
        server.server_close()


__all__ = ["PreviewShieldUIServer", "create_ui_server", "serve_ui"]
