"""Tests for PreviewShield's direct, SSRF-resistant network transport."""

from __future__ import annotations

import socket
import ssl
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from previewshield import network
from previewshield.exceptions import NetworkSafetyError, ScanError
from previewshield.network import NetworkOptions, fetch

_Responder = Callable[[BaseHTTPRequestHandler], None]


class _QuietThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request: object, client_address: object) -> None:
        """Suppress expected disconnects from intentionally unread bodies."""


@contextmanager
def _serve(responder: _Responder) -> Iterator[_QuietThreadingHTTPServer]:
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self) -> None:
            responder(self)

        def log_message(self, format_string: str, *args: object) -> None:
            del format_string, args

    server = _QuietThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _port(server: ThreadingHTTPServer) -> int:
    return int(server.server_address[1])


def _empty_response(handler: BaseHTTPRequestHandler, status: int = 200) -> None:
    handler.send_response(status)
    handler.send_header("Content-Length", "0")
    handler.end_headers()


def _pinned_addrinfo(
    hostname: str,
    port: int,
    **kwargs: object,
) -> list[tuple[Any, ...]]:
    del hostname, kwargs
    return [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("127.0.0.1", port),
        )
    ]


def _public_addrinfo(
    hostname: str,
    port: int,
    **kwargs: object,
) -> list[tuple[Any, ...]]:
    del hostname, kwargs
    return [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("93.184.216.34", port),
        )
    ]


def test_fetch_pins_dns_preserves_host_duplicates_and_skips_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, str] = {}
    body_release = threading.Event()

    def respond(handler: BaseHTTPRequestHandler) -> None:
        seen["host"] = handler.headers["Host"]
        seen["path"] = handler.path
        handler.send_response(200)
        handler.send_header("X-Repeat", "first")
        handler.send_header("X-Repeat", "second")
        handler.send_header("Content-Length", "1000000")
        handler.end_headers()
        body_release.wait(timeout=1.5)

    with _serve(respond) as server:
        port = _port(server)
        monkeypatch.setattr(socket, "getaddrinfo", _pinned_addrinfo)
        monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")

        started = time.monotonic()
        snapshot = fetch(
            f"http://PINNED.test:{port}/a path?q=hello world",
            NetworkOptions(timeout=1.0, allow_private=True),
        )
        duration = time.monotonic() - started
        body_release.set()

    assert duration < 0.5
    assert seen == {
        "host": f"pinned.test:{port}",
        "path": "/a%20path?q=hello%20world",
    }
    assert snapshot.requested_url == f"http://pinned.test:{port}/a%20path?q=hello%20world"
    assert snapshot.final_url == snapshot.requested_url
    assert snapshot.status_code == 200
    assert snapshot.reason == "OK"
    assert snapshot.resolved_ip == "127.0.0.1"
    assert snapshot.header("X-Repeat") == "second"
    assert snapshot.header_values("x-repeat") == ("first", "second")
    assert snapshot.redirects == ()
    assert snapshot.tls is None


def test_total_response_header_size_is_bounded() -> None:
    def respond(handler: BaseHTTPRequestHandler) -> None:
        handler.send_response(200)
        for index in range(9):
            handler.send_header(f"X-Large-{index}", "x" * 8192)
        handler.send_header("Content-Length", "0")
        handler.end_headers()

    with (
        _serve(respond) as server,
        pytest.raises(ScanError, match="response headers exceed the 65536-byte limit"),
    ):
        fetch(
            f"http://127.0.0.1:{_port(server)}/",
            NetworkOptions(allow_private=True),
        )


def test_cross_origin_redirect_strips_all_caller_headers() -> None:
    destination_headers: dict[str, str | None] = {}

    def destination(handler: BaseHTTPRequestHandler) -> None:
        destination_headers.update(
            authorization=handler.headers.get("Authorization"),
            cookie=handler.headers.get("Cookie"),
            trace=handler.headers.get("X-Trace"),
            api_key=handler.headers.get("X-API-Key"),
            user_agent=handler.headers.get("User-Agent"),
            accept=handler.headers.get("Accept"),
        )
        handler.send_response(200)
        handler.send_header("Set-Cookie", "one=1")
        handler.send_header("Set-Cookie", "two=2")
        handler.send_header("Content-Length", "0")
        handler.end_headers()

    with _serve(destination) as destination_server:
        destination_url = f"http://127.0.0.1:{_port(destination_server)}/final"

        def source(handler: BaseHTTPRequestHandler) -> None:
            assert handler.headers["Authorization"] == "Bearer secret"
            assert handler.headers["Cookie"] == "session=secret"
            handler.send_response(302)
            handler.send_header("Location", destination_url)
            handler.send_header("Content-Length", "0")
            handler.end_headers()

        with _serve(source) as source_server:
            source_url = f"http://127.0.0.1:{_port(source_server)}/start"
            snapshot = fetch(
                source_url,
                NetworkOptions(allow_private=True),
                {
                    "Authorization": "Bearer secret",
                    "Cookie": "session=secret",
                    "X-Trace": "caller-metadata",
                    "X-API-Key": "api-secret",
                },
            )

    assert destination_headers == {
        "authorization": None,
        "cookie": None,
        "trace": None,
        "api_key": None,
        "user_agent": "PreviewShield/1.0",
        "accept": "*/*",
    }
    assert snapshot.final_url == destination_url
    assert snapshot.header_values("set-cookie") == ("one=1", "two=2")
    assert snapshot.redirects == (
        network.RedirectHop(
            url=source_url,
            status_code=302,
            location=destination_url,
            resolved_ip="127.0.0.1",
        ),
    )


def test_same_origin_redirect_keeps_sensitive_headers() -> None:
    final_headers: dict[str, str | None] = {}

    def respond(handler: BaseHTTPRequestHandler) -> None:
        if handler.path == "/start":
            handler.send_response(307)
            handler.send_header("Location", "/final")
            handler.send_header("Content-Length", "0")
            handler.end_headers()
            return
        final_headers["authorization"] = handler.headers.get("Authorization")
        final_headers["cookie"] = handler.headers.get("Cookie")
        final_headers["api_key"] = handler.headers.get("X-API-Key")
        final_headers["trace"] = handler.headers.get("X-Trace")
        _empty_response(handler)

    with _serve(respond) as server:
        snapshot = fetch(
            f"http://127.0.0.1:{_port(server)}/start",
            NetworkOptions(allow_private=True),
            {
                "authorization": "Bearer same",
                "cookie": "same=1",
                "X-API-Key": "same-secret",
                "X-Trace": "same-trace",
            },
        )

    assert snapshot.status_code == 200
    assert final_headers == {
        "authorization": "Bearer same",
        "cookie": "same=1",
        "api_key": "same-secret",
        "trace": "same-trace",
    }


def test_redirect_fragment_is_not_sent_over_http() -> None:
    seen_paths: list[str] = []

    def respond(handler: BaseHTTPRequestHandler) -> None:
        seen_paths.append(handler.path)
        if handler.path == "/start":
            handler.send_response(302)
            handler.send_header("Location", "/final#section")
            handler.send_header("Content-Length", "0")
            handler.end_headers()
            return
        _empty_response(handler)

    with _serve(respond) as server:
        base = f"http://127.0.0.1:{_port(server)}"
        snapshot = fetch(f"{base}/start", NetworkOptions(allow_private=True))

    assert seen_paths == ["/start", "/final"]
    assert snapshot.final_url == f"{base}/final"


def test_explicit_user_agent_and_accept_are_not_duplicated() -> None:
    seen: dict[str, list[str] | None] = {}

    def respond(handler: BaseHTTPRequestHandler) -> None:
        seen["user-agent"] = handler.headers.get_all("User-Agent")
        seen["accept"] = handler.headers.get_all("Accept")
        _empty_response(handler)

    with _serve(respond) as server:
        fetch(
            f"http://127.0.0.1:{_port(server)}",
            NetworkOptions(allow_private=True),
            {"User-Agent": "custom-agent", "Accept": "application/json"},
        )

    assert seen == {"user-agent": ["custom-agent"], "accept": ["application/json"]}


def test_redirect_limit_is_enforced() -> None:
    def respond(handler: BaseHTTPRequestHandler) -> None:
        handler.send_response(302)
        handler.send_header("Location", "/second")
        handler.send_header("Content-Length", "0")
        handler.end_headers()

    with (
        _serve(respond) as server,
        pytest.raises(ScanError, match="Redirect limit exceeded"),
    ):
        fetch(
            f"http://127.0.0.1:{_port(server)}/first",
            NetworkOptions(max_redirects=0, allow_private=True),
        )


def test_redirect_loop_is_detected() -> None:
    def respond(handler: BaseHTTPRequestHandler) -> None:
        handler.send_response(301)
        handler.send_header("Location", handler.path)
        handler.send_header("Content-Length", "0")
        handler.end_headers()

    with (
        _serve(respond) as server,
        pytest.raises(ScanError, match="Redirect loop detected"),
    ):
        fetch(
            f"http://127.0.0.1:{_port(server)}/loop",
            NetworkOptions(allow_private=True),
        )


@pytest.mark.parametrize("allowed_host", ["source.allowed.test", "*.allowed.test"])
def test_disallowed_redirect_is_blocked_before_destination_is_hit(
    allowed_host: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_hit = threading.Event()
    destination_hit = threading.Event()

    def destination(handler: BaseHTTPRequestHandler) -> None:
        destination_hit.set()
        _empty_response(handler)

    monkeypatch.setattr(socket, "getaddrinfo", _pinned_addrinfo)
    with _serve(destination) as destination_server:
        destination_url = f"http://blocked.test:{_port(destination_server)}/final"

        def source(handler: BaseHTTPRequestHandler) -> None:
            source_hit.set()
            handler.send_response(302)
            handler.send_header("Location", destination_url)
            handler.send_header("Content-Length", "0")
            handler.end_headers()

        with (
            _serve(source) as source_server,
            pytest.raises(NetworkSafetyError, match="configured allowlist"),
        ):
            fetch(
                f"http://source.allowed.test:{_port(source_server)}/start",
                NetworkOptions(
                    allow_private=True,
                    allowed_hosts=(allowed_host.upper(),),
                ),
            )

    assert source_hit.is_set()
    assert not destination_hit.is_set()


def test_wildcard_allowlist_does_not_match_the_apex() -> None:
    with pytest.raises(NetworkSafetyError, match="configured allowlist"):
        fetch(
            "http://allowed.test",
            NetworkOptions(allowed_hosts=("*.allowed.test",)),
        )


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.10.10.10",
        "169.254.10.10",
        "100.64.0.1",
        "224.0.0.1",
        "240.0.0.1",
        "0.0.0.0",
        "::1",
        "fe80::1",
        "fec0::1",
        "ff02::1",
        "::",
        "::ffff:127.0.0.1",
        "2002:0a00:0001::",
        "2001:0000:4136:e378:8000:63bf:f5ff:fffe",
    ],
)
def test_non_public_dns_answers_are_blocked(
    address: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sockaddr: tuple[Any, ...] = (address, 80, 0, 0) if family == socket.AF_INET6 else (address, 80)

    def resolve(*args: object, **kwargs: object) -> list[tuple[Any, ...]]:
        del args, kwargs
        return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)]

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    with pytest.raises(NetworkSafetyError, match="resolved to blocked address"):
        fetch("http://blocked.test", NetworkOptions())


def test_one_unsafe_dns_answer_rejects_the_entire_origin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def resolve(*args: object, **kwargs: object) -> list[tuple[Any, ...]]:
        del args, kwargs
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("93.184.216.34", 80),
            ),
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                socket.IPPROTO_TCP,
                "",
                ("127.0.0.1", 80),
            ),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    with pytest.raises(NetworkSafetyError, match=r"127\.0\.0\.1"):
        fetch("http://mixed.test", NetworkOptions())


def test_private_target_is_blocked_by_default() -> None:
    def respond(handler: BaseHTTPRequestHandler) -> None:
        _empty_response(handler)

    with (
        _serve(respond) as server,
        pytest.raises(NetworkSafetyError, match="blocked address"),
    ):
        fetch(f"http://127.0.0.1:{_port(server)}", NetworkOptions())


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/file",
        "http://user:secret@example.com/",
        "http://example.com/#fragment",
        "http://example.com:99999/",
        "http://example.com:/",
        "http://invalid_host.example/",
        " http://example.com/",
        "http://example.com/%not-escaped",
        "http://[fe80::1%25adapter]/",
        "http://example.com/with\\backslash",
    ],
)
def test_unsafe_urls_are_rejected_before_network_access(url: str) -> None:
    with pytest.raises(NetworkSafetyError):
        fetch(url, NetworkOptions())


@pytest.mark.parametrize(
    ("headers", "message"),
    [
        ({"Host": "attacker.example"}, "cannot be overridden"),
        ({"Connection": "keep-alive"}, "cannot be overridden"),
        ({"X-Test\r\nInjected": "true"}, "invalid name"),
        ({"X-Test": "safe\r\nInjected: true"}, "control character"),
        ({"X-Test": "snowman: ☃"}, "ISO-8859-1"),
    ],
)
def test_unsafe_request_headers_are_rejected(
    headers: dict[str, str],
    message: str,
) -> None:
    with pytest.raises(NetworkSafetyError, match=message):
        fetch("https://example.com", NetworkOptions(), headers)


@pytest.mark.parametrize(
    "arguments",
    [
        {"timeout": 0},
        {"timeout": float("inf")},
        {"timeout": True},
        {"max_redirects": -1},
        {"max_redirects": 21},
        {"max_redirects": True},
        {"allow_private": "yes"},
        {"user_agent": "bad\r\nheader"},
        {"allowed_hosts": ["example.com"]},
        {"allowed_hosts": ("*.",)},
        {"allowed_hosts": ("*.127.0.0.1",)},
        {"allowed_hosts": ("bad*host.example",)},
    ],
)
def test_network_options_reject_unbounded_or_unsafe_values(arguments: dict[str, Any]) -> None:
    with pytest.raises(ValueError):
        NetworkOptions(**arguments)


def test_dns_failures_have_a_stable_domain_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> list[tuple[Any, ...]]:
        del args, kwargs
        raise socket.gaierror

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    with pytest.raises(ScanError, match=r"^DNS resolution failed for 'missing\.test'\.$"):
        fetch("http://missing.test", NetworkOptions())


@pytest.mark.parametrize(
    ("answer", "message"),
    [
        (
            (9999, socket.SOCK_STREAM, 0, "", ("ignored", 80)),
            "no usable addresses",
        ),
        (
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("not-an-ip", 80)),
            "invalid address",
        ),
        (
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("::1", 80)),
            "address-family mismatch",
        ),
        (
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", "not-a-tuple"),
            "malformed socket address",
        ),
        (
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 81)),
            "unexpected destination port",
        ),
    ],
)
def test_malformed_dns_answers_are_scan_errors(
    answer: tuple[Any, ...],
    message: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def resolve(*args: object, **kwargs: object) -> list[tuple[Any, ...]]:
        del args, kwargs
        return [answer]

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    with pytest.raises(ScanError, match=message):
        fetch("http://malformed.test", NetworkOptions())


def test_header_timeout_has_a_stable_domain_error() -> None:
    def respond(handler: BaseHTTPRequestHandler) -> None:
        time.sleep(0.2)
        with suppress(OSError):
            _empty_response(handler)

    with (
        _serve(respond) as server,
        pytest.raises(ScanError, match="Request timed out"),
    ):
        fetch(
            f"http://127.0.0.1:{_port(server)}",
            NetworkOptions(timeout=0.05, allow_private=True),
        )


def test_total_deadline_stops_slowloris_header_drip() -> None:
    def respond(handler: BaseHTTPRequestHandler) -> None:
        handler.close_connection = True
        payload = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        with suppress(OSError):
            for byte in payload:
                time.sleep(0.01)
                handler.connection.sendall(bytes((byte,)))

    with _serve(respond) as server:
        started = time.monotonic()
        with pytest.raises(ScanError, match="Request timed out"):
            fetch(
                f"http://127.0.0.1:{_port(server)}",
                NetworkOptions(timeout=0.05, allow_private=True),
            )
        elapsed = time.monotonic() - started

    assert elapsed < 0.3


def test_https_certificate_errors_are_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_tls(connection: object) -> None:
        del connection
        raise ssl.SSLCertVerificationError

    monkeypatch.setattr(socket, "getaddrinfo", _public_addrinfo)
    monkeypatch.setattr(network._PinnedHTTPSConnection, "connect", fail_tls)
    with pytest.raises(ScanError, match="TLS certificate verification failed"):
        fetch("https://certificate.test", NetworkOptions())


def test_https_pinning_preserves_sni_and_closes_on_wrap_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeSocket:
        def __init__(self) -> None:
            self.closed = False
            self.timeout: float | None = None

        def close(self) -> None:
            self.closed = True

        def settimeout(self, timeout: float) -> None:
            self.timeout = timeout

        def shutdown(self, how: int) -> None:
            del how

        def do_handshake(self) -> None:
            return

    class RecordingContext:
        def __init__(self, wrapped: FakeSocket, *, fail: bool = False) -> None:
            self.wrapped = wrapped
            self.fail = fail
            self.server_hostname: str | None = None
            self.verify_mode = ssl.CERT_REQUIRED
            self.check_hostname = True

        def wrap_socket(
            self,
            raw_socket: FakeSocket,
            *,
            server_hostname: str,
            do_handshake_on_connect: bool,
        ) -> FakeSocket:
            self.server_hostname = server_hostname
            assert not do_handshake_on_connect
            if self.fail:
                raise ssl.SSLError("test failure")
            assert raw_socket is not self.wrapped
            return self.wrapped

    raw_socket = FakeSocket()
    wrapped_socket = FakeSocket()
    context = RecordingContext(wrapped_socket)

    def connect(*args: object, **kwargs: object) -> tuple[FakeSocket, str]:
        del args, kwargs
        return raw_socket, "93.184.216.34"

    monkeypatch.setattr(network, "_connect_pinned", connect)
    connection = network._PinnedHTTPSConnection(
        "secure.example",
        443,
        (),
        1.0,
        context,  # type: ignore[arg-type]
    )
    connection.connect()

    assert context.server_hostname == "secure.example"
    assert connection.connected_ip == "93.184.216.34"
    assert connection.sock is wrapped_socket
    assert not raw_socket.closed

    failing_raw = FakeSocket()
    failing_context = RecordingContext(FakeSocket(), fail=True)

    def connect_failure(*args: object, **kwargs: object) -> tuple[FakeSocket, str]:
        del args, kwargs
        return failing_raw, "93.184.216.34"

    monkeypatch.setattr(network, "_connect_pinned", connect_failure)
    failing_connection = network._PinnedHTTPSConnection(
        "secure.example",
        443,
        (),
        1.0,
        failing_context,  # type: ignore[arg-type]
    )
    with pytest.raises(ssl.SSLError, match="test failure"):
        failing_connection.connect()
    assert failing_raw.closed


def test_connection_failures_are_stable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refuse(*args: object, **kwargs: object) -> tuple[socket.socket, str]:
        del args, kwargs
        raise ConnectionRefusedError

    monkeypatch.setattr(socket, "getaddrinfo", _public_addrinfo)
    monkeypatch.setattr(network, "_connect_pinned", refuse)
    with pytest.raises(ScanError, match=r"^Connection failed for 'public\.test'\.$"):
        fetch("http://public.test", NetworkOptions())


def test_invalid_http_responses_are_stable() -> None:
    def invalid_http(handler: BaseHTTPRequestHandler) -> None:
        handler.connection.sendall(b"NOT-HTTP\r\n\r\n")
        handler.close_connection = True

    with (
        _serve(invalid_http) as server,
        pytest.raises(ScanError, match="Invalid HTTP response"),
    ):
        fetch(
            f"http://127.0.0.1:{_port(server)}",
            NetworkOptions(allow_private=True),
        )


def test_tls_metadata_is_captured(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeSSLSocket:
        def version(self) -> str:
            return "TLSv1.3"

        def cipher(self) -> tuple[str, str, int]:
            return "TLS_AES_256_GCM_SHA384", "TLSv1.3", 256

        def getpeercert(self) -> dict[str, object]:
            return {
                "subject": ((("commonName", "preview.example"),),),
                "issuer": ((("organizationName", "Test CA"),),),
                "notAfter": "Dec 31 23:59:59 2099 GMT",
            }

    monkeypatch.setattr(network.ssl, "SSLSocket", FakeSSLSocket)
    info = network._capture_tls(FakeSSLSocket())  # type: ignore[arg-type]

    assert info is not None
    assert info.version == "TLSv1.3"
    assert info.cipher == "TLS_AES_256_GCM_SHA384"
    assert info.certificate_subject == "commonName=preview.example"
    assert info.certificate_issuer == "organizationName=Test CA"
    assert info.certificate_expires_at == "2099-12-31T23:59:59Z"
    assert info.certificate_days_remaining is not None
    assert info.certificate_days_remaining > 20_000
