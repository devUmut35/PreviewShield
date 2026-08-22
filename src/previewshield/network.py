"""Safe, dependency-free HTTP metadata fetching for PreviewShield.

The fetcher deliberately bypasses environment and system proxy configuration.  It
resolves each origin itself, validates every returned address, and connects directly
to one of those exact addresses.  This DNS pinning prevents a second name lookup from
redirecting a scan toward an internal service after the safety check.

Only response headers are captured.  Response bodies are never read or buffered.
"""

from __future__ import annotations

import http.client
import ipaddress
import math
import re
import socket
import ssl
import threading
import time
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, TypeAlias
from urllib.parse import SplitResult, quote, urldefrag, urljoin, urlsplit, urlunsplit

from previewshield.exceptions import NetworkSafetyError, ScanError
from previewshield.models import MutableHeaderBag, RedirectHop, ResponseSnapshot, TLSInfo
from previewshield.targets import normalize_hostname as _shared_normalize_hostname

_DEFAULT_TIMEOUT = 10.0
_DEFAULT_REDIRECTS = 5
_MAX_REDIRECTS = 20
_MAX_URL_LENGTH = 8192
_MAX_PORT = 65_535
_MAX_HEADER_VALUE_LENGTH = 16_384
_MAX_RESPONSE_HEADER_BYTES = 64 * 1024
_IPV4_SOCKADDR_LENGTH = 2
_IPV6_SOCKADDR_LENGTH = 4
_CERTIFICATE_ATTRIBUTE_LENGTH = 2
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_FORBIDDEN_REQUEST_HEADERS = frozenset(
    {
        "connection",
        "content-length",
        "host",
        "proxy-authorization",
        "proxy-connection",
        "transfer-encoding",
    }
)
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_CONTROL_CHARACTER = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
_UNSAFE_URL_CHARACTER = re.compile(r"[\x00-\x1f\x7f]")

_SocketAddress: TypeAlias = tuple[str, int] | tuple[str, int, int, int]
_RequestHeaders: TypeAlias = tuple[tuple[str, str], ...]


@dataclass(frozen=True, slots=True)
class NetworkOptions:
    """Controls safe network access for one fetch operation.

    ``timeout`` is a total wall-clock budget, in seconds, shared by all redirect
    hops (system DNS resolution itself cannot be portably interrupted by Python's
    standard library).  ``allow_private`` disables the address boundary and should
    only be used for explicitly trusted local targets, such as test servers.
    ``allowed_hosts`` optionally restricts every hop to exact hostnames or ``*.``
    subdomain patterns; an empty tuple preserves unrestricted legacy behavior.

    No option enables proxy discovery: requests always connect directly to a DNS
    answer that this module validated.
    """

    timeout: float = _DEFAULT_TIMEOUT
    max_redirects: int = _DEFAULT_REDIRECTS
    allow_private: bool = False
    user_agent: str = "PreviewShield/1.0"
    allowed_hosts: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Reject settings that could disable resource bounds or inject headers."""

        if isinstance(self.timeout, bool) or not isinstance(self.timeout, (int, float)):
            raise ValueError("timeout must be a finite positive number")
        if not math.isfinite(self.timeout) or self.timeout <= 0:
            raise ValueError("timeout must be a finite positive number")
        if isinstance(self.max_redirects, bool) or not isinstance(self.max_redirects, int):
            raise ValueError("max_redirects must be an integer")
        if not 0 <= self.max_redirects <= _MAX_REDIRECTS:
            raise ValueError(f"max_redirects must be between 0 and {_MAX_REDIRECTS}")
        if not isinstance(self.allow_private, bool):
            raise ValueError("allow_private must be a boolean")
        _validate_header_value(self.user_agent, label="user_agent")
        if not self.user_agent:
            raise ValueError("user_agent must not be empty")
        if not isinstance(self.allowed_hosts, tuple):
            raise ValueError("allowed_hosts must be a tuple of host patterns")
        object.__setattr__(self, "allowed_hosts", _normalize_allowed_hosts(self.allowed_hosts))


@dataclass(frozen=True, slots=True)
class _NormalizedURL:
    value: str
    scheme: str
    hostname: str
    port: int
    request_target: str

    @property
    def origin(self) -> tuple[str, str, int]:
        return self.scheme, self.hostname, self.port

    @property
    def host_header(self) -> str:
        host = f"[{self.hostname}]" if ":" in self.hostname else self.hostname
        default_port = 443 if self.scheme == "https" else 80
        return host if self.port == default_port else f"{host}:{self.port}"


@dataclass(frozen=True, slots=True)
class _ResolvedAddress:
    ip: str
    family: socket.AddressFamily
    sockaddr: _SocketAddress


@dataclass(frozen=True, slots=True)
class _ResponseMetadata:
    status_code: int
    reason: str
    headers: dict[str, tuple[str, ...]]
    resolved_ip: str
    tls: TLSInfo | None


class _SocketDeadline:
    """Interrupt blocking socket I/O when an absolute monotonic deadline expires."""

    def __init__(self, sock: socket.socket, started: float, timeout: float) -> None:
        self._socket = sock
        self._deadline = started + timeout
        self._expired = threading.Event()
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("network deadline expired")
        sock.settimeout(remaining)
        self._timer = threading.Timer(remaining, self._expire)
        self._timer.daemon = True
        self._timer.start()
        self._closed = False

    def expired(self) -> bool:
        """Return whether the watchdog fired or wall-clock time crossed the deadline."""

        return self._expired.is_set() or time.monotonic() >= self._deadline

    def finish(self) -> None:
        """Atomically stop the watchdog and reject a just-completed late response."""

        self.close()
        if self.expired():
            raise TimeoutError("network deadline expired")

    def close(self) -> None:
        """Cancel and join the watchdog without closing the guarded socket."""

        if self._closed:
            return
        self._closed = True
        self._timer.cancel()
        self._timer.join()

    def _expire(self) -> None:
        self._expired.set()
        with suppress(OSError):
            self._socket.shutdown(socket.SHUT_RDWR)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection that opens only a pre-resolved, validated address."""

    def __init__(
        self,
        host: str,
        port: int,
        addresses: Sequence[_ResolvedAddress],
        timeout: float,
    ) -> None:
        super().__init__(host, port=port, timeout=timeout)
        self._pinned_addresses = addresses
        self.connected_ip: str | None = None

    def connect(self) -> None:
        """Connect without asking the operating system to resolve the host again."""

        self.sock, self.connected_ip = _connect_pinned(self._pinned_addresses, self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection with pinned DNS and normal hostname verification/SNI."""

    def __init__(
        self,
        host: str,
        port: int,
        addresses: Sequence[_ResolvedAddress],
        timeout: float,
        context: ssl.SSLContext,
    ) -> None:
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._pinned_addresses = addresses
        self._previewshield_context = context
        self.connected_ip: str | None = None

    def connect(self) -> None:
        """Wrap the pinned socket while retaining the URL hostname for TLS checks."""

        started = time.monotonic()
        raw_socket, self.connected_ip = _connect_pinned(
            self._pinned_addresses,
            self.timeout,
        )
        tls_socket: ssl.SSLSocket | None = None
        watchdog: _SocketDeadline | None = None
        try:
            tls_socket = self._previewshield_context.wrap_socket(
                raw_socket,
                server_hostname=self.host,
                do_handshake_on_connect=False,
            )
            watchdog = _SocketDeadline(tls_socket, started, _numeric_timeout(self.timeout))
            tls_socket.do_handshake()
            watchdog.finish()
            self.sock = tls_socket
        except Exception as error:
            if watchdog is not None and watchdog.expired():
                raise TimeoutError("TLS handshake exceeded the network deadline") from error
            raise
        finally:
            if watchdog is not None:
                watchdog.close()
            if self.sock is None:
                (tls_socket or raw_socket).close()


def fetch(
    url: str,
    options: NetworkOptions,
    request_headers: Mapping[str, str] | None = None,
) -> ResponseSnapshot:
    """Fetch response metadata through a direct, DNS-pinned GET request.

    The initial URL and every redirect are independently normalized, resolved, and
    checked against both the hostname allowlist and public-network boundary.  The
    body is deliberately left unread.  Caller-supplied headers are retained only for
    same-origin redirects; cross-origin hops receive fresh tool-owned ``User-Agent``
    and ``Accept`` headers.  Proxy settings from the environment are never consulted.

    Args:
        url: An absolute HTTP(S) URL, or a host/path shorthand that defaults to HTTPS.
        options: Timeout, redirect, and address-safety settings.
        request_headers: Optional caller headers.  Transport framing and ``Host``
            headers are controlled by this module and cannot be overridden.

    Raises:
        NetworkSafetyError: If a URL, request header, or resolved address is unsafe.
        ScanError: If DNS, the connection, TLS, or the HTTP exchange fails.
    """

    if not isinstance(options, NetworkOptions):
        raise TypeError("options must be a NetworkOptions instance")

    started = time.monotonic()
    current = _normalize_url(url)
    _enforce_allowed_host(current.hostname, options.allowed_hosts)
    requested_url = current.value
    headers = _prepare_request_headers(request_headers, options.user_agent)
    cross_origin_headers: _RequestHeaders = (
        ("User-Agent", options.user_agent),
        ("Accept", "*/*"),
    )
    redirects: list[RedirectHop] = []
    visited = {current.value}
    tls_context: ssl.SSLContext | None = None

    while True:
        _remaining_timeout(started, options.timeout, current.hostname)
        addresses = _resolve(current.hostname, current.port, options.allow_private)
        if current.scheme == "https" and tls_context is None:
            tls_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)

        remaining = _remaining_timeout(started, options.timeout, current.hostname)
        response = _request_once(current, addresses, headers, remaining, tls_context)
        location = _redirect_location(response)
        if location is None:
            elapsed_ms = max(0, round((time.monotonic() - started) * 1000))
            return ResponseSnapshot(
                requested_url=requested_url,
                final_url=current.value,
                status_code=response.status_code,
                reason=response.reason,
                headers=response.headers,
                resolved_ip=response.resolved_ip,
                elapsed_ms=elapsed_ms,
                redirects=tuple(redirects),
                tls=response.tls,
            )

        if len(redirects) >= options.max_redirects:
            raise ScanError(
                f"Redirect limit exceeded while scanning '{current.hostname}' "
                f"(maximum {options.max_redirects})."
            )

        redirect_url, _fragment = urldefrag(urljoin(current.value, location))
        next_url = _normalize_url(redirect_url, allow_shorthand=False)
        _enforce_allowed_host(next_url.hostname, options.allowed_hosts)
        if next_url.value in visited:
            raise ScanError(f"Redirect loop detected while scanning '{current.hostname}'.")

        redirects.append(
            RedirectHop(
                url=current.value,
                status_code=response.status_code,
                location=next_url.value,
                resolved_ip=response.resolved_ip,
            )
        )
        visited.add(next_url.value)
        if current.origin != next_url.origin:
            headers = cross_origin_headers
        current = next_url


def _normalize_url(url: str, *, allow_shorthand: bool = True) -> _NormalizedURL:
    parsed = _parse_url(url, allow_shorthand=allow_shorthand)
    scheme = parsed.scheme.lower()
    try:
        port_value = parsed.port
    except ValueError as error:
        raise NetworkSafetyError("Target URL has an invalid authority or port.") from error

    hostname = _normalize_hostname(parsed.hostname or "")
    port = port_value if port_value is not None else (443 if scheme == "https" else 80)
    if not 1 <= port <= _MAX_PORT:
        raise NetworkSafetyError("Target URL port must be between 1 and 65535.")

    path = parsed.path or "/"
    if _INVALID_PERCENT_ESCAPE.search(path) or _INVALID_PERCENT_ESCAPE.search(parsed.query):
        raise NetworkSafetyError("Target URL contains an invalid percent escape.")
    normalized_path = quote(path, safe="/%:@!$&'()*+,;=-._~")
    normalized_query = quote(parsed.query, safe="%:@!$&'()*+,;=/?-._~")
    request_target = normalized_path
    if normalized_query:
        request_target = f"{request_target}?{normalized_query}"

    url_host = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 443 if scheme == "https" else 80
    netloc = url_host if port == default_port else f"{url_host}:{port}"
    normalized = urlunsplit((scheme, netloc, normalized_path, normalized_query, ""))
    return _NormalizedURL(normalized, scheme, hostname, port, request_target)


def _parse_url(url: str, *, allow_shorthand: bool) -> SplitResult:
    if not isinstance(url, str):
        raise NetworkSafetyError("Target URL must be a string.")
    if not url or url != url.strip():
        raise NetworkSafetyError("Target URL must not be empty or contain outer whitespace.")
    if len(url) > _MAX_URL_LENGTH:
        raise NetworkSafetyError(f"Target URL exceeds {_MAX_URL_LENGTH} characters.")
    if _UNSAFE_URL_CHARACTER.search(url) or "\\" in url:
        raise NetworkSafetyError("Target URL contains an unsafe character.")
    if "#" in url:
        raise NetworkSafetyError("URL fragments are not allowed.")

    candidate = url
    if allow_shorthand and "://" not in candidate:
        candidate = f"https://{candidate}"

    try:
        parsed = urlsplit(candidate)
    except (UnicodeError, ValueError) as error:
        raise NetworkSafetyError("Target URL has an invalid authority or port.") from error

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise NetworkSafetyError("Only http:// and https:// URLs are allowed.")
    if not parsed.netloc or parsed.hostname is None:
        raise NetworkSafetyError("Target URL must include a hostname.")
    if parsed.username is not None or parsed.password is not None:
        raise NetworkSafetyError("Credentials in target URLs are not allowed.")
    if parsed.netloc.endswith(":"):
        raise NetworkSafetyError("Target URL has an empty port.")
    if parsed.fragment:
        raise NetworkSafetyError("URL fragments are not allowed.")
    return parsed


def _normalize_hostname(hostname: str) -> str:
    try:
        return _shared_normalize_hostname(hostname)
    except ValueError as error:
        raise NetworkSafetyError(str(error)) from error


def _normalize_allowed_hosts(patterns: tuple[str, ...]) -> tuple[str, ...]:
    normalized: list[str] = []
    for pattern in patterns:
        if not isinstance(pattern, str) or not pattern:
            raise ValueError("allowed_hosts entries must be non-empty strings")
        wildcard = pattern.startswith("*.")
        raw_hostname = pattern[2:] if wildcard else pattern
        if "*" in raw_hostname:
            raise ValueError(f"Invalid allowed host pattern: {pattern!r}")
        try:
            hostname = _normalize_hostname(raw_hostname)
        except NetworkSafetyError as error:
            raise ValueError(f"Invalid allowed host pattern: {pattern!r}") from error
        if wildcard:
            try:
                ipaddress.ip_address(hostname)
            except ValueError:
                normalized_pattern = f"*.{hostname}"
            else:
                raise ValueError("Wildcard allowed_hosts entries cannot target IP addresses")
        else:
            normalized_pattern = hostname
        if normalized_pattern not in normalized:
            normalized.append(normalized_pattern)
    return tuple(normalized)


def _enforce_allowed_host(hostname: str, allowed_hosts: tuple[str, ...]) -> None:
    if not allowed_hosts:
        return
    for allowed in allowed_hosts:
        if allowed.startswith("*."):
            suffix = allowed[1:]
            if hostname.endswith(suffix) and hostname != suffix[1:]:
                return
        elif hostname == allowed:
            return
    raise NetworkSafetyError(f"Target host '{hostname}' is not in the configured allowlist.")


def _prepare_request_headers(
    request_headers: Mapping[str, str] | None,
    user_agent: str,
) -> _RequestHeaders:
    prepared: list[tuple[str, str]] = []
    seen: set[str] = set()
    if request_headers is not None:
        if not isinstance(request_headers, Mapping):
            raise NetworkSafetyError("Request headers must be a string mapping.")
        for name, value in request_headers.items():
            if not isinstance(name, str) or not _HEADER_NAME.fullmatch(name):
                raise NetworkSafetyError("A request header has an invalid name.")
            lowered = name.lower()
            if lowered in _FORBIDDEN_REQUEST_HEADERS:
                raise NetworkSafetyError(f"Request header '{name}' cannot be overridden.")
            if not isinstance(value, str):
                raise NetworkSafetyError(f"Request header '{name}' must have a string value.")
            try:
                _validate_header_value(value, label=f"request header '{name}'")
            except ValueError as error:
                raise NetworkSafetyError(str(error)) from error
            prepared.append((name, value))
            seen.add(lowered)

    if "user-agent" not in seen:
        prepared.append(("User-Agent", user_agent))
    if "accept" not in seen:
        prepared.append(("Accept", "*/*"))
    return tuple(prepared)


def _validate_header_value(value: str, *, label: str) -> None:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    if len(value) > _MAX_HEADER_VALUE_LENGTH:
        raise ValueError(f"{label} exceeds {_MAX_HEADER_VALUE_LENGTH} characters")
    if _CONTROL_CHARACTER.search(value):
        raise ValueError(f"{label} contains a control character")
    try:
        value.encode("latin-1")
    except UnicodeEncodeError as error:
        raise ValueError(f"{label} must contain ISO-8859-1 characters only") from error


def _resolve(hostname: str, port: int, allow_private: bool) -> tuple[_ResolvedAddress, ...]:
    try:
        results = socket.getaddrinfo(
            hostname,
            port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except (OSError, UnicodeError) as error:
        raise ScanError(f"DNS resolution failed for '{hostname}'.") from error

    addresses: list[_ResolvedAddress] = []
    seen: set[tuple[socket.AddressFamily, _SocketAddress]] = set()
    for family_value, socket_type, protocol, _canonical_name, raw_sockaddr in results:
        if socket_type != socket.SOCK_STREAM or protocol not in {0, socket.IPPROTO_TCP}:
            continue
        if family_value not in {socket.AF_INET, socket.AF_INET6}:
            continue
        family = socket.AddressFamily(family_value)
        sockaddr = _validated_sockaddr(family, raw_sockaddr, port)
        ip_text = sockaddr[0]
        try:
            address = ipaddress.ip_address(ip_text)
        except ValueError as error:
            raise ScanError(f"DNS returned an invalid address for '{hostname}'.") from error
        if (family == socket.AF_INET) != isinstance(address, ipaddress.IPv4Address):
            raise ScanError(f"DNS returned an address-family mismatch for '{hostname}'.")
        if not allow_private and _is_non_public(address):
            raise NetworkSafetyError(
                f"Target '{hostname}' resolved to blocked address '{address.compressed}'."
            )
        key = (family, sockaddr)
        if key not in seen:
            seen.add(key)
            addresses.append(_ResolvedAddress(address.compressed, family, sockaddr))

    if not addresses:
        raise ScanError(f"DNS resolution returned no usable addresses for '{hostname}'.")
    return tuple(addresses)


def _validated_sockaddr(
    family: socket.AddressFamily,
    raw_sockaddr: Any,
    expected_port: int,
) -> _SocketAddress:
    if not isinstance(raw_sockaddr, tuple):
        raise ScanError("DNS returned a malformed socket address.")
    if family == socket.AF_INET:
        if len(raw_sockaddr) < _IPV4_SOCKADDR_LENGTH or not isinstance(raw_sockaddr[0], str):
            raise ScanError("DNS returned a malformed IPv4 socket address.")
        if raw_sockaddr[1] != expected_port:
            raise ScanError("DNS returned an unexpected destination port.")
        return raw_sockaddr[0], expected_port
    if len(raw_sockaddr) < _IPV6_SOCKADDR_LENGTH or not isinstance(raw_sockaddr[0], str):
        raise ScanError("DNS returned a malformed IPv6 socket address.")
    if raw_sockaddr[1] != expected_port:
        raise ScanError("DNS returned an unexpected destination port.")
    flow_info = raw_sockaddr[2]
    scope_id = raw_sockaddr[3]
    if not isinstance(flow_info, int) or not isinstance(scope_id, int):
        raise ScanError("DNS returned a malformed IPv6 socket address.")
    return raw_sockaddr[0], expected_port, flow_info, scope_id


def _is_non_public(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(address, ipaddress.IPv6Address):
        if address.is_site_local:
            return True
        mapped = address.ipv4_mapped
        if mapped is not None and _is_non_public(mapped):
            return True
        six_to_four = address.sixtofour
        if six_to_four is not None and _is_non_public(six_to_four):
            return True
        teredo = address.teredo
        if teredo is not None and any(_is_non_public(item) for item in teredo):
            return True
    return (
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        or not address.is_global
    )


def _connect_pinned(
    addresses: Sequence[_ResolvedAddress],
    timeout: float | object,
) -> tuple[socket.socket, str]:
    numeric_timeout = _numeric_timeout(timeout)
    started = time.monotonic()
    last_error: OSError | None = None
    for address in addresses:
        remaining = numeric_timeout - (time.monotonic() - started)
        if remaining <= 0:
            raise TimeoutError("pinned connection timed out")
        sock = socket.socket(address.family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        try:
            sock.settimeout(remaining)
            sock.connect(address.sockaddr)
        except OSError as error:
            last_error = error
            sock.close()
            continue
        return sock, address.ip
    if last_error is not None:
        raise last_error
    raise OSError("no pinned address was available")


def _numeric_timeout(timeout: float | object) -> float:
    return float(timeout) if isinstance(timeout, (int, float)) else _DEFAULT_TIMEOUT


def _request_once(
    target: _NormalizedURL,
    addresses: Sequence[_ResolvedAddress],
    request_headers: _RequestHeaders,
    timeout: float,
    tls_context: ssl.SSLContext | None,
) -> _ResponseMetadata:
    try:
        return _perform_request(target, addresses, request_headers, timeout, tls_context)
    except ssl.SSLCertVerificationError as error:
        raise ScanError(f"TLS certificate verification failed for '{target.hostname}'.") from error
    except ssl.SSLError as error:
        raise ScanError(f"TLS connection failed for '{target.hostname}'.") from error
    except TimeoutError as error:
        raise ScanError(f"Request timed out while scanning '{target.hostname}'.") from error
    except http.client.HTTPException as error:
        raise ScanError(f"Invalid HTTP response from '{target.hostname}'.") from error
    except OSError as error:
        raise ScanError(f"Connection failed for '{target.host_header}'.") from error


def _perform_request(
    target: _NormalizedURL,
    addresses: Sequence[_ResolvedAddress],
    request_headers: _RequestHeaders,
    timeout: float,
    tls_context: ssl.SSLContext | None,
) -> _ResponseMetadata:
    connection: _PinnedHTTPConnection | _PinnedHTTPSConnection
    response: http.client.HTTPResponse | None = None
    watchdog: _SocketDeadline | None = None
    connection = _build_connection(target, addresses, timeout, tls_context)
    started = time.monotonic()
    try:
        connection.connect()
        connected_socket = connection.sock
        if connected_socket is None:  # pragma: no cover - guaranteed by connect()
            raise OSError("connection socket is unavailable")
        watchdog = _SocketDeadline(connected_socket, started, timeout)
        tls_info = _capture_tls(connected_socket)
        connection.putrequest(
            "GET",
            target.request_target,
            skip_host=True,
            skip_accept_encoding=True,
        )
        connection.putheader("Host", target.host_header)
        for name, value in request_headers:
            connection.putheader(name, value)
        connection.putheader("Connection", "close")
        connection.endheaders()
        _set_remaining_socket_timeout(connection.sock, started, timeout)
        response = connection.getresponse()

        response_headers = response.getheaders()
        header_bytes = sum(len(name) + len(value) + 4 for name, value in response_headers)
        if header_bytes > _MAX_RESPONSE_HEADER_BYTES:
            raise ScanError(
                "HTTP response headers exceed the "
                f"{_MAX_RESPONSE_HEADER_BYTES}-byte limit for '{target.hostname}'."
            )

        bag = MutableHeaderBag()
        for name, value in response_headers:
            bag.add(name, value)
        connected_ip = connection.connected_ip
        if connected_ip is None:  # pragma: no cover - guaranteed by connect()
            raise ScanError("Pinned connection did not report its destination address.")
        metadata = _ResponseMetadata(
            status_code=response.status,
            reason=str(response.reason or ""),
            headers=bag.freeze(),
            resolved_ip=connected_ip,
            tls=tls_info,
        )
        watchdog.finish()
        return metadata
    except (OSError, http.client.HTTPException) as error:
        if watchdog is not None and watchdog.expired():
            raise TimeoutError("HTTP exchange exceeded the network deadline") from error
        raise
    finally:
        if watchdog is not None:
            watchdog.close()
        if response is not None:
            response.close()
        connection.close()


def _build_connection(
    target: _NormalizedURL,
    addresses: Sequence[_ResolvedAddress],
    timeout: float,
    tls_context: ssl.SSLContext | None,
) -> _PinnedHTTPConnection | _PinnedHTTPSConnection:
    if target.scheme == "https":
        if tls_context is None:  # pragma: no cover - fetch always creates it
            raise ScanError("TLS context is unavailable.")
        return _PinnedHTTPSConnection(
            target.hostname,
            target.port,
            addresses,
            timeout,
            tls_context,
        )
    return _PinnedHTTPConnection(
        target.hostname,
        target.port,
        addresses,
        timeout,
    )


def _remaining_timeout(started: float, timeout: float, hostname: str) -> float:
    remaining = timeout - (time.monotonic() - started)
    if remaining <= 0:
        raise ScanError(f"Request timed out while scanning '{hostname}'.")
    return remaining


def _set_remaining_socket_timeout(
    sock: socket.socket | None,
    started: float,
    timeout: float,
) -> None:
    if sock is None:
        raise OSError("connection socket is unavailable")
    remaining = timeout - (time.monotonic() - started)
    if remaining <= 0:
        raise TimeoutError("HTTP exchange timed out")
    sock.settimeout(remaining)


def _redirect_location(response: _ResponseMetadata) -> str | None:
    if response.status_code not in _REDIRECT_STATUSES:
        return None
    values = response.headers.get("location", ())
    return values[-1] if values else None


def _capture_tls(sock: socket.socket | None) -> TLSInfo | None:
    if not isinstance(sock, ssl.SSLSocket):
        return None

    cipher_details = sock.cipher()
    certificate: Mapping[str, object] = sock.getpeercert() or {}
    expires_at: str | None = None
    days_remaining: int | None = None
    not_after = certificate.get("notAfter")
    if isinstance(not_after, str):
        try:
            expiry = datetime.fromtimestamp(
                ssl.cert_time_to_seconds(not_after),
                tz=timezone.utc,
            )
        except (OverflowError, ValueError):
            pass
        else:
            expires_at = expiry.replace(microsecond=0).isoformat().replace("+00:00", "Z")
            days_remaining = math.floor(
                (expiry - datetime.now(timezone.utc)).total_seconds() / 86_400
            )

    return TLSInfo(
        version=sock.version(),
        cipher=cipher_details[0] if cipher_details else None,
        certificate_subject=_format_certificate_name(certificate.get("subject")),
        certificate_issuer=_format_certificate_name(certificate.get("issuer")),
        certificate_expires_at=expires_at,
        certificate_days_remaining=days_remaining,
    )


def _format_certificate_name(value: object) -> str | None:
    if not isinstance(value, tuple):
        return None
    parts: list[str] = []
    for relative_name in value:
        if not isinstance(relative_name, tuple):
            continue
        parts.extend(
            f"{attribute[0]}={attribute[1]}"
            for attribute in relative_name
            if (
                isinstance(attribute, tuple)
                and len(attribute) == _CERTIFICATE_ATTRIBUTE_LENGTH
                and isinstance(attribute[0], str)
                and isinstance(attribute[1], str)
            )
        )
    return ", ".join(parts) or None


__all__ = ["NetworkOptions", "fetch"]
