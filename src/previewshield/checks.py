"""Deterministic, policy-aware security checks for HTTP response snapshots."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

from previewshield.models import Finding, ResponseSnapshot, Severity
from previewshield.policy import Policy, RequiredHeaderPolicy
from previewshield.utils import clean_text

OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/"
MDN_HEADERS = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers"
MDN_COOKIES = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Cookies"
MDN_CSP = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP"
MDN_CORS = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS"
OWASP_TLS = (
    "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html"
)


@dataclass(frozen=True)
class Rule:
    """Stable metadata for one built-in check."""

    rule_id: str
    title: str
    severity: Severity
    category: str
    remediation: str
    references: tuple[str, ...]


def _rule(
    rule_id: str,
    title: str,
    severity: Severity,
    category: str,
    remediation: str,
    *references: str,
) -> Rule:
    return Rule(rule_id, title, severity, category, remediation, tuple(references))


RULES: dict[str, Rule] = {
    item.rule_id: item
    for item in (
        _rule(
            "PS0001",
            "Insecure HTTP transport",
            Severity.HIGH,
            "transport",
            "Serve the target exclusively over HTTPS and redirect HTTP at the edge.",
            OWASP_TLS,
        ),
        _rule(
            "PS0002",
            "HTTPS redirect downgrade",
            Severity.CRITICAL,
            "transport",
            "Remove redirects from HTTPS to HTTP and keep the complete chain encrypted.",
            OWASP_TLS,
        ),
        _rule(
            "PS1001",
            "Strict-Transport-Security is missing",
            Severity.HIGH,
            "headers",
            "Send Strict-Transport-Security on HTTPS responses with an appropriate max-age.",
            OWASP_HEADERS,
        ),
        _rule(
            "PS1002",
            "Strict-Transport-Security is weak or invalid",
            Severity.MEDIUM,
            "headers",
            "Use a valid HSTS max-age that meets the project policy.",
            OWASP_HEADERS,
        ),
        _rule(
            "PS1101",
            "Enforced Content-Security-Policy is missing",
            Severity.HIGH,
            "content-security",
            "Deploy an enforcing Content-Security-Policy; report-only mode is not enforcement.",
            MDN_CSP,
        ),
        _rule(
            "PS1102",
            "Content-Security-Policy permits unsafe-eval",
            Severity.HIGH,
            "content-security",
            "Remove 'unsafe-eval' and migrate evaluated code to static scripts.",
            MDN_CSP,
        ),
        _rule(
            "PS1103",
            "Content-Security-Policy permits unsafe inline code",
            Severity.MEDIUM,
            "content-security",
            "Replace 'unsafe-inline' with nonces or hashes and a strict CSP.",
            MDN_CSP,
        ),
        _rule(
            "PS1104",
            "Content-Security-Policy contains a broad wildcard",
            Severity.MEDIUM,
            "content-security",
            "Replace wildcard sources with the smallest explicit source allowlist.",
            MDN_CSP,
        ),
        _rule(
            "PS1105",
            "Content-Security-Policy lacks a safe default-src",
            Severity.MEDIUM,
            "content-security",
            "Add a restrictive default-src directive, commonly default-src 'self'.",
            MDN_CSP,
        ),
        _rule(
            "PS1106",
            "Content-Security-Policy does not block object embedding",
            Severity.MEDIUM,
            "content-security",
            "Add object-src 'none' to the enforced Content-Security-Policy.",
            MDN_CSP,
        ),
        _rule(
            "PS1107",
            "Content-Security-Policy lacks base-uri protection",
            Severity.LOW,
            "content-security",
            "Add base-uri 'none' or a narrowly scoped base-uri directive.",
            MDN_CSP,
        ),
        _rule(
            "PS1201",
            "Clickjacking protection is missing",
            Severity.HIGH,
            "headers",
            "Set CSP frame-ancestors and optionally X-Frame-Options for older clients.",
            OWASP_HEADERS,
        ),
        _rule(
            "PS1202",
            "X-Content-Type-Options is missing or invalid",
            Severity.MEDIUM,
            "headers",
            "Send X-Content-Type-Options: nosniff.",
            OWASP_HEADERS,
        ),
        _rule(
            "PS1203",
            "Referrer-Policy is missing or unsafe",
            Severity.LOW,
            "privacy",
            "Set a restrictive Referrer-Policy such as strict-origin-when-cross-origin.",
            OWASP_HEADERS,
        ),
        _rule(
            "PS1204",
            "Permissions-Policy is missing",
            Severity.LOW,
            "privacy",
            "Explicitly disable browser capabilities the application does not need.",
            OWASP_HEADERS,
        ),
        _rule(
            "PS1205",
            "Deprecated X-XSS-Protection is enabled",
            Severity.INFO,
            "headers",
            (
                "Prefer Content-Security-Policy and send X-XSS-Protection: 0 "
                "if the header is retained."
            ),
            OWASP_HEADERS,
        ),
        _rule(
            "PS1301",
            "Credentialed wildcard CORS policy is invalid",
            Severity.MEDIUM,
            "cors",
            "Do not combine a wildcard allowed origin with credentials; allow explicit origins.",
            MDN_CORS,
        ),
        _rule(
            "PS1302",
            "CORS trusts a broad or opaque origin",
            Severity.HIGH,
            "cors",
            "Allow only explicitly trusted origins and avoid the null origin.",
            MDN_CORS,
        ),
        _rule(
            "PS1303",
            "Specific CORS response may need Vary: Origin",
            Severity.INFO,
            "cors",
            "If the allowed origin is selected dynamically, add Origin to the Vary header.",
            MDN_CORS,
        ),
        _rule(
            "PS1401",
            "Cookie lacks the Secure attribute",
            Severity.MEDIUM,
            "cookies",
            "Mark security-sensitive cookies Secure so browsers send them only over HTTPS.",
            MDN_COOKIES,
        ),
        _rule(
            "PS1402",
            "Cookie lacks the HttpOnly attribute",
            Severity.LOW,
            "cookies",
            "Mark cookies that do not require JavaScript access as HttpOnly.",
            MDN_COOKIES,
        ),
        _rule(
            "PS1403",
            "Cookie lacks a valid SameSite attribute",
            Severity.LOW,
            "cookies",
            "Set SameSite=Lax or SameSite=Strict unless cross-site use is required.",
            MDN_COOKIES,
        ),
        _rule(
            "PS1404",
            "SameSite=None cookie is not Secure",
            Severity.HIGH,
            "cookies",
            "Cookies using SameSite=None must also use Secure.",
            MDN_COOKIES,
        ),
        _rule(
            "PS1405",
            "Cookie prefix contract is violated",
            Severity.HIGH,
            "cookies",
            "Honor __Secure- and __Host- cookie prefix requirements.",
            MDN_COOKIES,
        ),
        _rule(
            "PS1501",
            "Legacy TLS protocol is in use",
            Severity.CRITICAL,
            "tls",
            "Require TLS 1.2 or newer and disable SSL and legacy TLS versions.",
            OWASP_TLS,
        ),
        _rule(
            "PS1502",
            "TLS certificate is expired or near expiry",
            Severity.HIGH,
            "tls",
            "Renew the certificate and automate renewal monitoring.",
            OWASP_TLS,
        ),
        _rule(
            "PS1503",
            "Weak TLS cipher is in use",
            Severity.HIGH,
            "tls",
            "Configure modern AEAD cipher suites and remove legacy ciphers.",
            OWASP_TLS,
        ),
        _rule(
            "PS1601",
            "Technology details are exposed",
            Severity.LOW,
            "information-disclosure",
            "Remove or minimize Server and X-Powered-By response headers.",
            OWASP_HEADERS,
        ),
        _rule(
            "PS1602",
            "Server error response was scanned",
            Severity.HIGH,
            "availability",
            "Fix the server error before treating this route as a valid security baseline.",
            MDN_HEADERS,
        ),
        _rule(
            "PS1603",
            "Client error response was scanned",
            Severity.MEDIUM,
            "availability",
            "Confirm the route and authentication setup so the intended response is assessed.",
            MDN_HEADERS,
        ),
    )
}

_CSP_DIRECTIVE = re.compile(r"^([a-z][a-z0-9-]*)\s*(.*)$", re.IGNORECASE)
_DIRECTIVE_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_CSP_NONCE_OR_HASH = re.compile(
    r"^'(?:nonce-[a-z0-9+/_-]+={0,2}|sha(?:256|384|512)-[a-z0-9+/_-]+={0,2})'$",
    re.IGNORECASE,
)
_CSP_SCHEME_WILDCARD = re.compile(r"^[a-z][a-z0-9+.-]*://\*", re.IGNORECASE)
_CSP_ANY_HOST_SOURCE = re.compile(
    r"^[a-z][a-z0-9+.-]*://\*(?::(?:\d+|\*))?(?:/.*)?$",
    re.IGNORECASE,
)
_CSP_ENFORCING_DIRECTIVES = frozenset(
    {
        "base-uri",
        "child-src",
        "connect-src",
        "default-src",
        "fenced-frame-src",
        "font-src",
        "form-action",
        "frame-ancestors",
        "frame-src",
        "img-src",
        "manifest-src",
        "media-src",
        "object-src",
        "require-trusted-types-for",
        "sandbox",
        "script-src",
        "script-src-attr",
        "script-src-elem",
        "style-src",
        "style-src-attr",
        "style-src-elem",
        "trusted-types",
        "upgrade-insecure-requests",
        "worker-src",
    }
)
_WEAK_CIPHER_MARKERS = ("3DES", "DES-CBC", "RC4", "NULL", "EXPORT", "MD5")
_HSTS_SATURATED_MAX_AGE = 1_000_000_000_000
_MAX_HSTS_AGE_DIGITS = 12
_MIN_QUOTED_LENGTH = 2
_ASCII_CONTROL_BOUNDARY = 32
_NO_REPRESENTATION_STATUSES = frozenset({204, 205, 304})
_REFERRER_POLICIES = frozenset(
    {
        "no-referrer",
        "no-referrer-when-downgrade",
        "origin",
        "origin-when-cross-origin",
        "same-origin",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url",
    }
)
CLIENT_ERROR_STATUS = 400
SERVER_ERROR_STATUS = 500


def evaluate(snapshot: ResponseSnapshot, policy: Policy) -> tuple[Finding, ...]:
    """Evaluate every enabled rule against one captured response."""

    findings: list[Finding] = []
    _check_transport(snapshot, policy, findings)
    _check_hsts(snapshot, policy, findings)
    is_document = _is_document_response(snapshot)
    directives = _check_csp(snapshot, policy, findings) if is_document else {}
    _check_browser_headers(snapshot, policy, directives, findings, is_document=is_document)
    _check_cors(snapshot, policy, findings)
    _check_cookies(snapshot, policy, findings)
    _check_tls(snapshot, policy, findings)
    _check_response_health(snapshot, policy, findings)
    _check_required_headers(snapshot, policy, findings)
    return tuple(findings)


def _emit(  # noqa: PLR0913 - centralizes policy application for all observations
    output: list[Finding],
    policy: Policy,
    snapshot: ResponseSnapshot,
    rule_id: str,
    message: str,
    *,
    subject: str = "response",
    evidence: str | None = None,
    severity: Severity | None = None,
) -> None:
    if not policy.rule_enabled(rule_id):
        return
    rule = RULES[rule_id]
    effective = policy.severity_for(rule_id, severity or rule.severity)
    output.append(
        Finding(
            rule_id=rule.rule_id,
            title=rule.title,
            severity=effective,
            category=rule.category,
            message=message,
            remediation=rule.remediation,
            target=snapshot.requested_url,
            subject=subject,
            evidence=clean_text(evidence, limit=300) if evidence else None,
            references=rule.references,
        )
    )


def _check_transport(snapshot: ResponseSnapshot, policy: Policy, output: list[Finding]) -> None:
    requested_scheme = urlsplit(snapshot.requested_url).scheme.lower()
    final_scheme = urlsplit(snapshot.final_url).scheme.lower()
    if requested_scheme != "https" or final_scheme != "https":
        _emit(
            output,
            policy,
            snapshot,
            "PS0001",
            "The requested route is not protected by end-to-end HTTPS.",
            evidence=(
                f"requested={requested_scheme or 'unknown'}, final={final_scheme or 'unknown'}"
            ),
        )
    for index, hop in enumerate(snapshot.redirects, start=1):
        if (
            urlsplit(hop.url).scheme.lower() == "https"
            and urlsplit(hop.location).scheme.lower() == "http"
        ):
            _emit(
                output,
                policy,
                snapshot,
                "PS0002",
                "The redirect chain moves from HTTPS to plaintext HTTP.",
                subject=f"redirect:{index}",
                evidence=f"hop {index}: HTTPS to HTTP",
            )


def _check_hsts(snapshot: ResponseSnapshot, policy: Policy, output: list[Finding]) -> None:
    parsed_url = urlsplit(snapshot.final_url)
    if parsed_url.scheme.lower() != "https":
        return
    try:
        ipaddress.ip_address(parsed_url.hostname or "")
    except ValueError:
        pass
    else:
        return
    values = snapshot.header_values("strict-transport-security")
    if not values:
        _emit(output, policy, snapshot, "PS1001", "The HTTPS response has no HSTS policy.")
        return
    max_age = _parse_hsts_max_age(values[0])
    if max_age is None:
        _emit(
            output,
            policy,
            snapshot,
            "PS1002",
            "The HSTS header has no valid max-age directive.",
            evidence="max-age is missing or invalid",
            severity=Severity.HIGH,
        )
        return
    if max_age < policy.min_hsts_max_age:
        _emit(
            output,
            policy,
            snapshot,
            "PS1002",
            "The HSTS lifetime is shorter than the configured minimum.",
            evidence=f"max-age={max_age}; required>={policy.min_hsts_max_age}",
            severity=Severity.HIGH if max_age == 0 else None,
        )


def _check_csp(
    snapshot: ResponseSnapshot, policy: Policy, output: list[Finding]
) -> dict[str, tuple[str, ...]]:
    values = snapshot.header_values("content-security-policy")
    if not values:
        report_only = bool(snapshot.header_values("content-security-policy-report-only"))
        _emit(
            output,
            policy,
            snapshot,
            "PS1101",
            "Only a report-only CSP is present." if report_only else "No enforced CSP is present.",
            evidence="report-only policy detected" if report_only else None,
        )
        return {}

    directives = _parse_csp(values)
    if not _CSP_ENFORCING_DIRECTIVES.intersection(directives):
        _emit(
            output,
            policy,
            snapshot,
            "PS1101",
            "The CSP header contains no recognized enforcing directive.",
            evidence="empty or ineffective CSP header",
        )
        return {}
    all_sources = tuple(source for sources in directives.values() for source in sources)
    if "'unsafe-eval'" in all_sources:
        _emit(
            output,
            policy,
            snapshot,
            "PS1102",
            "An enforced CSP source list contains 'unsafe-eval'.",
            evidence="unsafe-eval",
        )
    if any(
        "'unsafe-inline'" in sources and not _has_nonce_or_hash(sources)
        for sources in directives.values()
    ):
        _emit(
            output,
            policy,
            snapshot,
            "PS1103",
            "Inline script or style execution is broadly allowed without a nonce or hash.",
            evidence="unsafe-inline without nonce/hash",
        )
    if any(_is_wildcard_source(source) for source in all_sources):
        _emit(
            output,
            policy,
            snapshot,
            "PS1104",
            "An enforced CSP directive trusts a wildcard source.",
            evidence="wildcard source",
        )
    if "default-src" not in directives:
        _emit(
            output,
            policy,
            snapshot,
            "PS1105",
            "The enforced CSP does not define a restrictive default-src fallback.",
        )
    object_sources = tuple(token.lower() for token in directives.get("object-src", ()))
    if "object-src" not in directives or object_sources not in {(), ("'none'",)}:
        _emit(
            output,
            policy,
            snapshot,
            "PS1106",
            "The enforced CSP does not set object-src 'none'.",
        )
    if "base-uri" not in directives:
        _emit(
            output,
            policy,
            snapshot,
            "PS1107",
            "The enforced CSP does not constrain document base URLs.",
        )
    return directives


def _parse_csp(values: Iterable[str]) -> dict[str, tuple[str, ...]]:
    parsed: dict[str, list[str]] = {}
    for value in values:
        for raw_directive in value.split(";"):
            match = _CSP_DIRECTIVE.match(raw_directive.strip())
            if match is None:
                continue
            name = match.group(1).lower()
            if name in parsed:
                continue
            sources = match.group(2).split()
            parsed[name] = [source.lower() for source in sources]
    return {name: tuple(sources) for name, sources in parsed.items()}


def _has_nonce_or_hash(sources: Iterable[str]) -> bool:
    return any(_CSP_NONCE_OR_HASH.fullmatch(source) is not None for source in sources)


def _is_wildcard_source(source: str) -> bool:
    return (
        source == "*" or source.startswith("*.") or _CSP_SCHEME_WILDCARD.match(source) is not None
    )


def _parse_hsts_max_age(value: str) -> int | None:
    seen: set[str] = set()
    max_age: int | None = None
    for raw_directive in value.split(";"):
        directive = raw_directive.strip()
        if not directive:
            continue
        raw_name, separator, raw_value = directive.partition("=")
        name = raw_name.strip().lower()
        if not _DIRECTIVE_TOKEN.fullmatch(name) or name in seen:
            return None
        seen.add(name)
        directive_value = raw_value.strip()
        if name == "max-age":
            if not separator:
                return None
            if directive_value.startswith('"') and directive_value.endswith('"'):
                directive_value = directive_value[1:-1]
            if not directive_value.isascii() or not directive_value.isdigit():
                return None
            significant_digits = directive_value.lstrip("0") or "0"
            max_age = (
                _HSTS_SATURATED_MAX_AGE
                if len(significant_digits) > _MAX_HSTS_AGE_DIGITS
                else int(significant_digits)
            )
        elif name == "includesubdomains":
            if separator:
                return None
        elif separator and not _valid_directive_value(directive_value):
            return None
    return max_age


def _valid_directive_value(value: str) -> bool:
    if _DIRECTIVE_TOKEN.fullmatch(value):
        return True
    if len(value) < _MIN_QUOTED_LENGTH or not value.startswith('"') or not value.endswith('"'):
        return False
    escaped = False
    for character in value[1:-1]:
        if escaped:
            if ord(character) < _ASCII_CONTROL_BOUNDARY and character != "\t":
                return False
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == '"' or (ord(character) < _ASCII_CONTROL_BOUNDARY and character != "\t"):
            return False
    return not escaped


def _check_browser_headers(
    snapshot: ResponseSnapshot,
    policy: Policy,
    csp: dict[str, tuple[str, ...]],
    output: list[Finding],
    *,
    is_document: bool,
) -> None:
    xfo = (snapshot.header("x-frame-options") or "").strip().upper()
    frame_ancestors = csp.get("frame-ancestors")
    broad_frame_sources = {"*", "http:", "https:", "data:"}
    csp_blocks_broad_framing = bool(frame_ancestors) and not any(
        source in broad_frame_sources or _CSP_ANY_HOST_SOURCE.fullmatch(source) is not None
        for source in frame_ancestors or ()
    )
    if is_document and not csp_blocks_broad_framing and xfo not in {"DENY", "SAMEORIGIN"}:
        _emit(
            output,
            policy,
            snapshot,
            "PS1201",
            "Neither CSP frame-ancestors nor a valid X-Frame-Options value prevents framing.",
        )

    nosniff = (snapshot.header("x-content-type-options") or "").strip().lower()
    if snapshot.status_code not in _NO_REPRESENTATION_STATUSES and nosniff != "nosniff":
        _emit(
            output,
            policy,
            snapshot,
            "PS1202",
            "The response does not opt out of MIME type sniffing.",
            evidence=f"value={nosniff}" if nosniff else "header missing",
        )

    if is_document:
        referrer = _effective_referrer_policy(snapshot.header_values("referrer-policy"))
        unsafe_referrers = {"unsafe-url", "no-referrer-when-downgrade"}
        if referrer is None or referrer in unsafe_referrers:
            _emit(
                output,
                policy,
                snapshot,
                "PS1203",
                "The response does not define a sufficiently restrictive referrer policy.",
                evidence="header missing or invalid" if referrer is None else f"value={referrer}",
                severity=Severity.MEDIUM if referrer in unsafe_referrers else None,
            )

        if snapshot.header("permissions-policy") is None:
            _emit(
                output,
                policy,
                snapshot,
                "PS1204",
                "Browser capabilities are not constrained with Permissions-Policy.",
            )

        xss = (snapshot.header("x-xss-protection") or "").strip()
        if xss and xss != "0":
            _emit(
                output,
                policy,
                snapshot,
                "PS1205",
                "A deprecated browser XSS filter is enabled and can create unexpected behavior.",
                evidence=f"value={xss}",
            )


def _is_document_response(snapshot: ResponseSnapshot) -> bool:
    if snapshot.status_code in _NO_REPRESENTATION_STATUSES:
        return False
    content_type = (snapshot.header("content-type") or "").split(";", 1)[0].strip().lower()
    return not content_type or content_type in {
        "text/html",
        "application/xhtml+xml",
        "image/svg+xml",
    }


def _effective_referrer_policy(values: Iterable[str]) -> str | None:
    effective: str | None = None
    for value in values:
        for token in value.split(","):
            normalized = token.strip().lower()
            if normalized in _REFERRER_POLICIES:
                effective = normalized
    return effective


def _check_cors(snapshot: ResponseSnapshot, policy: Policy, output: list[Finding]) -> None:
    origin = (snapshot.header("access-control-allow-origin") or "").strip()
    if not origin:
        return
    credentials = (snapshot.header("access-control-allow-credentials") or "").strip().lower()
    if origin == "*" and credentials == "true":
        _emit(
            output,
            policy,
            snapshot,
            "PS1301",
            "The response advertises credentials while allowing every origin.",
            evidence="allow-origin=*; allow-credentials=true",
        )
    elif origin in {"*", "null"}:
        _emit(
            output,
            policy,
            snapshot,
            "PS1302",
            "The CORS policy trusts an unrestricted or opaque origin.",
            evidence=f"allow-origin={origin}",
            severity=Severity.MEDIUM if origin == "*" else None,
        )
    elif not _vary_contains_origin(snapshot.header_values("vary")):
        _emit(
            output,
            policy,
            snapshot,
            "PS1303",
            "A specific allowed origin is returned without a Vary: Origin cache key; "
            "this matters only when the value is selected dynamically.",
            evidence="Vary does not include Origin",
        )


def _vary_contains_origin(values: Iterable[str]) -> bool:
    return any(
        token.strip().lower() in {"origin", "*"} for value in values for token in value.split(",")
    )


def _check_cookies(snapshot: ResponseSnapshot, policy: Policy, output: list[Finding]) -> None:
    for index, raw_cookie in enumerate(snapshot.header_values("set-cookie"), start=1):
        parsed = _cookie_attributes(raw_cookie)
        if parsed is None:
            continue
        name, attributes = parsed
        subject = f"cookie:{name or index}"
        if "secure" not in attributes:
            _emit(
                output,
                policy,
                snapshot,
                "PS1401",
                "A response cookie can be sent over an unencrypted connection.",
                subject=subject,
                evidence="Secure attribute missing",
            )
        if "httponly" not in attributes:
            _emit(
                output,
                policy,
                snapshot,
                "PS1402",
                "A response cookie is accessible to client-side scripts.",
                subject=subject,
                evidence="HttpOnly attribute missing",
            )
        same_site = attributes.get("samesite")
        if same_site is None or same_site.lower() not in {"lax", "strict", "none"}:
            _emit(
                output,
                policy,
                snapshot,
                "PS1403",
                (
                    "A response cookie relies on browser-default cross-site behavior."
                    if same_site is None
                    else "A response cookie uses an invalid SameSite value."
                ),
                subject=subject,
                evidence=(
                    "SameSite attribute missing"
                    if same_site is None
                    else "SameSite attribute invalid"
                ),
            )
        elif same_site.lower() == "none" and "secure" not in attributes:
            _emit(
                output,
                policy,
                snapshot,
                "PS1404",
                "A cross-site cookie does not meet the browser Secure requirement.",
                subject=subject,
                evidence="SameSite=None without Secure",
            )
        if _cookie_prefix_invalid(name, attributes):
            _emit(
                output,
                policy,
                snapshot,
                "PS1405",
                "The cookie attributes do not satisfy the guarantees promised by its prefix.",
                subject=subject,
                evidence="cookie prefix requirements not met",
            )


def _cookie_attributes(raw_cookie: str) -> tuple[str, dict[str, str]] | None:
    parts = [part.strip() for part in raw_cookie.split(";")]
    if not parts or "=" not in parts[0]:
        return None
    name = clean_text(parts[0].split("=", 1)[0].strip(), limit=100)
    attributes: dict[str, str] = {}
    for part in parts[1:]:
        attribute, separator, value = part.partition("=")
        normalized = attribute.strip().lower()
        if normalized:
            attributes[normalized] = value.strip() if separator else ""
    return name, attributes


def _cookie_prefix_invalid(name: str, attributes: dict[str, str]) -> bool:
    if name.startswith("__Secure-"):
        return "secure" not in attributes
    if name.startswith("__Host-"):
        return "secure" not in attributes or attributes.get("path") != "/" or "domain" in attributes
    return False


def _check_tls(snapshot: ResponseSnapshot, policy: Policy, output: list[Finding]) -> None:
    tls = snapshot.tls
    if tls is None:
        return
    version = (tls.version or "").upper().replace(" ", "")
    if version and version not in {"TLSV1.2", "TLSV1.3"}:
        _emit(
            output,
            policy,
            snapshot,
            "PS1501",
            "The negotiated transport protocol is obsolete.",
            subject="tls",
            evidence=f"version={tls.version}",
        )
    if tls.certificate_days_remaining is not None:
        days = tls.certificate_days_remaining
        if days <= policy.certificate_warning_days:
            _emit(
                output,
                policy,
                snapshot,
                "PS1502",
                "The TLS certificate is expired or approaching its renewal window.",
                subject="certificate",
                evidence=f"days remaining={days}",
                severity=Severity.CRITICAL if days < 0 else None,
            )
    cipher = (tls.cipher or "").upper()
    if cipher and any(marker in cipher for marker in _WEAK_CIPHER_MARKERS):
        _emit(
            output,
            policy,
            snapshot,
            "PS1503",
            "The negotiated cipher contains a known legacy primitive.",
            subject="tls",
            evidence=f"cipher={tls.cipher}",
        )


def _check_response_health(
    snapshot: ResponseSnapshot, policy: Policy, output: list[Finding]
) -> None:
    disclosed = [name for name in ("server", "x-powered-by") if snapshot.header(name) is not None]
    if disclosed:
        _emit(
            output,
            policy,
            snapshot,
            "PS1601",
            "The response exposes implementation or server details.",
            subject="headers",
            evidence=f"present: {', '.join(disclosed)}",
        )
    if snapshot.status_code >= SERVER_ERROR_STATUS:
        _emit(
            output,
            policy,
            snapshot,
            "PS1602",
            "The route returned a server error instead of a stable application response.",
            subject="status",
            evidence=f"status={snapshot.status_code}",
        )
    elif snapshot.status_code >= CLIENT_ERROR_STATUS:
        _emit(
            output,
            policy,
            snapshot,
            "PS1603",
            "The route returned a client error, so the intended page may not have been assessed.",
            subject="status",
            evidence=f"status={snapshot.status_code}",
        )


def _check_required_headers(
    snapshot: ResponseSnapshot, policy: Policy, output: list[Finding]
) -> None:
    for requirement in policy.required_headers:
        if not policy.rule_enabled(requirement.rule_id):
            continue
        value = snapshot.header(requirement.name)
        message = _required_header_failure(requirement, value)
        if message is None:
            continue
        severity = policy.severity_for(requirement.rule_id, requirement.severity)
        output.append(
            Finding(
                rule_id=requirement.rule_id,
                title=f"Required header {requirement.name} is missing or invalid",
                severity=severity,
                category="custom-policy",
                message=message,
                remediation=requirement.remediation,
                target=snapshot.requested_url,
                subject=f"header:{requirement.name.lower()}",
                evidence="header missing" if value is None else "value does not satisfy policy",
                references=(),
            )
        )


def _required_header_failure(requirement: RequiredHeaderPolicy, value: str | None) -> str | None:
    if value is None:
        return f"The project requires the {requirement.name} response header."
    if requirement.exact is not None and value != requirement.exact:
        return f"The {requirement.name} response header does not equal the required value."
    if requirement.contains is not None and requirement.contains not in value:
        return f"The {requirement.name} response header lacks the required fragment."
    return None


__all__ = ["RULES", "Rule", "evaluate"]
