"""Safe, deterministic report rendering for PreviewShield."""

from __future__ import annotations

import hashlib
import importlib
import math
import re
from collections.abc import Callable, Mapping, Sequence
from typing import TypeAlias, cast
from urllib.parse import urlsplit, urlunsplit

from previewshield.models import DiffReport, Finding, FindingDelta, ScanReport
from previewshield.utils import clean_text, markdown_code

Report: TypeAlias = ScanReport | DiffReport
JsonScalar: TypeAlias = str | int | float | bool | None
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
Renderer: TypeAlias = Callable[[Report], str]

EVIDENCE_LIMIT = 240
TEXT_LIMIT = 2_000
REDACTED = "[REDACTED]"

_CANONICAL_FORMATS = ("console", "html", "json", "junit", "markdown", "sarif")
_FORMAT_ALIASES = {
    "md": "markdown",
    "text": "console",
    "txt": "console",
    "xml": "junit",
}
_SENSITIVE_KEY_PARTS = (
    "api-key",
    "apikey",
    "authorization",
    "cookie",
    "credential",
    "csrf",
    "password",
    "passwd",
    "private-key",
    "proxy-authenticate",
    "secret",
    "session",
    "token",
)
_URL_KEYS = {
    "final_url",
    "helpuri",
    "location",
    "requested_url",
    "references",
    "target",
    "url",
}
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"(?i)(\b(?:api[-_ ]?key|access[-_ ]?token|refresh[-_ ]?token|csrf(?:token)?|"
            r"password|passwd|secret|session(?:id)?|token)[\s\"']*[:=][\s\"']*)"
            r"([^\s\"',;&}]+)"
        ),
        rf"\g<1>{REDACTED}",
    ),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+"), rf"\g<1> {REDACTED}"),
    (
        re.compile(r"(?i)(\b(?:set-cookie|cookie|authorization|proxy-authorization)\s*:)\s*.*"),
        rf"\g<1> {REDACTED}",
    ),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
        REDACTED,
    ),
    (
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
        REDACTED,
    ),
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*", re.IGNORECASE),
        REDACTED,
    ),
)
_EMBEDDED_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_FINGERPRINT = re.compile(r"^[a-f0-9]{16,128}$", re.IGNORECASE)


def supported_formats() -> tuple[str, ...]:
    """Return canonical output names in stable order."""

    return _CANONICAL_FORMATS


def render(report: Report, format_name: str) -> str:
    """Render a scan or diff report using a registered output format.

    Short aliases are accepted for CLI ergonomics, while :func:`supported_formats`
    intentionally returns only canonical names.
    """

    normalized = format_name.strip().lower().lstrip(".")
    normalized = _FORMAT_ALIASES.get(normalized, normalized)
    renderers = _load_renderers()
    try:
        renderer = renderers[normalized]
    except KeyError as error:
        choices = ", ".join(_CANONICAL_FORMATS)
        msg = f"Unsupported report format {format_name!r}. Choose one of: {choices}."
        raise ValueError(msg) from error
    return renderer(report)


def _load_renderers() -> dict[str, Renderer]:
    """Import renderers lazily so helper functions remain cycle-free."""

    locations = {
        "console": ("previewshield.reporters.console", "render_console"),
        "html": ("previewshield.reporters.html", "render_html"),
        "json": ("previewshield.reporters.json_report", "render_json"),
        "junit": ("previewshield.reporters.junit", "render_junit"),
        "markdown": ("previewshield.reporters.markdown", "render_markdown"),
        "sarif": ("previewshield.reporters.sarif", "render_sarif"),
    }
    return {
        name: cast(Renderer, getattr(importlib.import_module(module_name), function_name))
        for name, (module_name, function_name) in locations.items()
    }


def _is_sensitive_key(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", "-", key.lower()).strip("-")
    return any(part in normalized for part in _SENSITIVE_KEY_PARTS)


def _redact_embedded_url(match: re.Match[str]) -> str:
    value = match.group(0)
    trailing = ""
    while value and value[-1] in ".,;:!?)]:":
        trailing = value[-1] + trailing
        value = value[:-1]
    return _url_without_secrets(value) + trailing


def _url_without_secrets(value: str) -> str:
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname or ""
        port = parsed.port
    except ValueError:
        return REDACTED

    if not parsed.scheme or not parsed.netloc:
        return value
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    netloc = f"{hostname}:{port}" if port is not None else hostname
    return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))


def _safe_text(value: str, *, limit: int = TEXT_LIMIT) -> str:
    """Normalize one untrusted value, remove common secrets, and cap its size."""

    working_limit = max(limit * 4, TEXT_LIMIT)
    safe = clean_text(str(value), limit=working_limit)
    safe = _EMBEDDED_URL.sub(_redact_embedded_url, safe)
    for pattern, replacement in _SECRET_PATTERNS:
        safe = pattern.sub(replacement, safe)
    safe = clean_text(safe, limit=limit)
    if len(safe) > limit:
        safe = f"{safe[: limit - 1]}…"
    return safe


def _safe_url(value: str, *, limit: int = TEXT_LIMIT) -> str:
    """Remove URL credentials, query parameters, and fragments."""

    return _safe_text(_url_without_secrets(_safe_text(value, limit=limit)), limit=limit)


def _safe_evidence(value: str | None) -> str | None:
    if value is None:
        return None
    return _safe_text(value, limit=EVIDENCE_LIMIT)


def _markdown_value(value: str, *, limit: int = 500) -> str:
    """Return a GFM table-safe code span for an untrusted value."""

    return markdown_code(_safe_text(value, limit=limit)).replace("|", "&#124;")


def _sanitize_primitive(value: object, *, key: str = "") -> JsonValue:
    """Recursively retain a JSON-compatible shape while removing secrets."""

    if value is None or isinstance(value, (bool, int)):
        output: JsonValue = value
    elif isinstance(value, float):
        output = value if math.isfinite(value) else None
    elif isinstance(value, str):
        if key.lower() in _URL_KEYS or key.lower().endswith("_url"):
            output = _safe_url(value)
        else:
            limit = EVIDENCE_LIMIT if key.lower() == "evidence" else TEXT_LIMIT
            output = _safe_text(value, limit=limit)
    elif isinstance(value, Mapping):
        mapped_output: dict[str, JsonValue] = {}
        for raw_key in sorted(value, key=str):
            safe_key = _safe_text(str(raw_key), limit=200)
            item = value[raw_key]
            if _is_sensitive_key(safe_key):
                mapped_output[safe_key] = _redacted_like(item)
            else:
                mapped_output[safe_key] = _sanitize_primitive(item, key=safe_key)
        output = mapped_output
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        output = [_sanitize_primitive(item, key=key) for item in value]
    else:
        output = _safe_text(str(value))
    return output


def _redacted_like(value: object) -> JsonValue:
    """Redact a value without changing its container shape."""

    if isinstance(value, Mapping):
        return {
            _safe_text(str(key), limit=200): _redacted_like(item) for key, item in value.items()
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_redacted_like(item) for item in value]
    return REDACTED


def _finding_sort_key(finding: Finding) -> tuple[int, str, str, str, str]:
    return (
        -finding.severity.rank,
        finding.rule_id.casefold(),
        finding.target.casefold(),
        finding.subject.casefold(),
        finding.fingerprint,
    )


def _sorted_findings(findings: Sequence[Finding]) -> tuple[Finding, ...]:
    return tuple(sorted(findings, key=_finding_sort_key))


def _delta_sort_key(delta: FindingDelta) -> tuple[int, int, str, str, str]:
    kind_order = {"regression": 0, "resolved": 1, "changed": 2, "unchanged": 3}
    finding = delta.finding
    return (
        kind_order[delta.kind.value],
        -finding.severity.rank,
        finding.rule_id.casefold(),
        finding.target.casefold(),
        finding.fingerprint,
    )


def _sorted_deltas(deltas: Sequence[FindingDelta]) -> tuple[FindingDelta, ...]:
    return tuple(sorted(deltas, key=_delta_sort_key))


def _stable_fingerprint(finding: Finding) -> str:
    fingerprint = finding.fingerprint
    if _FINGERPRINT.fullmatch(fingerprint):
        return fingerprint.lower()
    source = f"{finding.rule_id}\x1f{finding.target}\x1f{finding.subject}"
    return hashlib.sha256(source.encode("utf-8", errors="replace")).hexdigest()[:24]


__all__ = ["Report", "render", "supported_formats"]
