"""Small shared helpers with output-safety guarantees."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from previewshield.exceptions import ConfigurationError
from previewshield.models import Severity

_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


def utc_now() -> str:
    """Return an RFC 3339 timestamp in UTC."""

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def clean_text(value: str, *, limit: int = 500) -> str:
    """Strip control characters and cap untrusted network evidence."""

    cleaned = _CONTROL_CHARACTERS.sub("", value).replace("\r", " ").replace("\n", " ")
    if len(cleaned) <= limit:
        return cleaned
    return f"{cleaned[: limit - 1]}…"


def markdown_code(value: str) -> str:
    """Render untrusted text as a safe inline Markdown code span."""

    cleaned = clean_text(value).replace("`", "'")
    return f"`{cleaned}`"


def parse_threshold(value: str) -> Severity:
    """Parse a severity and expose a configuration-focused error."""

    try:
        return Severity.parse(value)
    except ValueError as error:
        raise ConfigurationError(str(error)) from error


def validate_header_name(name: str) -> str:
    """Reject request header names that could enable header injection."""

    if not _HEADER_NAME.fullmatch(name):
        raise ConfigurationError(f"Invalid request header name: {name!r}.")
    return name


def redact_url(url: str) -> str:
    """Remove credentials and fragments before a URL enters a report."""

    parsed = urlsplit(url)
    hostname = parsed.hostname or ""
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    if parsed.port is not None:
        hostname = f"{hostname}:{parsed.port}"
    return urlunsplit((parsed.scheme, hostname, parsed.path, parsed.query, ""))
