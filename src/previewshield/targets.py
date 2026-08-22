"""Shared normalization and validation for scan targets and routes.

Scanner, network, and policy layers historically repeated hostname and
origin-relative path validation with slightly different messages.  These helpers
keep one canonical implementation while letting each caller translate failures
into its own domain error type.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Sequence
from pathlib import PurePosixPath
from urllib.parse import urlsplit

MAX_HOSTNAME_LENGTH = 253

_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def normalize_hostname(hostname: str) -> str:
    """Return a lowercase ASCII hostname, raising ``ValueError`` when unsafe."""

    if "%" in hostname:
        raise ValueError("IPv6 scope identifiers are not allowed in target URLs.")
    try:
        return ipaddress.ip_address(hostname).compressed
    except ValueError:
        pass

    stripped = hostname.rstrip(".")
    if not stripped:
        raise ValueError("Target URL must include a hostname.")
    try:
        normalized = stripped.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ValueError("Target URL contains an invalid hostname.") from error
    if len(normalized) > MAX_HOSTNAME_LENGTH:
        raise ValueError(f"Target hostname exceeds {MAX_HOSTNAME_LENGTH} characters.")
    if any(not _HOST_LABEL.fullmatch(label) for label in normalized.split(".")):
        raise ValueError("Target URL contains an invalid hostname.")
    return normalized


def normalize_origin_paths(paths: Sequence[str]) -> tuple[str, ...]:
    """Validate origin-relative paths and return deduplicated normalized routes.

    Raises ``ValueError`` when a path is not a safe origin-relative route.
    """

    if isinstance(paths, (str, bytes)) or not paths:
        raise ValueError("At least one origin-relative path is required.")
    result: list[str] = []
    for raw_path in paths:
        if not isinstance(raw_path, str) or not raw_path.strip():
            raise ValueError("Scan paths must be non-empty strings.")
        parsed = urlsplit(raw_path.strip())
        route = parsed.path or "/"
        if (
            parsed.scheme
            or parsed.netloc
            or parsed.fragment
            or not route.startswith("/")
            or ".." in PurePosixPath(route).parts
        ):
            raise ValueError(f"Unsafe origin-relative path: {raw_path!r}.")
        if parsed.query:
            route = f"{route}?{parsed.query}"
        if route not in result:
            result.append(route)
    return tuple(result)
