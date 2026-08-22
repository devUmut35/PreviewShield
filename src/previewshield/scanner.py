"""High-level, multi-route scanning orchestration."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from urllib.parse import urlsplit, urlunsplit

from previewshield._version import __version__
from previewshield.checks import evaluate
from previewshield.exceptions import ConfigurationError
from previewshield.models import RouteReport, ScanReport, Severity
from previewshield.network import NetworkOptions, fetch
from previewshield.policy import Policy, default_policy
from previewshield.targets import normalize_hostname, normalize_origin_paths
from previewshield.utils import utc_now

SCHEMA_VERSION = "1.0"
_SCORE_PENALTIES = {
    Severity.INFO: 0,
    Severity.LOW: 3,
    Severity.MEDIUM: 8,
    Severity.HIGH: 15,
    Severity.CRITICAL: 25,
}
_GRADES = ((95, "A+"), (90, "A"), (80, "B"), (70, "C"), (60, "D"))


def scan(  # noqa: PLR0913 - public API uses explicit, optional controls
    target: str,
    *,
    policy: Policy | None = None,
    paths: Sequence[str] | None = None,
    request_headers: Mapping[str, str] | None = None,
    fail_on: Severity | None = None,
    allow_private: bool | None = None,
) -> ScanReport:
    """Scan one web origin or route and return a serializable report.

    A target containing a path is scanned as-is when the policy uses only its
    default ``/`` route. Explicit CLI or policy paths are always resolved from the
    target origin, which keeps baseline and preview fingerprints comparable.
    """

    active_policy = policy or default_policy()
    threshold = fail_on or active_policy.fail_on
    try:
        route_paths = normalize_origin_paths(paths) if paths is not None else active_policy.paths
    except ValueError as error:
        raise ConfigurationError(str(error)) from error
    route_urls, normalized_target = _route_urls(target, route_paths, paths is None)
    try:
        options = NetworkOptions(
            timeout=active_policy.network.timeout_seconds,
            max_redirects=active_policy.network.max_redirects,
            allow_private=(
                active_policy.network.allow_private if allow_private is None else allow_private
            ),
            user_agent=active_policy.network.user_agent,
            allowed_hosts=active_policy.network.allowed_hosts,
        )
    except ValueError as error:
        raise ConfigurationError(f"Invalid network policy: {error}.") from error

    route_reports: list[RouteReport] = []
    for route_url in route_urls:
        if not active_policy.host_allowed(route_url):
            hostname = urlsplit(route_url).hostname or ""
            raise ConfigurationError(
                f"Target host '{hostname}' is not included in network.allowed_hosts."
            )
        snapshot = fetch(route_url, options, request_headers=request_headers)
        route_reports.append(
            RouteReport(snapshot=snapshot, findings=evaluate(snapshot, active_policy))
        )

    route_tuple = tuple(route_reports)
    score = _score(route_tuple)
    all_findings = tuple(finding for route in route_tuple for finding in route.findings)
    passed = not any(finding.severity.rank >= threshold.rank for finding in all_findings)
    return ScanReport(
        schema_version=SCHEMA_VERSION,
        tool_version=__version__,
        generated_at=utc_now(),
        policy_name=active_policy.name,
        target=normalized_target,
        routes=route_tuple,
        score=score,
        grade=_grade(score),
        fail_on=threshold,
        passed=passed,
    )


def _route_urls(
    target: str,
    paths: Sequence[str],
    preserve_single_target_path: bool,
) -> tuple[tuple[str, ...], str]:
    if not isinstance(target, str) or not target.strip():
        raise ConfigurationError("Target must be a non-empty URL or hostname.")
    candidate = target.strip()
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError as error:
        raise ConfigurationError("Target has an invalid URL authority or port.") from error
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ConfigurationError("Target must use http:// or https://.")
    if not parsed.netloc or parsed.hostname is None:
        raise ConfigurationError("Target must include a hostname.")
    if parsed.username is not None or parsed.password is not None:
        raise ConfigurationError("Credentials in target URLs are not allowed.")
    if parsed.fragment:
        raise ConfigurationError("Target URL fragments are not allowed.")

    try:
        hostname = normalize_hostname(parsed.hostname or "")
    except ValueError as error:
        raise ConfigurationError("Target contains an invalid hostname.") from error
    display_host = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    netloc = display_host if port in {None, default_port} else f"{display_host}:{port}"
    origin = urlunsplit((parsed.scheme.lower(), netloc, "", "", ""))
    provided_path = parsed.path or "/"
    provided_route = provided_path + (f"?{parsed.query}" if parsed.query else "")
    if preserve_single_target_path and tuple(paths) == ("/",) and provided_route != "/":
        return (f"{origin}{provided_route}",), f"{origin}{provided_route}"
    return tuple(f"{origin}{path}" for path in paths), origin


def _score(routes: Sequence[RouteReport]) -> int:
    if not routes:
        return 0
    route_scores = []
    for route in routes:
        penalty = sum(_SCORE_PENALTIES[finding.severity] for finding in route.findings)
        route_scores.append(max(0, 100 - penalty))
    return round(sum(route_scores) / len(route_scores))


def _grade(score: int) -> str:
    for minimum, grade in _GRADES:
        if score >= minimum:
            return grade
    return "F"


__all__ = ["SCHEMA_VERSION", "scan"]
