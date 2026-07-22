"""Validated policy-as-code configuration for PreviewShield."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import yaml

from previewshield.exceptions import ConfigurationError
from previewshield.models import Severity
from previewshield.utils import clean_text, parse_threshold, validate_header_name

MAX_POLICY_BYTES = 256 * 1024
_RULE_ID = re.compile(r"^(?:PS\d{4}|CUSTOM\.[A-Z0-9_.-]+)$")
_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_MAX_HOSTNAME_LENGTH = 253
_ALLOWED_ROOT_KEYS = {
    "version",
    "name",
    "profile",
    "fail_on",
    "paths",
    "network",
    "checks",
    "diff",
}
_ALLOWED_NETWORK_KEYS = {
    "timeout_seconds",
    "max_redirects",
    "allow_private",
    "allowed_hosts",
    "user_agent",
}
_ALLOWED_CHECK_KEYS = {
    "disabled",
    "severity_overrides",
    "required_headers",
    "min_hsts_max_age",
    "certificate_warning_days",
}
_ALLOWED_DIFF_KEYS = {"mode"}
_PROFILE_DEFAULTS: dict[str, dict[str, Any]] = {
    "balanced": {
        "fail_on": Severity.HIGH,
        "min_hsts_max_age": 15_552_000,
        "certificate_warning_days": 30,
        "diff_mode": "regressions",
    },
    "strict": {
        "fail_on": Severity.MEDIUM,
        "min_hsts_max_age": 31_536_000,
        "certificate_warning_days": 45,
        "diff_mode": "regressions",
    },
}


@dataclass(frozen=True)
class NetworkPolicy:
    """Network safety and reliability controls."""

    timeout_seconds: float = 10.0
    max_redirects: int = 5
    allow_private: bool = False
    allowed_hosts: tuple[str, ...] = ()
    user_agent: str = "PreviewShield/1.0 (+https://github.com/devUmut35/PreviewShield)"


@dataclass(frozen=True)
class RequiredHeaderPolicy:
    """A project-specific response header requirement."""

    name: str
    severity: Severity
    exact: str | None = None
    contains: str | None = None
    remediation: str = "Configure the required response header at the application or edge."

    @property
    def rule_id(self) -> str:
        """Return a deterministic custom SARIF rule identifier."""

        normalized = re.sub(r"[^A-Z0-9]+", "_", self.name.upper()).strip("_")
        return f"CUSTOM.{normalized}"


@dataclass(frozen=True)
class Policy:
    """Complete immutable PreviewShield policy."""

    version: int
    name: str
    profile: str
    fail_on: Severity
    paths: tuple[str, ...]
    network: NetworkPolicy
    disabled_rules: frozenset[str]
    severity_overrides: Mapping[str, Severity]
    required_headers: tuple[RequiredHeaderPolicy, ...]
    min_hsts_max_age: int
    certificate_warning_days: int
    diff_mode: str

    def severity_for(self, rule_id: str, default: Severity) -> Severity:
        """Apply an optional project-level severity override."""

        return self.severity_overrides.get(rule_id, default)

    def rule_enabled(self, rule_id: str) -> bool:
        """Return whether a built-in or custom rule is active."""

        return rule_id not in self.disabled_rules

    def host_allowed(self, url: str) -> bool:
        """Enforce an optional hostname allowlist before DNS resolution."""

        if not self.network.allowed_hosts:
            return True
        hostname = (urlsplit(url).hostname or "").rstrip(".").lower()
        return any(_host_matches(hostname, allowed) for allowed in self.network.allowed_hosts)


def default_policy(profile: str = "balanced") -> Policy:
    """Create the built-in policy without reading from disk."""

    return policy_from_mapping({"version": 1, "profile": profile})


def load_policy(path: str | Path | None = None, *, profile: str = "balanced") -> Policy:
    """Load and strictly validate a YAML policy, or return built-in defaults."""

    if path is None:
        return default_policy(profile)

    policy_path = Path(path)
    try:
        size = policy_path.stat().st_size
    except OSError as error:
        raise ConfigurationError(f"Cannot read policy file {policy_path}: {error}.") from error
    if size > MAX_POLICY_BYTES:
        raise ConfigurationError(
            f"Policy file is {size} bytes; the maximum is {MAX_POLICY_BYTES} bytes."
        )

    try:
        raw = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise ConfigurationError(f"Invalid policy file {policy_path}: {error}.") from error
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigurationError("The policy root must be a YAML mapping.")
    return policy_from_mapping(raw, fallback_profile=profile)


def policy_from_mapping(raw: Mapping[str, Any], *, fallback_profile: str = "balanced") -> Policy:
    """Validate a mapping and create a strongly typed policy."""

    _reject_unknown(raw, _ALLOWED_ROOT_KEYS, "policy")
    version = _integer(raw.get("version", 1), "version", minimum=1, maximum=1)
    profile = _string(raw.get("profile", fallback_profile), "profile").lower()
    if profile not in _PROFILE_DEFAULTS:
        allowed = ", ".join(sorted(_PROFILE_DEFAULTS))
        raise ConfigurationError(f"Unknown profile '{profile}'. Expected one of: {allowed}.")
    defaults = _PROFILE_DEFAULTS[profile]

    name = clean_text(_string(raw.get("name", f"PreviewShield {profile}"), "name"), limit=80)
    fail_on_value = raw.get("fail_on")
    fail_on = (
        defaults["fail_on"]
        if fail_on_value is None
        else parse_threshold(_string(fail_on_value, "fail_on"))
    )
    paths = _paths(raw.get("paths", ["/"]))
    network = _network_policy(raw.get("network", {}))
    checks = _mapping(raw.get("checks", {}), "checks")
    _reject_unknown(checks, _ALLOWED_CHECK_KEYS, "checks")
    disabled = frozenset(_rule_ids(checks.get("disabled", []), "checks.disabled"))
    overrides = _severity_overrides(checks.get("severity_overrides", {}))
    required_headers = _required_headers(checks.get("required_headers", {}))
    _validate_rule_references(disabled, overrides, required_headers)
    min_hsts_max_age = _integer(
        checks.get("min_hsts_max_age", defaults["min_hsts_max_age"]),
        "checks.min_hsts_max_age",
        minimum=0,
        maximum=630_720_000,
    )
    certificate_warning_days = _integer(
        checks.get("certificate_warning_days", defaults["certificate_warning_days"]),
        "checks.certificate_warning_days",
        minimum=1,
        maximum=365,
    )
    diff = _mapping(raw.get("diff", {}), "diff")
    _reject_unknown(diff, _ALLOWED_DIFF_KEYS, "diff")
    diff_mode = _string(diff.get("mode", defaults["diff_mode"]), "diff.mode").lower()
    if diff_mode not in {"regressions", "absolute"}:
        raise ConfigurationError("diff.mode must be 'regressions' or 'absolute'.")

    return Policy(
        version=version,
        name=name,
        profile=profile,
        fail_on=fail_on,
        paths=paths,
        network=network,
        disabled_rules=disabled,
        severity_overrides=overrides,
        required_headers=required_headers,
        min_hsts_max_age=min_hsts_max_age,
        certificate_warning_days=certificate_warning_days,
        diff_mode=diff_mode,
    )


def default_policy_yaml() -> str:
    """Return a commented starter policy for ``previewshield init``."""

    return """# PreviewShield policy v1
version: 1
name: default
profile: balanced
fail_on: high

paths:
  - /

network:
  timeout_seconds: 10
  max_redirects: 5
  allow_private: false
  # allowed_hosts: [example.com, "*.example.com"]

checks:
  min_hsts_max_age: 15552000
  certificate_warning_days: 30
  disabled: []
  severity_overrides: {}
  required_headers: {}
  # required_headers:
  #   X-Robots-Tag:
  #     severity: medium
  #     contains: noindex

diff:
  # regressions: fail only on new or severity-increased findings
  # absolute: fail on every preview finding at the threshold
  mode: regressions
"""


def _network_policy(value: Any) -> NetworkPolicy:
    raw = _mapping(value, "network")
    _reject_unknown(raw, _ALLOWED_NETWORK_KEYS, "network")
    timeout = _number(
        raw.get("timeout_seconds", 10.0),
        "network.timeout_seconds",
        minimum=0.1,
        maximum=120.0,
    )
    max_redirects = _integer(
        raw.get("max_redirects", 5),
        "network.max_redirects",
        minimum=0,
        maximum=20,
    )
    allow_private = _boolean(raw.get("allow_private", False), "network.allow_private")
    allowed_hosts = tuple(
        _normalize_host(item)
        for item in _string_list(raw.get("allowed_hosts", []), "network.allowed_hosts")
    )
    user_agent = _user_agent(
        raw.get(
            "user_agent",
            "PreviewShield/1.0 (+https://github.com/devUmut35/PreviewShield)",
        )
    )
    return NetworkPolicy(
        timeout_seconds=timeout,
        max_redirects=max_redirects,
        allow_private=allow_private,
        allowed_hosts=allowed_hosts,
        user_agent=user_agent,
    )


def _required_headers(value: Any) -> tuple[RequiredHeaderPolicy, ...]:
    raw = _mapping(value, "checks.required_headers")
    results: list[RequiredHeaderPolicy] = []
    for header_name, options_value in raw.items():
        if not isinstance(header_name, str):
            raise ConfigurationError("Required header names must be strings.")
        name = validate_header_name(header_name)
        if options_value is True:
            options: Mapping[str, Any] = {}
        else:
            options = _mapping(options_value, f"checks.required_headers.{name}")
        _reject_unknown(
            options,
            {"severity", "exact", "contains", "remediation"},
            f"checks.required_headers.{name}",
        )
        severity = parse_threshold(
            _string(options.get("severity", "medium"), f"required_headers.{name}.severity")
        )
        exact = _optional_string(options.get("exact"), f"required_headers.{name}.exact")
        contains = _optional_string(options.get("contains"), f"required_headers.{name}.contains")
        if exact is not None and contains is not None:
            raise ConfigurationError(
                f"Required header {name} cannot define both 'exact' and 'contains'."
            )
        remediation = clean_text(
            _string(
                options.get(
                    "remediation",
                    "Configure the required response header at the application or edge.",
                ),
                f"required_headers.{name}.remediation",
            ),
            limit=500,
        )
        results.append(
            RequiredHeaderPolicy(
                name=name,
                severity=severity,
                exact=exact,
                contains=contains,
                remediation=remediation,
            )
        )
    return tuple(sorted(results, key=lambda item: item.name.lower()))


def _severity_overrides(value: Any) -> Mapping[str, Severity]:
    raw = _mapping(value, "checks.severity_overrides")
    results: dict[str, Severity] = {}
    for rule_id, severity in raw.items():
        if not isinstance(rule_id, str) or not _RULE_ID.fullmatch(rule_id):
            raise ConfigurationError(f"Invalid rule ID in severity overrides: {rule_id!r}.")
        results[rule_id] = parse_threshold(_string(severity, f"severity_overrides.{rule_id}"))
    return results


def _paths(value: Any) -> tuple[str, ...]:
    paths = _string_list(value, "paths")
    if not paths:
        raise ConfigurationError("paths must include at least one route.")
    normalized: list[str] = []
    for path in paths:
        parsed = urlsplit(path)
        if parsed.scheme or parsed.netloc or parsed.fragment:
            raise ConfigurationError(f"Path must be origin-relative without a fragment: {path!r}.")
        route = parsed.path or "/"
        if not route.startswith("/") or ".." in PurePosixPath(route).parts:
            raise ConfigurationError(f"Unsafe route path: {path!r}.")
        if parsed.query:
            route = f"{route}?{parsed.query}"
        if route not in normalized:
            normalized.append(route)
    return tuple(normalized)


def _rule_ids(value: Any, field: str) -> tuple[str, ...]:
    values = _string_list(value, field)
    for rule_id in values:
        if not _RULE_ID.fullmatch(rule_id):
            raise ConfigurationError(f"Invalid rule ID in {field}: {rule_id!r}.")
    return tuple(values)


def _host_matches(hostname: str, allowed: str) -> bool:
    if allowed.startswith("*."):
        suffix = allowed[1:]
        return hostname.endswith(suffix) and hostname != suffix[1:]
    return hostname == allowed


def _normalize_host(value: str) -> str:
    host = value.rstrip(".").lower()
    if not host or "/" in host or "://" in host:
        raise ConfigurationError(f"Invalid allowed host: {value!r}.")
    wildcard = host.startswith("*.")
    raw_hostname = host[2:] if wildcard else host
    if "*" in raw_hostname:
        raise ConfigurationError(f"Invalid allowed host: {value!r}.")
    try:
        normalized = raw_hostname.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise ConfigurationError(f"Invalid allowed host: {value!r}.") from error
    if len(normalized) > _MAX_HOSTNAME_LENGTH:
        raise ConfigurationError(f"Invalid allowed host: {value!r}.")
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        if any(not _HOST_LABEL.fullmatch(label) for label in normalized.split(".")):
            raise ConfigurationError(f"Invalid allowed host: {value!r}.") from None
    else:
        if wildcard:
            raise ConfigurationError("Wildcard allowed hosts cannot target IP addresses.")
    return f"*.{normalized}" if wildcard else normalized


def _validate_rule_references(
    disabled: frozenset[str],
    overrides: Mapping[str, Severity],
    required_headers: tuple[RequiredHeaderPolicy, ...],
) -> None:
    from previewshield.checks import RULES  # noqa: PLC0415 - avoids policy/check cycle

    known = set(RULES)
    known.update(requirement.rule_id for requirement in required_headers)
    unknown = sorted((set(disabled) | set(overrides)) - known)
    if unknown:
        raise ConfigurationError(f"Unknown rule ID(s): {', '.join(unknown)}.")


def _reject_unknown(raw: Mapping[str, Any], allowed: set[str], field: str) -> None:
    unknown = sorted(str(key) for key in raw if key not in allowed)
    if unknown:
        raise ConfigurationError(f"Unknown {field} option(s): {', '.join(unknown)}.")


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ConfigurationError(f"{field} must be a YAML mapping.")
    return value


def _string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigurationError(f"{field} must be a non-empty string.")
    return value.strip()


def _optional_string(value: Any, field: str) -> str | None:
    if value is None:
        return None
    return clean_text(_string(value, field), limit=500)


def _string_list(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ConfigurationError(f"{field} must be a YAML list of strings.")
    normalized = tuple(item.strip() for item in value)
    if any(not item for item in normalized):
        raise ConfigurationError(f"{field} must not contain empty values.")
    return normalized


def _user_agent(value: Any) -> str:
    result = _string(value, "network.user_agent")
    if clean_text(result, limit=200) != result:
        raise ConfigurationError(
            "network.user_agent must be at most 200 characters without control characters."
        )
    try:
        result.encode("latin-1")
    except UnicodeEncodeError as error:
        raise ConfigurationError(
            "network.user_agent must contain ISO-8859-1 characters only."
        ) from error
    return result


def _boolean(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigurationError(f"{field} must be true or false.")
    return value


def _integer(value: Any, field: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigurationError(f"{field} must be an integer.")
    if not minimum <= value <= maximum:
        raise ConfigurationError(f"{field} must be between {minimum} and {maximum}.")
    return int(value)


def _number(value: Any, field: str, *, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigurationError(f"{field} must be a number.")
    result = float(value)
    if not minimum <= result <= maximum:
        raise ConfigurationError(f"{field} must be between {minimum} and {maximum}.")
    return result
