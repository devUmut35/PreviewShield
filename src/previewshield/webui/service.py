"""Validation and API orchestration for the local browser interface."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import cast

from previewshield import api
from previewshield.exceptions import ConfigurationError
from previewshield.models import DiffReport, ScanReport, Severity
from previewshield.policy import Policy, default_policy

MAX_TARGET_LENGTH = 2_048
MAX_PATH_LENGTH = 512
MAX_PATHS = 20
_CONTROL_CHARACTER = re.compile(r"[\x00-\x1f\x7f]")
_SCAN_KEYS = frozenset(
    {"target", "profile", "paths", "fail_on", "allow_private", "authorized_private"}
)
_DIFF_KEYS = frozenset(
    {
        "baseline",
        "preview",
        "profile",
        "paths",
        "fail_on",
        "allow_private",
        "authorized_private",
    }
)


class UIInputError(ConfigurationError):
    """Raised when a browser request does not match the UI contract."""


def execute_scan(payload: object, *, private_targets_enabled: bool) -> ScanReport:
    """Validate one browser request and run a single-target scan."""

    data = _payload(payload, allowed=_SCAN_KEYS)
    policy, paths, threshold, allow_private = _options(
        data,
        private_targets_enabled=private_targets_enabled,
    )
    return api.scan(
        _text(data, "target", maximum=MAX_TARGET_LENGTH),
        policy=policy,
        paths=paths,
        fail_on=threshold,
        allow_private=allow_private,
    )


def execute_diff(payload: object, *, private_targets_enabled: bool) -> DiffReport:
    """Validate one browser request and compare production with a preview."""

    data = _payload(payload, allowed=_DIFF_KEYS)
    policy, paths, threshold, allow_private = _options(
        data,
        private_targets_enabled=private_targets_enabled,
    )
    return api.diff(
        _text(data, "baseline", maximum=MAX_TARGET_LENGTH),
        _text(data, "preview", maximum=MAX_TARGET_LENGTH),
        policy=policy,
        paths=paths,
        fail_on=threshold,
        allow_private=allow_private,
    )


def _payload(payload: object, *, allowed: frozenset[str]) -> Mapping[str, object]:
    if not isinstance(payload, dict) or any(not isinstance(key, str) for key in payload):
        raise UIInputError("The request body must be a JSON object.")
    data = cast(Mapping[str, object], payload)
    unknown = sorted(key for key in data if key not in allowed)
    if unknown:
        raise UIInputError(f"Unknown option(s): {', '.join(unknown)}.")
    return data


def _options(
    data: Mapping[str, object],
    *,
    private_targets_enabled: bool,
) -> tuple[Policy, tuple[str, ...], Severity, bool]:
    profile = _choice(data, "profile", choices=("balanced", "strict"), default="balanced")
    policy = default_policy(profile)
    paths = _paths(data.get("paths", ["/"]))
    fail_on = _choice(
        data,
        "fail_on",
        choices=tuple(severity.value for severity in Severity),
        default=policy.fail_on.value,
    )
    threshold = Severity.parse(fail_on)
    allow_private = _boolean(data, "allow_private", default=False)
    authorized_private = _boolean(data, "authorized_private", default=False)
    if allow_private and not private_targets_enabled:
        raise UIInputError(
            "Private targets are locked. Restart with --allow-private-targets only for "
            "trusted local systems."
        )
    if allow_private and not authorized_private:
        raise UIInputError("Confirm authorization before scanning a private or loopback target.")
    return policy, paths, threshold, allow_private


def _text(data: Mapping[str, object], name: str, *, maximum: int) -> str:
    value = data.get(name)
    if not isinstance(value, str) or not value.strip():
        raise UIInputError(f"{name} must be a non-empty string.")
    normalized = value.strip()
    if len(normalized) > maximum:
        raise UIInputError(f"{name} must be at most {maximum} characters.")
    if _CONTROL_CHARACTER.search(normalized):
        raise UIInputError(f"{name} contains control characters.")
    return normalized


def _choice(
    data: Mapping[str, object],
    name: str,
    *,
    choices: tuple[str, ...],
    default: str,
) -> str:
    value = data.get(name, default)
    if not isinstance(value, str) or value not in choices:
        raise UIInputError(f"{name} must be one of: {', '.join(choices)}.")
    return value


def _boolean(data: Mapping[str, object], name: str, *, default: bool) -> bool:
    value = data.get(name, default)
    if not isinstance(value, bool):
        raise UIInputError(f"{name} must be true or false.")
    return value


def _paths(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(path, str) for path in value):
        raise UIInputError("paths must be a JSON list of strings.")
    if not value:
        raise UIInputError("paths must include at least one route.")
    if len(value) > MAX_PATHS:
        raise UIInputError(f"paths may contain at most {MAX_PATHS} routes.")
    normalized: list[str] = []
    for raw_path in value:
        path = raw_path.strip()
        if not path or len(path) > MAX_PATH_LENGTH or _CONTROL_CHARACTER.search(path):
            raise UIInputError(f"Each route must contain 1 to {MAX_PATH_LENGTH} safe characters.")
        if path not in normalized:
            normalized.append(path)
    return tuple(normalized)


__all__ = ["UIInputError", "execute_diff", "execute_scan"]
