from __future__ import annotations

from pathlib import Path

import pytest

from previewshield.exceptions import ConfigurationError
from previewshield.models import Severity
from previewshield.policy import (
    MAX_POLICY_BYTES,
    default_policy,
    default_policy_yaml,
    load_policy,
    policy_from_mapping,
)


def test_default_balanced_policy() -> None:
    policy = default_policy()

    assert policy.version == 1
    assert policy.profile == "balanced"
    assert policy.fail_on is Severity.HIGH
    assert policy.paths == ("/",)
    assert policy.min_hsts_max_age == 15_552_000
    assert not policy.network.allow_private


def test_strict_profile_changes_thresholds() -> None:
    policy = default_policy("strict")

    assert policy.fail_on is Severity.MEDIUM
    assert policy.min_hsts_max_age == 31_536_000
    assert policy.certificate_warning_days == 45


def test_policy_parses_custom_controls() -> None:
    policy = policy_from_mapping(
        {
            "version": 1,
            "name": "storefront",
            "paths": ["/", "/account?view=security", "/"],
            "network": {
                "allowed_hosts": ["example.com", "*.preview.example.com"],
                "timeout_seconds": 3.5,
            },
            "checks": {
                "disabled": ["PS1204"],
                "severity_overrides": {"PS1601": "medium"},
                "required_headers": {"X-Robots-Tag": {"contains": "noindex", "severity": "high"}},
            },
            "diff": {"mode": "absolute"},
        }
    )

    assert policy.name == "storefront"
    assert policy.paths == ("/", "/account?view=security")
    assert policy.network.timeout_seconds == 3.5
    assert policy.host_allowed("https://demo.preview.example.com")
    assert not policy.host_allowed("https://preview.example.com")
    assert policy.severity_for("PS1601", Severity.LOW) is Severity.MEDIUM
    assert not policy.rule_enabled("PS1204")
    assert policy.required_headers[0].rule_id == "CUSTOM.X_ROBOTS_TAG"
    assert policy.diff_mode == "absolute"


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ({"unknown": True}, "Unknown policy"),
        ({"version": 2}, "between 1 and 1"),
        ({"profile": "extreme"}, "Unknown profile"),
        ({"paths": ["https://example.com"]}, "origin-relative"),
        ({"paths": ["/../admin"]}, "Unsafe route"),
        ({"network": {"allow_private": "yes"}}, "true or false"),
        ({"network": {"allowed_hosts": [" "]}}, "empty values"),
        ({"network": {"allowed_hosts": ["bad host"]}}, "Invalid allowed host"),
        ({"network": {"allowed_hosts": ["*.127.0.0.1"]}}, "cannot target IP"),
        ({"network": {"user_agent": "Preview\nShield"}}, "control characters"),
        ({"network": {"user_agent": "PreviewShield ☃"}}, "ISO-8859-1"),
        ({"checks": {"disabled": ["bad"]}}, "Invalid rule ID"),
        ({"checks": {"disabled": ["PS9999"]}}, "Unknown rule ID"),
        (
            {"checks": {"severity_overrides": {"CUSTOM.UNKNOWN": "high"}}},
            "Unknown rule ID",
        ),
        (
            {"checks": {"required_headers": {"X-Test": {"exact": "a", "contains": "a"}}}},
            "cannot define both",
        ),
    ],
)
def test_invalid_policy_is_rejected(raw: dict[str, object], message: str) -> None:
    with pytest.raises(ConfigurationError, match=message):
        policy_from_mapping(raw)


def test_load_policy_uses_safe_yaml(tmp_path: Path) -> None:
    path = tmp_path / ".previewshield.yml"
    path.write_text("version: 1\nfail_on: medium\n", encoding="utf-8")

    assert load_policy(path).fail_on is Severity.MEDIUM


def test_load_policy_rejects_oversized_file(tmp_path: Path) -> None:
    path = tmp_path / "large.yml"
    path.write_bytes(b"#" * (MAX_POLICY_BYTES + 1))

    with pytest.raises(ConfigurationError, match="maximum"):
        load_policy(path)


def test_default_policy_template_round_trips(tmp_path: Path) -> None:
    path = tmp_path / ".previewshield.yml"
    path.write_text(default_policy_yaml(), encoding="utf-8")

    policy = load_policy(path)
    assert policy.profile == "balanced"
    assert policy.paths == ("/",)
