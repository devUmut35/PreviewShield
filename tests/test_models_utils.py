from __future__ import annotations

import pytest

from previewshield.exceptions import ConfigurationError
from previewshield.models import Finding, MutableHeaderBag, Severity, to_primitive
from previewshield.utils import (
    clean_text,
    markdown_code,
    parse_threshold,
    redact_url,
    validate_header_name,
)


def finding(host: str) -> Finding:
    return Finding(
        rule_id="PS9001",
        title="Test",
        severity=Severity.HIGH,
        category="test",
        message="Message",
        remediation="Fix",
        target=f"https://{host}/route?mode=test",
    )


def test_fingerprint_is_stable_across_deployment_hosts() -> None:
    assert finding("prod.example").fingerprint == finding("preview.example").fingerprint
    assert finding("prod.example").with_severity(Severity.LOW).severity is Severity.LOW


def test_severity_parser_and_primitive_conversion() -> None:
    assert Severity.parse(" HIGH ") is Severity.HIGH
    assert to_primitive(finding("example.com"))["severity"] == "high"
    with pytest.raises(ValueError, match="Unknown severity"):
        Severity.parse("blocker")


def test_mutable_header_bag_preserves_duplicate_values() -> None:
    bag = MutableHeaderBag()
    bag.add("Set-Cookie", "one=1")
    bag.add("set-cookie", "two=2")

    assert bag.freeze() == {"set-cookie": ("one=1", "two=2")}


def test_output_safety_helpers() -> None:
    cleaned = clean_text("safe\r\ntext")
    assert "\r" not in cleaned and "\n" not in cleaned
    assert clean_text("abcdef", limit=4) == "abc…"
    assert markdown_code("a`b") == "`a'b`"
    assert redact_url("https://user:secret@example.com:8443/path?q=1#fragment") == (
        "https://example.com:8443/path?q=1"
    )


def test_configuration_helpers() -> None:
    assert parse_threshold("medium") is Severity.MEDIUM
    assert validate_header_name("X-Safe_Header") == "X-Safe_Header"
    with pytest.raises(ConfigurationError, match="Unknown severity"):
        parse_threshold("urgent")
    with pytest.raises(ConfigurationError, match="Invalid request header"):
        validate_header_name("Bad Header")
