"""Typed, serializable data models used across PreviewShield."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlsplit


class Severity(str, Enum):
    """Finding severity ordered from informational to critical."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Return a stable numeric rank for comparisons and thresholds."""

        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]

    @classmethod
    def parse(cls, value: str) -> Severity:
        """Parse a case-insensitive severity value."""

        try:
            return cls(value.strip().lower())
        except ValueError as error:
            allowed = ", ".join(item.value for item in cls)
            raise ValueError(f"Unknown severity '{value}'. Expected one of: {allowed}.") from error


@dataclass(frozen=True)
class TLSInfo:
    """TLS details observed on the pinned connection."""

    version: str | None = None
    cipher: str | None = None
    certificate_subject: str | None = None
    certificate_issuer: str | None = None
    certificate_expires_at: str | None = None
    certificate_days_remaining: int | None = None


@dataclass(frozen=True)
class RedirectHop:
    """One response in an HTTP redirect chain."""

    url: str
    status_code: int
    location: str
    resolved_ip: str


@dataclass(frozen=True)
class ResponseSnapshot:
    """Security-relevant response metadata captured without reading the body."""

    requested_url: str
    final_url: str
    status_code: int
    reason: str
    headers: dict[str, tuple[str, ...]]
    resolved_ip: str
    elapsed_ms: int
    redirects: tuple[RedirectHop, ...] = ()
    tls: TLSInfo | None = None

    def header(self, name: str) -> str | None:
        """Return the final value for a case-insensitive response header."""

        values = self.headers.get(name.lower(), ())
        return values[-1] if values else None

    def header_values(self, name: str) -> tuple[str, ...]:
        """Return every value for a repeatable response header."""

        return self.headers.get(name.lower(), ())


@dataclass(frozen=True)
class Finding:
    """One actionable web-hardening observation."""

    rule_id: str
    title: str
    severity: Severity
    category: str
    message: str
    remediation: str
    target: str
    subject: str = "response"
    evidence: str | None = None
    references: tuple[str, ...] = ()

    @property
    def fingerprint(self) -> str:
        """Build a stable identity used for baseline comparisons and SARIF."""

        parsed = urlsplit(self.target)
        route = parsed.path or "/"
        if parsed.query:
            route = f"{route}?{parsed.query}"
        source = "\x1f".join((self.rule_id, route, self.subject))
        return hashlib.sha256(source.encode("utf-8")).hexdigest()[:24]

    def with_severity(self, severity: Severity) -> Finding:
        """Return a copy with a policy-provided severity override."""

        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            severity=severity,
            category=self.category,
            message=self.message,
            remediation=self.remediation,
            target=self.target,
            subject=self.subject,
            evidence=self.evidence,
            references=self.references,
        )


@dataclass(frozen=True)
class RouteReport:
    """Snapshot and findings for one scanned route."""

    snapshot: ResponseSnapshot
    findings: tuple[Finding, ...] = ()


@dataclass(frozen=True)
class ScanReport:
    """Complete report for one origin and one or more routes."""

    schema_version: str
    tool_version: str
    generated_at: str
    policy_name: str
    target: str
    routes: tuple[RouteReport, ...]
    score: int
    grade: str
    fail_on: Severity
    passed: bool

    @property
    def findings(self) -> tuple[Finding, ...]:
        """Flatten findings from every route in stable scan order."""

        return tuple(finding for route in self.routes for finding in route.findings)

    @property
    def counts(self) -> dict[str, int]:
        """Count findings by severity for output formats and action outputs."""

        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts


class DeltaKind(str, Enum):
    """How one finding changed between baseline and preview."""

    REGRESSION = "regression"
    RESOLVED = "resolved"
    UNCHANGED = "unchanged"
    CHANGED = "changed"


@dataclass(frozen=True)
class FindingDelta:
    """Comparison result for one stable finding identity."""

    kind: DeltaKind
    fingerprint: str
    baseline: Finding | None = None
    preview: Finding | None = None

    @property
    def finding(self) -> Finding:
        """Return the most relevant finding for display."""

        finding = self.preview or self.baseline
        if finding is None:  # pragma: no cover - protected by constructors
            raise ValueError("A finding delta must contain a baseline or preview finding.")
        return finding


@dataclass(frozen=True)
class DiffReport:
    """Security regression comparison between two scan reports."""

    schema_version: str
    tool_version: str
    generated_at: str
    policy_name: str
    baseline: ScanReport
    preview: ScanReport
    deltas: tuple[FindingDelta, ...]
    fail_on: Severity
    passed: bool

    @property
    def regressions(self) -> tuple[FindingDelta, ...]:
        """Return newly introduced or severity-increased findings."""

        return tuple(delta for delta in self.deltas if delta.kind is DeltaKind.REGRESSION)

    @property
    def resolved(self) -> tuple[FindingDelta, ...]:
        """Return findings present in the baseline but absent in preview."""

        return tuple(delta for delta in self.deltas if delta.kind is DeltaKind.RESOLVED)

    @property
    def unchanged(self) -> tuple[FindingDelta, ...]:
        """Return findings whose severity and content did not change."""

        return tuple(delta for delta in self.deltas if delta.kind is DeltaKind.UNCHANGED)


def to_primitive(value: Any) -> Any:
    """Convert nested dataclasses and enums into JSON-safe primitives."""

    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "__dataclass_fields__"):
        return to_primitive(asdict(value))
    if isinstance(value, dict):
        return {str(key): to_primitive(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_primitive(item) for item in value]
    return value


@dataclass
class MutableHeaderBag:
    """Internal helper that preserves duplicate response headers."""

    values: dict[str, list[str]] = field(default_factory=dict)

    def add(self, name: str, value: str) -> None:
        """Append one response header using a lowercase key."""

        self.values.setdefault(name.lower(), []).append(value)

    def freeze(self) -> dict[str, tuple[str, ...]]:
        """Create an immutable-by-convention representation for snapshots."""

        return {name: tuple(values) for name, values in self.values.items()}
