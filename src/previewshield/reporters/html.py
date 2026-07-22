"""Self-contained HTML report renderer."""

from __future__ import annotations

from html import escape

from previewshield.models import DiffReport, Finding, FindingDelta, ScanReport, Severity
from previewshield.reporters import (
    Report,
    _safe_evidence,
    _safe_text,
    _safe_url,
    _sorted_deltas,
    _sorted_findings,
)

_STYLE = """
:root { color-scheme: light dark; --bg:#0b1020; --panel:#151c30; --text:#edf2ff;
  --muted:#a9b5d1; --line:#2a3553; --good:#35c98b; --bad:#ff667a; --warn:#f6c453; }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text); font:15px/1.55 system-ui,sans-serif; }
main { width:min(1180px,calc(100% - 32px)); margin:32px auto 56px; }
h1,h2 { line-height:1.2; } h1 { margin:0 0 8px; } h2 { margin-top:30px; }
.muted { color:var(--muted); }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:12px; }
.card { background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:16px; }
.metric { font-size:1.55rem; font-weight:750; }
.pass { color:var(--good); } .fail { color:var(--bad); }
code { overflow-wrap:anywhere; }
table { width:100%; border-collapse:collapse; background:var(--panel); }
th,td { padding:11px 12px; text-align:left; vertical-align:top; border:1px solid var(--line); }
th { color:var(--muted); font-size:.82rem; text-transform:uppercase; letter-spacing:.04em; }
.badge { display:inline-block; border-radius:999px; padding:2px 9px; font-weight:750;
  font-size:.76rem; }
.critical,.high,.regression { background:#66293a; color:#ffdce3; }
.medium,.changed { background:#644f20; color:#fff0bd; }
.low,.info { background:#25385f; color:#dbe7ff; }
.resolved { background:#174b3b; color:#c9ffe9; }
.issue { margin-bottom:7px; } .fix,.evidence { color:var(--muted); font-size:.9rem; }
.empty { padding:22px; border:1px dashed var(--line); border-radius:12px; color:var(--muted); }
footer { margin-top:32px; padding-top:18px; border-top:1px solid var(--line);
  color:var(--muted); font-size:.85rem; }
@media (max-width:720px) {
  main { width:min(100% - 20px,1180px); margin-top:18px; }
  table { display:block; overflow-x:auto; }
}
""".strip()


def _html(value: str, *, limit: int = 2_000) -> str:
    return escape(_safe_text(value, limit=limit), quote=True)


def _html_url(value: str) -> str:
    return escape(_safe_url(value), quote=True)


def _finding_cells(finding: Finding) -> str:
    evidence = _safe_evidence(finding.evidence)
    evidence_html = (
        f'<div class="evidence"><strong>Evidence:</strong> {_html(evidence, limit=240)}</div>'
        if evidence
        else ""
    )
    return (
        f'<td><span class="badge {finding.severity.value}">'
        f"{finding.severity.value.upper()}</span></td>"
        f"<td><code>{_html(finding.rule_id, limit=100)}</code><br>"
        f'<span class="muted">{_html(finding.category, limit=100)}</span></td>'
        f"<td><code>{_html_url(finding.target)}</code></td>"
        f'<td><div class="issue"><strong>{_html(finding.title, limit=500)}</strong><br>'
        f"{_html(finding.message)}</div>"
        f'<div class="fix"><strong>Fix:</strong> {_html(finding.remediation)}</div>'
        f"{evidence_html}</td>"
    )


def _scan_table(findings: tuple[Finding, ...]) -> str:
    if not findings:
        return '<div class="empty">No security findings were detected.</div>'
    rows = "".join(f"<tr>{_finding_cells(finding)}</tr>" for finding in findings)
    return (
        "<table><thead><tr><th>Severity</th><th>Rule</th><th>Target</th>"
        f"<th>Finding and remediation</th></tr></thead><tbody>{rows}</tbody></table>"
    )


def _delta_table(deltas: tuple[FindingDelta, ...]) -> str:
    if not deltas:
        return '<div class="empty">No security changes were detected.</div>'
    rows = "".join(
        f'<tr><td><span class="badge {delta.kind.value}">{delta.kind.value.upper()}</span></td>'
        f"{_finding_cells(delta.finding)}</tr>"
        for delta in deltas
    )
    return (
        "<table><thead><tr><th>Change</th><th>Severity</th><th>Rule</th><th>Target</th>"
        f"<th>Finding and remediation</th></tr></thead><tbody>{rows}</tbody></table>"
    )


def _counts_cards(report: ScanReport) -> str:
    cards = "".join(
        f'<div class="card"><div class="muted">{severity.value.title()}</div>'
        f'<div class="metric">{report.counts[severity.value]}</div></div>'
        for severity in Severity
    )
    return f'<div class="grid">{cards}</div>'


def _scan_body(report: ScanReport) -> str:
    status_class = "pass" if report.passed else "fail"
    return (
        "<h1>PreviewShield security scan</h1>"
        f'<p class="muted">Generated {_html(report.generated_at, limit=100)}</p>'
        '<div class="grid">'
        f'<div class="card"><div class="muted">Status</div><div class="metric {status_class}">'
        f"{'PASS' if report.passed else 'FAIL'}</div></div>"
        '<div class="card"><div class="muted">Score</div>'
        f'<div class="metric">{report.score}/100</div></div>'
        '<div class="card"><div class="muted">Grade</div>'
        f'<div class="metric">{_html(report.grade, limit=20)}</div></div>'
        '<div class="card"><div class="muted">Threshold</div>'
        f'<div class="metric">{report.fail_on.value}</div></div>'
        "</div>"
        f"<p><strong>Target:</strong> <code>{_html_url(report.target)}</code><br>"
        f"<strong>Policy:</strong> {_html(report.policy_name, limit=200)}</p>"
        "<h2>Severity summary</h2>"
        f"{_counts_cards(report)}"
        f"<h2>Findings ({len(report.findings)})</h2>"
        f"{_scan_table(_sorted_findings(report.findings))}"
    )


def _diff_body(report: DiffReport) -> str:
    status_class = "pass" if report.passed else "fail"
    deltas = _sorted_deltas(report.deltas)
    regressions = sum(delta.kind.value == "regression" for delta in deltas)
    resolved = sum(delta.kind.value == "resolved" for delta in deltas)
    changed = sum(delta.kind.value == "changed" for delta in deltas)
    visible = tuple(delta for delta in deltas if delta.kind.value != "unchanged")
    return (
        "<h1>PreviewShield security diff</h1>"
        f'<p class="muted">Generated {_html(report.generated_at, limit=100)}</p>'
        '<div class="grid">'
        f'<div class="card"><div class="muted">Status</div><div class="metric {status_class}">'
        f"{'PASS' if report.passed else 'FAIL'}</div></div>"
        '<div class="card"><div class="muted">Regressions</div>'
        f'<div class="metric fail">{regressions}</div></div>'
        '<div class="card"><div class="muted">Resolved</div>'
        f'<div class="metric pass">{resolved}</div></div>'
        '<div class="card"><div class="muted">Changed</div>'
        f'<div class="metric">{changed}</div></div>'
        "</div>"
        f"<p><strong>Baseline:</strong> <code>{_html_url(report.baseline.target)}</code> "
        f"({report.baseline.score}/100, {_html(report.baseline.grade, limit=20)})<br>"
        f"<strong>Preview:</strong> <code>{_html_url(report.preview.target)}</code> "
        f"({report.preview.score}/100, {_html(report.preview.grade, limit=20)})<br>"
        f"<strong>Policy:</strong> {_html(report.policy_name, limit=200)}</p>"
        f"<h2>Security changes ({len(visible)})</h2>{_delta_table(visible)}"
    )


def render_html(report: Report) -> str:
    """Render an escaped, standalone HTML document with no external assets."""

    body = _scan_body(report) if isinstance(report, ScanReport) else _diff_body(report)
    document = (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'none'; style-src 'unsafe-inline'; img-src data:\">"
        "<title>PreviewShield security report</title>"
        f"<style>{_STYLE}</style></head><body><main>{body}"
        f"<footer>PreviewShield {_html(report.tool_version, limit=100)} - "
        "Secret-safe deterministic report</footer>"
        "</main></body></html>"
    )
    return f"{document}\n"


render = render_html

__all__ = ["render", "render_html"]
