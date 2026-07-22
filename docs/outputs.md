# Output formats

Every renderer consumes the same typed scan or diff result. Choosing another format does not
make another network request and does not change the policy decision.

## Generate one or several reports

```bash
previewshield scan https://example.com \
  --format console \
  --also-format json=artifacts/previewshield.json \
  --also-format html=artifacts/previewshield.html
```

When `--output` is omitted, the primary report is printed to standard output. Additional formats
always require `FORMAT=PATH`. PreviewShield refuses to write two reports to the same resolved
path.

Canonical format names are `console`, `html`, `json`, `junit`, `markdown`, and `sarif`.

## Format matrix

| Format | Contents | Recommended consumer |
| --- | --- | --- |
| `console` | ANSI-free summary and actionable findings | Developers and plain CI logs |
| `json` | Complete, stable, sorted data model | Scripts, archives, data pipelines |
| `markdown` | Compact tables and prioritized fixes | GitHub job summaries and comments |
| `sarif` | SARIF 2.1.0 rules and results | GitHub code scanning and SARIF tools |
| `junit` | Test cases with threshold failures | CI test-report interfaces |
| `html` | Self-contained styled report | Humans, downloadable build artifacts |

## JSON

JSON is the canonical automation format. Objects contain `schema_version` and `tool_version` so
consumers can reject incompatible data deliberately.

A scan report includes:

```text
schema_version, tool_version, generated_at, policy_name
target, routes[], score, grade, fail_on, passed
```

Each route includes the response snapshot and findings. A snapshot contains normalized URLs,
status, duplicate-preserving response headers, resolved IP, elapsed time, redirects, and
negotiated TLS metadata. Findings contain rule ID, title, severity, category, message,
remediation, target, subject, evidence, and references.

A diff report includes:

```text
schema_version, tool_version, generated_at, policy_name
baseline, preview, deltas[], fail_on, passed
```

Each delta is `regression`, `resolved`, `changed`, or `unchanged`, with the relevant baseline and
preview finding records. Do not infer pass/fail from score; use the top-level `passed` value.

## Markdown

Markdown is intentionally concise. It sorts findings by severity, limits long tables and fix
lists, and works well in `GITHUB_STEP_SUMMARY`. The GitHub Action writes it automatically.

The summary is not a replacement for JSON when a complete machine-readable history is required.

## SARIF

SARIF uses version 2.1.0. Stable PreviewShield rule IDs become SARIF rule IDs, and stable finding
fingerprints let code-scanning platforms correlate repeated runs.

Because web findings have no source-code line, results use `.previewshield.yml` line 1 as a
repository-level physical anchor and put the target in a logical location and result properties.

- Scan reports include all findings.
- Diff reports include regressions only.
- Critical/high map to SARIF `error`, medium to `warning`, and low/info to `note`.

See the [GitHub Action guide](github-action.md#upload-sarif-to-github-code-scanning) for upload
permissions and workflow configuration.

## JUnit XML

Each visible finding or diff change becomes a test case. A test case becomes a JUnit failure only
when it is a failing scan finding, or a failing regression in diff mode, at or above the selected
threshold. Other observations are retained in `system-out`.

## HTML

HTML is a self-contained document with no remote script or stylesheet dependency. Treat it as a
build artifact and apply your normal artifact retention and access policy.

## Scoring and grades

PreviewShield calculates a score for each route from `100` minus finding penalties, floored at
zero, then averages route scores:

| Severity | Penalty per finding |
| --- | --- |
| `info` | 0 |
| `low` | 3 |
| `medium` | 8 |
| `high` | 15 |
| `critical` | 25 |

Grades are `A+` for 95+, `A` for 90+, `B` for 80+, `C` for 70+, `D` for 60+, and `F` below 60.

The score is a prioritization aid, not a security guarantee. Pass/fail is calculated separately
from severity and policy threshold. In regression mode, a preview may have a low score and still
pass when it introduced no new threshold-crossing findings.

## Sanitization and redaction

All renderers sanitize untrusted response metadata. The sanitization layer:

- removes credentials, query strings, and fragments from URLs;
- redacts values under names that look like credentials, cookies, passwords, sessions, or tokens;
- recognizes common bearer/basic credentials, JWTs, GitHub tokens, and private-key markers;
- removes control data and bounds evidence and display text;
- escapes output for Markdown, HTML, XML, JSON, and console contexts; and
- keeps duplicate response-header structure in JSON while redacting sensitive values.

Request header values supplied with `--header` are never stored in the report model.

Redaction is defense in depth, not a secret-management system. Do not send report artifacts to a
public location without reviewing their access policy, and never put credentials in target URL
query strings even though reports remove them.
