# Python API

PreviewShield exposes a small synchronous Python API backed by the same scanner, policy engine,
and network controls as the CLI.

## Scan a target

```python
from previewshield import Severity, scan

report = scan(
    "https://example.com",
    paths=("/", "/login"),
    fail_on=Severity.HIGH,
)

print(report.score, report.grade, report.passed)
for finding in report.findings:
    print(finding.rule_id, finding.severity.value, finding.message)
```

`scan()` returns an immutable `ScanReport`. Its `routes` retain the captured response snapshot and
findings for every path. The `findings` and `counts` properties provide flattened views.

## Compare two deployments

```python
from previewshield import Severity, diff

report = diff(
    "https://example.com",
    "https://preview.example.dev",
    paths=("/", "/login"),
    fail_on=Severity.HIGH,
)

if not report.passed:
    for delta in report.regressions:
        print(delta.finding.rule_id, delta.finding.title)
```

`DiffReport` exposes `regressions`, `resolved`, and `unchanged` properties. The complete `deltas`
tuple also contains non-regressive `changed` findings.

## Load a policy

```python
from previewshield import scan
from previewshield.policy import load_policy

policy = load_policy(".previewshield.yml")
report = scan("https://example.com", policy=policy)
```

Or use an in-memory validated mapping:

```python
from previewshield.policy import policy_from_mapping

policy = policy_from_mapping(
    {
        "version": 1,
        "profile": "strict",
        "paths": ["/", "/login"],
        "diff": {"mode": "regressions"},
    }
)
```

Do not instantiate `Policy` directly from untrusted data; the loader enforces types, ranges, safe
paths, and known keys.

## Request headers and private targets

```python
import os

from previewshield import scan

report = scan(
    "https://preview.example.dev",
    request_headers={"Authorization": f"Bearer {os.environ['PREVIEW_TOKEN']}"},
)
```

Set `allow_private=True` only for explicitly trusted internal test targets. It has the same
security implications as the CLI flag described in the [security model](security-model.md).

## Render a report

```python
from pathlib import Path

from previewshield import scan
from previewshield.reporters import render

report = scan("https://example.com")
Path("previewshield.sarif").write_text(
    render(report, "sarif"),
    encoding="utf-8",
)
```

Supported names are available from `previewshield.reporters.supported_formats()`.

## Exceptions

Expected failures inherit from `PreviewShieldError`:

```python
from previewshield import scan
from previewshield.exceptions import PreviewShieldError

try:
    report = scan("https://example.com")
except PreviewShieldError as error:
    print(error, error.exit_code)
```

`ConfigurationError`, `NetworkSafetyError`, `ScanError`, and `ReportError` distinguish common
failure classes. Policy failure is represented by `report.passed == False`; the Python API does
not raise just because the threshold was crossed.

The API performs synchronous network I/O. Applications with an async event loop should run it in
a worker thread or process and retain their own outer timeout.
