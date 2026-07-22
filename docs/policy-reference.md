# Policy reference

PreviewShield policy files use YAML and schema version `1`. Unknown keys, wrong types, unsafe
paths, and out-of-range values fail validation. Files larger than 256 KiB are rejected.

Generate the canonical starter file with:

```bash
previewshield init
```

Validate any policy without making a network request:

```bash
previewshield policy validate .previewshield.yml
```

## Complete example

```yaml
version: 1
name: public-web
profile: balanced
fail_on: high

paths:
  - /
  - /login
  - /api/health

network:
  timeout_seconds: 10
  max_redirects: 5
  allow_private: false
  allowed_hosts:
    - example.com
    - "*.example.dev"
  user_agent: "PreviewShield/1.0 (+https://github.com/devUmut35/PreviewShield)"

checks:
  min_hsts_max_age: 15552000
  certificate_warning_days: 30
  disabled:
    - PS1205
  severity_overrides:
    PS1204: medium
  required_headers:
    X-Robots-Tag:
      severity: medium
      contains: noindex
      remediation: Set X-Robots-Tag to noindex on preview responses.

diff:
  mode: regressions
```

## Root fields

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `version` | integer | `1` | Policy schema; only version `1` is accepted |
| `name` | string | `PreviewShield <profile>` | Display name included in reports, limited to 80 characters |
| `profile` | string | `balanced` | Base defaults: `balanced` or `strict` |
| `fail_on` | severity | profile default | Minimum severity that fails a scan or diff |
| `paths` | string list | `[/]` | Origin-relative routes scanned on each target |
| `network` | mapping | `{}` | Network bounds and destination controls |
| `checks` | mapping | `{}` | Rule selection and rule-specific settings |
| `diff` | mapping | `{}` | Baseline comparison behavior |

Severities, from least to most severe, are `info`, `low`, `medium`, `high`, and `critical`.

## Profiles

Profiles provide defaults; every setting can still be made explicit.

| Profile | `fail_on` | Minimum HSTS `max-age` | Certificate warning | Diff mode |
| --- | --- | --- | --- | --- |
| `balanced` | `high` | 15,552,000 seconds | 30 days | `regressions` |
| `strict` | `medium` | 31,536,000 seconds | 45 days | `regressions` |

When `--profile` and a policy file are both used, the CLI profile is only the fallback if the
file omits `profile`.

## Paths

Paths must:

- be non-empty and origin-relative;
- begin with `/`;
- contain no scheme, hostname, fragment, or `..` segment; and
- optionally include a query string.

Duplicate paths are removed while preserving order. `--path` replaces the policy list for that
invocation; repeat it for multiple routes.

## Network

### `timeout_seconds`

A total timeout shared by all redirect hops. Accepted range: `0.1` to `120` seconds. System DNS
resolution cannot be portably interrupted by Python, so DNS itself may outlive this budget.

### `max_redirects`

Maximum redirects before the scan fails. Accepted range: `0` to `20`.

### `allow_private`

Defaults to `false`. When false, PreviewShield rejects non-public DNS answers and IP literals,
including private, loopback, link-local, reserved, multicast, and unspecified ranges.

Setting this to `true`, or passing `--allow-private`, deliberately removes that boundary. Only do
so for a trusted local or internal test target. Read the [security model](security-model.md).

### `allowed_hosts`

An optional allowlist applied before DNS resolution to the initial target and every redirect hop.
Values are exact hostnames or a leading wildcard such as `"*.example.dev"`. A wildcard matches
subdomains but not the apex (`example.dev`). Internationalized names are normalized to IDNA form.

When the list is empty, any otherwise-safe public hostname is permitted. A redirect to a hostname
outside a non-empty allowlist fails before its DNS lookup.

### `user_agent`

The request User-Agent. It must be non-empty, contain only ISO-8859-1 characters, contain no
control characters, and be at most 200 characters. Invalid values fail policy validation.

## Checks

### `disabled`

A list of stable rule IDs to skip. Use `previewshield rules` to see built-in IDs. Required-header
IDs use `CUSTOM.<NORMALIZED_HEADER>`, for example `X-Robots-Tag` becomes
`CUSTOM.X_ROBOTS_TAG`.

Unknown built-in IDs and custom IDs without a matching `required_headers` entry fail validation,
so a typo cannot silently disable the wrong control.

Prefer documenting the reason in the pull request that changes the policy. Disabling a rule
hides it from both scan findings and comparisons.

### `severity_overrides`

A mapping from rule ID to severity:

```yaml
checks:
  severity_overrides:
    PS1204: medium
    CUSTOM.X_ROBOTS_TAG: high
```

Overrides affect pass/fail decisions, scoring, diffs, and all report formats.

### `required_headers`

Require an application- or organization-specific response header. A value of `true` checks only
for presence:

```yaml
checks:
  required_headers:
    Cross-Origin-Resource-Policy: true
```

Use a mapping to configure the finding:

```yaml
checks:
  required_headers:
    X-Robots-Tag:
      severity: medium
      contains: noindex
      remediation: Prevent preview deployments from being indexed.
```

Options:

| Field | Default | Meaning |
| --- | --- | --- |
| `severity` | `medium` | Severity when the requirement is not met |
| `exact` | none | Require the complete value to match, case-sensitively |
| `contains` | none | Require a case-sensitive substring |
| `remediation` | generic guidance | Replacement text shown in reports |

`exact` and `contains` are mutually exclusive.

### `min_hsts_max_age`

Minimum accepted HSTS `max-age`, from `0` through `630720000` seconds. The profile supplies the
default.

### `certificate_warning_days`

Raise `PS1502` when the negotiated certificate is expired or has no more than this many days
remaining. Accepted range: `1` through `365`.

## Diff mode

`diff.mode` accepts:

- `regressions` (default): fail only on a new finding or a severity increase at or above the
  threshold;
- `absolute`: fail if any preview finding is at or above the threshold, regardless of baseline.

A finding identity combines rule ID, route including its query, and subject. The hostname is
intentionally excluded so different production and preview hosts compare.

## CLI precedence

| CLI option | Effect |
| --- | --- |
| `--path` | Replaces policy paths for that invocation |
| `--fail-on` | Replaces the policy threshold |
| `--allow-private` | Enables private targets for that invocation |
| `--header` | Adds an in-memory request header; values are not stored in the policy or reports |
| `--profile` | Supplies defaults only when the policy omits its profile |

Use [examples/previewshield.yml](../examples/previewshield.yml) for a balanced public service and
[examples/strict.previewshield.yml](../examples/strict.previewshield.yml) for a stricter baseline.
