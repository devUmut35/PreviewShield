# GitHub Action

The PreviewShield Action runs the same engine as the CLI in a Docker container. It supports a
single-target scan or a production-to-preview diff, writes a GitHub job summary, and generates
JSON, Markdown, and SARIF reports in one invocation.

Pin a stable major release in normal use:

```yaml
- uses: devUmut35/PreviewShield@v1
```

Security-sensitive organizations may instead pin a full commit SHA and update it deliberately.

## Preview regression gate

Run PreviewShield after the job that publishes the preview. In this provider-neutral example,
`vars.PREVIEW_URL` stands for the deployment URL. Replace it with a trusted output from your own
deployment job or integration.

```yaml
name: Preview security

on:
  pull_request:

permissions:
  contents: read

jobs:
  previewshield:
    runs-on: ubuntu-latest
    steps:
      - name: Check out policy
        uses: actions/checkout@v6

      - name: Gate web security regressions
        id: previewshield
        uses: devUmut35/PreviewShield@v1
        with:
          baseline: https://example.com
          preview: ${{ vars.PREVIEW_URL }}
          config: .previewshield.yml
          paths: |
            /
            /login
            /api/health
          fail-on: high
          format: json
          output: previewshield-report.json

      - name: Preserve report
        if: always()
        uses: actions/upload-artifact@v7
        with:
          name: previewshield-report
          path: |
            previewshield-report.json
            previewshield-report.md
            previewshield-report.sarif
          if-no-files-found: warn
```

The Action exits with the CLI status. A policy violation therefore fails the job while the
`if: always()` artifact step can still preserve the generated report.

## Single-target scan

Use `target` without `baseline` or `preview`:

```yaml
- name: Audit production
  uses: devUmut35/PreviewShield@v1
  with:
    target: https://example.com
    paths: /,/login,/api/health
    fail-on: high
    format: markdown
    output: previewshield.md
```

`target` and `baseline`/`preview` are mutually exclusive. Diff mode requires both baseline and
preview.

## Inputs

| Input | Required | Default | Description |
| --- | --- | --- | --- |
| `target` | conditional | empty | URL for scan mode |
| `baseline` | conditional | empty | Production or known-good URL for diff mode |
| `preview` | conditional | empty | Preview URL for diff mode |
| `config` | no | empty | Repository-relative PreviewShield YAML policy path |
| `paths` | no | `/` | Comma-separated or multiline origin-relative paths |
| `fail-on` | no | `high` | Minimum failing severity |
| `format` | no | `json` | Primary format: `json`, `markdown`, or `sarif` |
| `output` | no | format-specific | Primary report path |
| `allow-private` | no | `false` | Permit private and loopback targets |

Accepted boolean values for `allow-private` are `true`/`false`, `1`/`0`, `yes`/`no`, and
`on`/`off`.

The Action does not expose the CLI's arbitrary request-header option. Use the CLI in a protected
workflow step if a preview requires custom authentication headers.

## Outputs

Give the step an `id` to use these outputs:

| Output | Description |
| --- | --- |
| `report` | Path to the selected primary report |
| `score` | Numeric score for the target, or for the preview in diff mode |
| `grade` | Grade for the target, or for the preview in diff mode |
| `passed` | `true` or `false` based on the configured policy |

```yaml
- name: Show decision
  if: always()
  env:
    SCORE: ${{ steps.previewshield.outputs.score }}
    GRADE: ${{ steps.previewshield.outputs.grade }}
    PASSED: ${{ steps.previewshield.outputs.passed }}
  run: echo "PreviewShield passed=$PASSED score=$SCORE grade=$GRADE"
```

The job summary contains the Markdown report. If the report cannot be read, the adapter writes a
small fallback summary instead.

## Sidecar reports

The Action always asks the engine for JSON, Markdown, and SARIF. `format` selects which one is
exposed by `report` and which exact path receives `output`; the other two use the same base name
with their natural extensions.

For example:

```yaml
with:
  format: sarif
  output: security/previewshield.sarif
```

creates:

```text
security/previewshield.sarif
security/previewshield.json
security/previewshield.md
```

## Upload SARIF to GitHub code scanning

GitHub code scanning requires `security-events: write`. Diff SARIF contains only regressions;
scan SARIF contains all findings.

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v6

  - name: Run PreviewShield
    id: previewshield
    uses: devUmut35/PreviewShield@v1
    with:
      baseline: https://example.com
      preview: ${{ vars.PREVIEW_URL }}
      config: .previewshield.yml
      format: sarif
      output: previewshield.sarif

  - name: Upload SARIF
    if: always() && hashFiles('previewshield.sarif') != ''
    uses: github/codeql-action/upload-sarif@v4
    with:
      sarif_file: previewshield.sarif
```

GitHub may restrict security-event writes for workflows from forks. Review repository permission
settings before relying on SARIF upload for untrusted pull requests.

## Trust boundaries

- Never construct baseline or preview URLs directly from untrusted pull-request text.
- Keep `allow-private: false` for untrusted code and public preview URLs.
- Treat changes to `.previewshield.yml` and the workflow as security-sensitive code review.
- Use `network.allowed_hosts` when preview hostnames follow a predictable pattern.
- Do not put credentials in URLs. URL user information is rejected.
- Preserve codes `2` through `4` as CI failures; they mean the gate could not produce a reliable
  decision.

For the underlying controls and remaining risks, see the
[PreviewShield security model](security-model.md).

## Testing a checkout before release

Inside this repository, `uses: ./` builds the local Docker Action:

```yaml
- uses: ./
  with:
    target: https://example.com
    fail-on: critical
```

Consumers should use a released tag or immutable commit from
`devUmut35/PreviewShield`, not `uses: ./`.
