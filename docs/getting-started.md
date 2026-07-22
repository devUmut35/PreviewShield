# Getting started

PreviewShield can audit one deployment or compare a known-good production deployment with a
preview. The comparison is usually the most useful CI mode because it separates existing
security debt from changes introduced by the current release.

## Requirements

- Python 3.10 or newer for the CLI
- A network path from the runner to every target
- Explicit authorization to send HTTP GET requests to those targets
- Docker only when running the GitHub Action locally; CLI use does not require it

## Install

From PyPI after the first release is published:

```bash
python -m pip install previewshield
previewshield --version
```

From the repository:

```bash
git clone https://github.com/devUmut35/PreviewShield.git
cd PreviewShield
python -m pip install -e .
```

For an isolated command-line install, `pipx install previewshield` also works once the package
is available on PyPI.

## Open the local web interface

For a guided first run, start PreviewShield's local release control room:

```bash
previewshield ui
```

The command binds only to `127.0.0.1:8765` and opens a browser automatically. The interface can
scan one deployment, compare production with a preview, filter findings, and download reports.
No account, database, hosted scanner, or separate frontend installation is required.

Use `previewshield ui --no-open` when you want to open the printed URL yourself. Private and
loopback targets are deliberately locked in normal UI sessions; read the [web UI guide](web-ui.md)
before enabling them.

## Run a scan

A hostname without a scheme defaults to HTTPS:

```bash
previewshield scan example.com
```

To scan several origin-relative routes, repeat `--path`:

```bash
previewshield scan https://example.com \
  --path / \
  --path /login \
  --path '/api/health?verbose=false'
```

When no explicit paths are supplied, the policy's `paths` list is used. If the default policy
contains only `/` and the target itself contains a path, that target path is preserved.

## Compare production and preview

```bash
previewshield diff \
  --baseline https://example.com \
  --preview https://pr-142.example.dev \
  --path / \
  --path /login \
  --fail-on high
```

Both targets receive the same paths, request headers, policy, timeout, and threshold. Findings
are matched using a stable identity made from the rule, route, and subject rather than the
hostname.

The default `regressions` mode fails on:

- a new finding at or above the threshold; or
- an existing finding whose severity increased to or above the threshold.

Resolved and unchanged findings remain in the report. Use `diff.mode: absolute` if every preview
finding at the threshold should fail, even when it already exists in production.

## Create a policy

```bash
previewshield init
previewshield policy validate .previewshield.yml
previewshield scan example.com --config .previewshield.yml
```

`init` refuses to replace an existing file unless `--force` is provided. Policy files are
strictly validated; misspelled keys produce a configuration error.

Start with [the balanced example](../examples/previewshield.yml) or read the complete
[policy reference](policy-reference.md).

## Save reports

The default console report goes to standard output. Choose a format and output file for CI:

```bash
previewshield scan example.com --format json --output previewshield.json
```

Create several representations without repeating the scan:

```bash
previewshield diff \
  --baseline https://example.com \
  --preview https://preview.example.dev \
  --format markdown --output previewshield.md \
  --also-format sarif=previewshield.sarif \
  --also-format junit=previewshield.xml
```

Available formats are `console`, `html`, `json`, `junit`, `markdown`, and `sarif`.

## Authenticated previews

Repeat `--header` to add request headers:

```bash
previewshield scan https://preview.example.dev \
  --header "Authorization: Bearer $PREVIEW_TOKEN" \
  --header "X-Preview-Access: $PREVIEW_ACCESS"
```

PreviewShield does not write request header values to reports and drops every caller-supplied
header on cross-origin redirects. The redirected request receives only fresh tool-owned headers.
Avoid placing secrets directly on a shared command line; prefer environment expansion in a
protected CI job.

Transport framing headers, `Host`, and proxy authorization cannot be overridden.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan or diff completed and passed, or an informational command succeeded |
| `1` | A finding or regression crossed the configured failure threshold |
| `2` | CLI arguments or policy configuration were invalid |
| `3` | The network safety boundary rejected the target, or the scan could not connect |
| `4` | A report or unexpected internal operation failed |
| `130` | The process was interrupted from the keyboard |

Treat `1` as a security policy decision. Codes `2` through `4` indicate that no reliable gate
decision was produced and should also fail a CI job.

## Next steps

- Put the policy under version control.
- Add every security-relevant public route, not just `/`.
- Use an explicit `network.allowed_hosts` list in stable CI environments.
- Add the [GitHub Action](github-action.md) after preview deployment.
- Review the [security model](security-model.md) before enabling private targets.
