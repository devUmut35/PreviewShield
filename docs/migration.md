# Migrating from Security Header Auditor

PreviewShield is the successor to Security Header Auditor. The original single-file script grew
into an installable package with policy-as-code, secure networking, multi-route scans, deployment
diffs, CI formats, and a GitHub Action.

## Repository and package names

| Before | Now |
| --- | --- |
| `devUmut35/security-header-auditor` | `devUmut35/PreviewShield` |
| `security_header_auditor.py` | `previewshield` CLI |
| `requirements.txt` install | `pip install previewshield` |

GitHub redirects repository renames, but update clone URLs, badges, Action references, and local
remotes deliberately.

```bash
git remote set-url origin https://github.com/devUmut35/PreviewShield.git
```

## Command changes

Basic positional use remains available through the compatibility wrapper:

```bash
python security_header_auditor.py https://example.com
```

New automation should call the installed command explicitly:

```bash
previewshield scan https://example.com
```

Update old report flags:

```bash
# Before
python security_header_auditor.py https://example.com --json -o report.json

# Now
previewshield scan https://example.com --format json --output report.json
```

The former interactive prompt is not part of the new CLI. Commands are explicit and suitable for
shell scripts and CI.

## Adopt a policy

Generate the starter file and commit it:

```bash
previewshield init
previewshield policy validate .previewshield.yml
git add .previewshield.yml
```

The balanced profile fails on high and critical findings. To preserve an existing rollout while
avoiding new debt, start with diff mode:

```bash
previewshield diff \
  --baseline https://example.com \
  --preview https://preview.example.dev \
  --config .previewshield.yml
```

This default gate reports existing production findings but fails only on new findings or severity
increases at the threshold. Move to `diff.mode: absolute` when the preview must satisfy the
complete policy.

## Output compatibility

PreviewShield JSON uses schema version `1.0` and is not the same shape as the original script's
JSON. Update consumers to read the top-level `passed`, `score`, `grade`, and `routes` fields. Diff
reports contain nested `baseline` and `preview` scan reports plus `deltas`.

Do not parse console text. Use JSON for automation, JUnit for test viewers, or SARIF for code
scanning.

## Security behavior changes

PreviewShield blocks non-public addresses by default, ignores environment proxies, validates
every redirect, and verifies TLS normally. A scan that previously reached `localhost`, an RFC1918
address, or an internal DNS name now returns exit code `3` unless private access is explicitly
enabled.

Before using `--allow-private`, review the [security model](security-model.md) and isolate the
runner from unrelated internal services.

## Suggested rollout

1. Run `previewshield scan` locally and review all findings.
2. Add explicit routes and allowed hosts to `.previewshield.yml`.
3. Add a production-to-preview diff with `fail_on: high`.
4. Archive JSON or HTML reports to establish history.
5. Triage baseline debt, documenting any disabled rule or severity override.
6. Tighten the profile or switch to absolute mode when the baseline is ready.
