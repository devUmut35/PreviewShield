# Examples

These files are starting points; replace example domains and risk decisions before committing
them to a real project.

| File | Purpose |
| --- | --- |
| [previewshield.yml](previewshield.yml) | Balanced public website policy |
| [strict.previewshield.yml](strict.previewshield.yml) | Medium-threshold, one-year HSTS policy |
| [custom-headers.previewshield.yml](custom-headers.previewshield.yml) | Organization-specific required headers |
| [github-action.yml](github-action.yml) | Pull-request diff, artifact, and SARIF workflow |

Validate a policy without contacting a target:

```bash
previewshield policy validate examples/previewshield.yml
```

Use it in a scan:

```bash
previewshield scan https://example.com --config examples/previewshield.yml
```
