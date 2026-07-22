# Pull request

## Summary

<!-- What user problem does this change solve? Keep this focused. -->

## Behavior and security impact

<!-- Describe observable behavior and any policy, rule-ID, schema, exit-code, network, secret,
or compatibility impact. Write "None" where appropriate. -->

## Validation

<!-- List the exact checks you ran and relevant results. -->

- [ ] `python -m ruff format --check .`
- [ ] `python -m ruff check .`
- [ ] `python -m mypy`
- [ ] `python -m bandit -c pyproject.toml -r src`
- [ ] `python -m pytest`

## Checklist

- [ ] The change is focused and linked to an issue when design discussion was needed.
- [ ] Tests cover new behavior, edge cases, and failure paths.
- [ ] Documentation and `CHANGELOG.md` reflect user-visible changes.
- [ ] Stable rule IDs, JSON schema, SARIF fingerprints, and exit codes remain compatible, or the
      breaking impact is explicitly justified.
- [ ] Examples, fixtures, logs, and reports contain no credentials or unauthorized target data.
- [ ] Network or renderer changes include adversarial tests for the affected trust boundary.
- [ ] I have read and agree to follow the [Code of Conduct](../CODE_OF_CONDUCT.md).
