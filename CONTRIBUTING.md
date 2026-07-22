# Contributing to PreviewShield

Thank you for helping make web security regressions easier to catch. Contributions of code,
tests, documentation, threat-model review, new rules, and reproducible bug reports are welcome.

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md). Security vulnerabilities
must be reported privately according to [SECURITY.md](SECURITY.md).

## Start with an issue

For a substantial rule, public API, policy schema, network behavior, or report-format change, open
an issue before investing in implementation. A short design discussion helps protect stable rule
IDs and output compatibility. Small documentation corrections and focused bug fixes can go
directly to a pull request.

- [Report a bug](https://github.com/devUmut35/PreviewShield/issues/new?template=bug_report.yml)
- [Request a feature](https://github.com/devUmut35/PreviewShield/issues/new?template=feature_request.yml)

## Development setup

Fork and clone the repository, then create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Linux or macOS:

```bash
source .venv/bin/activate
```

Or on PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Install the package and development tools:

```bash
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

PreviewShield supports Python 3.10 and newer. CI exercises Python 3.10 through 3.13; use one of
those versions locally.

## Make a focused change

- Branch from the latest `main`.
- Keep a pull request focused on one problem.
- Preserve public API, rule IDs, JSON schema, and exit-code compatibility unless the proposal
  explicitly addresses a breaking change.
- Add or update tests for behavior changes.
- Update documentation and `CHANGELOG.md` when users will notice the change.
- Never include real tokens, internal URLs, customer headers, or sensitive scan output in tests.

Use clear commit messages. Conventional Commit prefixes such as `feat:`, `fix:`, `docs:`, and
`test:` are encouraged but not required for external contributions.

## Validate the change

Run the complete local gate before opening a pull request:

```bash
python -m ruff format --check .
python -m ruff check .
python -m mypy
python -m bandit -c pyproject.toml -r src
python -m pip_audit --strict
node --check src/previewshield/webui/assets/app.js
node --check src/previewshield/webui/assets/logic.mjs
node --test tests/test_webui_logic.mjs
python -m pytest
python -m build
python -m twine check dist/*
```

To apply Python formatting before the check:

```bash
python -m ruff format .
```

Tests must not depend on arbitrary public services. Mock DNS and connections or use a loopback
fixture with the private-target boundary enabled explicitly. Network safety tests should cover
both the intended path and bypass attempts.

## Adding or changing a rule

A useful rule is deterministic, evidence-based, actionable, and tied to a defensible reference.
A rule pull request should include:

- the threat or hardening failure it detects;
- an OWASP, MDN, standards, or similarly authoritative reference;
- a default severity rationale;
- precise pass, fail, edge-case, and disabled-rule tests;
- remediation that a developer can apply; and
- behavior in production-to-preview comparison.

Built-in IDs use `PS` plus four digits. Do not reuse or renumber a released ID. Coordinate a new
ID in the issue or pull request. Changes that make a rule materially broader may need a new ID to
avoid surprising existing policies.

## Reporter changes

All renderers process attacker-controlled response metadata. Use the shared sanitizer and the
output format's escaping primitives. Add tests for control characters, markup injection, URL
credentials and query strings, duplicate headers, long values, and recognizable token patterns.

JSON shape and SARIF fingerprints are public integration contracts. Call out any compatibility
impact explicitly.

## Network and Action changes

The outbound-request code and GitHub Action are high-risk surfaces. Contributions must preserve:

- validation of every DNS answer and redirect destination;
- direct connection to a validated, pinned address;
- normal TLS hostname verification and SNI;
- removal of all caller-supplied headers on cross-origin redirects;
- bounded timeouts, redirects, URLs, and headers;
- no implicit proxy discovery; and
- shell-free handling of user-controlled Action inputs.

Explain the threat model in the pull request and include adversarial tests for any changed trust
boundary.

Local browser UI changes must preserve the exact Host, Origin, session, CSRF, CSP, request-size,
concurrency, and private-target controls. Never render scan data through `innerHTML`, persist scan
credentials in browser storage, or add external scripts, fonts, analytics, or CDN dependencies.

## Documentation style

- Write concise, inclusive English.
- Use examples that can be copied safely after replacing `example.com` values.
- Do not promise a security guarantee or describe a hardening finding as proof of exploitation.
- Use repository-relative links for project files and HTTPS for external references.
- Wrap commands in fenced blocks and name the language when useful.

## Pull-request review

Maintainers may request changes for correctness, security, compatibility, scope, test coverage,
or documentation. Approval does not guarantee an immediate release. By contributing, you agree
that your contribution is licensed under the repository's Apache License 2.0.
