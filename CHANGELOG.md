# Changelog

All notable changes to PreviewShield are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Local-only `previewshield ui` release control room with guided scan and diff workflows, finding
  filters, in-memory multi-format report downloads, and GitHub Action YAML generation.
- Loopback UI protections including exact Host and Origin validation, HttpOnly SameSite sessions,
  CSRF tokens, strict CSP, bounded requests and report memory, concurrency limits, and opt-in
  private targets.
- Browser behavior tests for result-mode snapshots and generated GitHub Action workflows.

## [1.0.0] - 2026-07-22

### Added

- Production-to-preview security regression comparison with stable finding fingerprints.
- Policy schema version 1 with balanced and strict profiles, multi-route scans, severity
  overrides, disabled rules, custom required headers, and regression or absolute diff modes.
- Thirty built-in checks covering HTTP transport, TLS, CSP, browser hardening headers, CORS,
  cookie attributes, information disclosure, and response health.
- DNS-pinned network fetcher with public-address validation, redirect checks, TLS hostname
  verification, sensitive-header stripping, bounded requests, and no proxy discovery.
- Console, JSON, Markdown, SARIF 2.1.0, JUnit XML, and standalone HTML reporters with output
  sanitization and secret redaction.
- Docker-based GitHub Action with job summaries and report, score, grade, and passed outputs.
- Typed Python API, Python 3.10 through 3.13 support, test suite, security checks, packaging, and
  PyPI trusted-publishing workflow.

[Unreleased]: https://github.com/devUmut35/PreviewShield/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/devUmut35/PreviewShield/releases/tag/v1.0.0
