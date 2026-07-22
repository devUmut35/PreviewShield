# Security policy

PreviewShield's network fetcher, policy parser, report renderers, CLI, local browser interface,
and GitHub Action process untrusted input. Responsible vulnerability reports are appreciated.

## Supported versions

| Version | Security fixes |
| --- | --- |
| `1.x` | Supported |
| Pre-PreviewShield `security-header-auditor` versions | Not supported |

Only the latest release in a supported major line is guaranteed to receive a fix. Upgrade before
reporting when practical.

## Report a vulnerability privately

Use [GitHub private vulnerability reporting](https://github.com/devUmut35/PreviewShield/security/advisories/new).
Do not open a public issue, pull request, discussion, or social-media thread before coordinated
disclosure.

Include:

- affected PreviewShield version or commit;
- component and vulnerability class;
- prerequisites and realistic impact;
- minimal, safe reproduction steps or proof of concept;
- whether private addresses, credentials, or a malicious redirect/DNS server are involved;
- suggested mitigation if known; and
- a safe way to contact you for follow-up.

Never include real credentials, customer data, or an internal service that you do not own. Build
a local or disposable reproduction where possible.

## Security-relevant examples

Reports are especially useful for potential:

- SSRF or non-public-address validation bypasses;
- DNS pinning or redirect validation gaps;
- leakage of any caller-supplied header across origins;
- TLS hostname-verification bypasses;
- report injection, stored script execution, or secret-redaction bypasses;
- local UI Host, Origin, session, CSRF, CSP, or report-isolation bypasses;
- policy parser denial of service or unsafe object construction;
- command, argument, output-file, or GitHub workflow injection; and
- vulnerabilities in shipped dependencies or release artifacts.

A security header finding on a scanned third-party website is not a vulnerability in
PreviewShield. Report that issue to the website owner through their own disclosure process.

## Response process

The maintainers aim to:

1. acknowledge a complete report within three business days;
2. confirm scope and severity within seven business days when reproduction is available;
3. develop and test a fix privately;
4. agree on a coordinated disclosure date with the reporter; and
5. publish a security advisory and patched release when users need action.

These are best-effort targets, not a service-level agreement. Complex reports or maintainer
availability may require more time. Please allow a reasonable remediation window before public
disclosure.

## Research safe harbor

We will not pursue legal action against good-faith research that:

- targets PreviewShield itself or infrastructure the researcher owns;
- avoids privacy violations, service disruption, data destruction, and access beyond what is
  needed to demonstrate the issue;
- does not use the scanner against third parties without authorization;
- reports the issue promptly and keeps it confidential during remediation; and
- complies with applicable law.

This statement cannot authorize testing of third-party services, GitHub, PyPI, or infrastructure
outside the project's control.

## Operational guidance

Read the [security model](docs/security-model.md) before scanning internal targets. Keep
`allow_private` disabled for untrusted pull requests, use narrow egress on self-hosted runners,
and treat policy and workflow changes as security-sensitive review.

The browser interface must remain bound to `127.0.0.1`; do not expose it through a reverse proxy,
container port mapping, tunnel, or shared multi-user host. Start it with `--allow-private-targets`
only for a trusted session, and stop it after the private scan is complete.
