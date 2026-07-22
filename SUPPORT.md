# Support

PreviewShield is a community-maintained open-source project. Support is best-effort and does not
include an uptime or response-time guarantee.

## Before asking for help

1. Read the [getting-started guide](docs/getting-started.md) and
   [policy reference](docs/policy-reference.md).
2. Run `previewshield --version` and reproduce with the latest supported release.
3. Run `previewshield policy validate PATH` when configuration is involved.
4. Search [existing issues](https://github.com/devUmut35/PreviewShield/issues) for the exact error
   or rule ID.
5. Remove credentials, internal hostnames, private addresses, and sensitive response data from
   anything you plan to post publicly.

## Where to ask

- Reproducible defects belong in a
  [bug report](https://github.com/devUmut35/PreviewShield/issues/new?template=bug_report.yml).
- Product proposals belong in a
  [feature request](https://github.com/devUmut35/PreviewShield/issues/new?template=feature_request.yml).
- Security vulnerabilities must follow [SECURITY.md](SECURITY.md) and must not be posted publicly.

Include the version, operating system, Python version, redacted command, policy, expected result,
actual result, and smallest safe reproduction. Maintainers may close requests that cannot be
reproduced or that concern an unsupported version.

## Scope

The issue tracker is not a security consulting service and cannot determine whether a third-party
website is vulnerable. PreviewShield findings are hardening signals; remediation must be reviewed
in the application's own architecture and threat model.

Commercial support and private remediation guidance are not currently offered.
