# Local web interface

PreviewShield includes a guided browser interface for people who do not want to assemble every
scan as a terminal command. The CLI and GitHub Action remain the automation interfaces; the web UI
is a local presentation layer over the same policy, scanner, diff, and reporter code.

## Start it

```bash
previewshield ui
```

The command listens only on `http://127.0.0.1:8765/`, opens the default browser, and keeps running
until `Ctrl+C` is pressed in the terminal. Choose another loopback port or suppress automatic
browser launch when needed:

```bash
previewshield ui --port 9000
previewshield ui --no-open
```

## Available workflows

### Compare deployments

This is the recommended mode. Enter the production and preview URLs, select the routes, choose a
balanced or strict profile, and set the failure threshold. The result shows:

- the production and preview scores on either side of the security seam;
- regressions, resolved findings, changed findings, and unchanged security debt;
- actionable rule, route, evidence, and remediation details; and
- the final policy decision as `PASS` or `BLOCK`.

`BLOCK` means the configured policy threshold was crossed. It does not mean the application is
known to be exploitable. Likewise, `PASS` is not a security guarantee.

### Scan one site

Use the single-site tab for an initial posture check when no baseline is available. Findings are
grouped by severity and can be filtered before downloading the full report.

## Download evidence

After a successful scan request—even one whose security decision is `BLOCK`—the UI can download
the same sanitized formats as the CLI:

- standalone HTML;
- JSON;
- Markdown;
- SARIF 2.1.0; and
- JUnit XML.

Reports are held only in bounded process memory. They disappear when the UI stops and are never
written to disk unless the browser user explicitly downloads one. The “Copy GitHub Action” button
creates a starter workflow from the current URLs, routes, and threshold.

## Private and localhost targets

Private, loopback, link-local, and other non-public addresses remain blocked by default. For a
trusted local development environment, restart the UI with:

```bash
previewshield ui --allow-private-targets
```

Then enable private targets inside Advanced network access and confirm that you own or are
authorized to scan them. This startup flag relaxes a core SSRF boundary for the entire UI session.
Do not use it while browsing untrusted pages, and stop the process when the local scan is complete.

The first UI release intentionally does not accept custom request headers or arbitrary policy-file
paths. Authenticated previews and repository policy files remain available through the CLI and
GitHub Action, where secret and filesystem handling are explicit.

## Local security controls

The browser never connects to the target directly. It sends JSON to the loopback server, which
calls PreviewShield's Python API and safe network layer. The server:

1. binds only to `127.0.0.1`;
2. accepts only its exact `Host` value;
3. requires a random HttpOnly, SameSite session cookie;
4. requires an exact same-origin POST and a separate CSRF token;
5. does not enable CORS;
6. limits request size, route count, response-header bytes, connection-read time, concurrent scans,
   and retained report bytes;
7. renders untrusted values with text-only DOM operations; and
8. applies a restrictive CSP and other browser security headers to every handled response.

The scan engine's documented residual risks still apply, including non-interruptible system DNS
resolution and cumulative time across multiple routes. Review the complete
[security model](security-model.md) before using PreviewShield in a sensitive network.

## Troubleshooting

If port 8765 is already in use, choose another port with `--port`. If the page is open but API
requests report an invalid session, close stale tabs and reopen the exact URL printed by the newest
PreviewShield process. Browser extensions that rewrite `Host`, `Origin`, cookies, or CSP may also
interfere with the local security checks.
