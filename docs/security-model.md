# Security model

PreviewShield makes outbound requests to URLs chosen by a developer or CI workflow. Its network
layer is designed to make public-site scanning safe by default, including when a target redirects
or DNS returns surprising data. This document defines those guarantees, remaining risks, and the
effect of unsafe overrides.

## Intended use

PreviewShield is designed to:

- issue bounded HTTP GET requests to one or more explicitly selected routes;
- capture response headers, redirect metadata, status, resolved address, timing, and negotiated
  TLS details;
- evaluate deterministic web-hardening rules; and
- compare the resulting findings between two deployments.

It does not crawl, submit forms, execute JavaScript, send attack payloads, or read response
bodies. It is not a penetration test and does not prove that a deployment is secure.

Only scan systems you own or have explicit permission to test. Although GET is conventionally
safe, a broken application can attach side effects to any request.

## Default outbound-request boundary

### URL validation

- Only `http` and `https` are accepted.
- Host/path shorthand defaults to HTTPS.
- URL credentials and user-supplied fragments are rejected; redirect fragments are discarded
  because fragments are not sent in HTTP requests.
- Invalid ports, malformed escaping, control characters, and unsafe hostnames are rejected.
- Request `Host`, framing, connection, and proxy authorization headers cannot be overridden.

### Address validation

For the initial request and every redirect, PreviewShield resolves the hostname itself and checks
every returned address. Unless private access is explicitly enabled, it rejects:

- private networks;
- loopback addresses;
- link-local addresses;
- reserved and unspecified addresses; and
- multicast addresses.

A hostname with a mixture of public and non-public answers is rejected; PreviewShield does not
select only the convenient public answer.

When `network.allowed_hosts` is non-empty, the initial hostname and every redirect hostname must
match it before DNS resolution. This combines a project-specific destination boundary with the
address-class boundary.

### DNS pinning

After validation, the TCP socket connects directly to one of the exact resolved addresses. The
HTTP client does not perform a second hostname resolution. This closes the usual validation-to-
connection gap exploited by DNS rebinding.

For HTTPS, the connection still uses the original URL hostname for SNI and certificate hostname
verification. The default operating-system trust store and Python TLS context remain active.

### Redirects and credentials

- Redirects are bounded and loops fail the scan.
- Every destination is normalized, resolved, and address-validated again.
- Every caller-supplied request header is removed whenever scheme, hostname, or port changes. The
  new origin receives only fresh tool-owned `User-Agent` and `Accept` headers.
- HTTPS-to-HTTP downgrade remains observable as `PS0002` even when the public destination itself
  is reachable.

### Proxies and bodies

Environment and system proxy configuration is not consulted. Requests connect directly to the
validated DNS answer. Response bodies are not read or buffered; only metadata needed by the
checks is captured.

## Resource bounds

Policy validation constrains timeouts, redirects, path shape, and file size. The network layer
also bounds URLs, request-header values, and the cumulative response-header fields accepted from
each hop. A timeout is shared across redirect hops rather than reset for each hop.

System DNS resolution cannot be portably interrupted by Python's standard library. A hostile or
unresponsive resolver can therefore exceed the configured HTTP timeout. Run untrusted scans in a
CI job with its own outer timeout and normal operating-system resource controls.

The local browser interface additionally caps its JSON request size, route count, connection-read
time, active scan count, individual serialized report size, total retained report bytes, and
in-memory report count. Multiple routes are still scanned in sequence, so their individual network
budgets can accumulate. The UI process is not a sandbox or a multi-tenant service.

## `allow_private` changes the boundary

The policy setting `network.allow_private: true`, CLI flag `--allow-private`, Action input
`allow-private: true`, and UI startup flag `--allow-private-targets` permit private, loopback, and
other non-public destinations. The UI also requires a second authorization confirmation in the
browser. These controls are useful for a trusted local test service, but they deliberately remove
the primary SSRF control.

Do not enable it when:

- pull-request authors can influence target URLs, redirects, DNS, or policy;
- the runner can reach cloud instance metadata, control planes, databases, or internal admin
  services; or
- reports or logs are exposed to people who should not learn internal addressing.

If internal scanning is required, use a dedicated runner with narrow egress, an explicit
`network.allowed_hosts` list that covers every intended redirect hop, short timeouts, and no
ambient credentials.

## Request headers and secrets

The CLI accepts repeatable `--header NAME:VALUE` options for authenticated previews. Values are
held only for the request and are not stored in report models. Every caller-supplied header is
stripped on cross-origin redirects.

All report formats apply additional secret and URL redaction. This is defense in depth. Command
arguments may still be visible to local process inspection or CI configuration readers, and a
target server receives the supplied values. Use protected environment variables and least-
privilege, short-lived preview credentials.

## Report safety

Response headers are attacker-controlled text. Renderers remove control data, cap long values,
redact likely credentials, and escape content for their destination format. Standalone HTML does
not load remote scripts or styles.

No pattern-based redaction can recognize every secret. Store reports with the same care as other
security scan artifacts. JSON intentionally contains security-relevant response headers after
sanitization, plus the resolved IP and TLS certificate metadata.

## Local browser interface

`previewshield ui` is a single-user loopback interface, not a hosted scanner. It binds only to
`127.0.0.1` and accepts the exact numeric loopback `Host` value selected at startup. API requests
require a random HttpOnly, SameSite session cookie, an exact same-origin POST, and a separate CSRF
token. CORS is not enabled.

The UI serves only packaged assets under a restrictive CSP. Client code builds finding cards with
text-only DOM properties and does not use `innerHTML`. Downloadable reports are rendered through
the same sanitizing reporters as the CLI, kept in bounded process memory, and addressed by random
session-local identifiers.

Do not expose the UI through a reverse proxy, tunnel, container port publication, or shared host.
Its HTTP cookie is intentionally not marked `Secure` because the supported origin is loopback HTTP;
the exact Host, Origin, CSRF, and SameSite controls form the local request boundary. Stop the
process when the interactive session is finished.

## Policy and comparison assumptions

- A baseline is a comparison reference, not automatically a secure system.
- `regressions` mode allows existing baseline debt to remain without failing the diff.
- Stable fingerprints intentionally exclude hostname; both deployments must expose equivalent
  routes for a meaningful comparison.
- A CDN, authentication gateway, geography, A/B test, or cache may make two responses
  non-equivalent even at the same path.
- Checks see only the final response headers, except redirect-specific rules.
- Scoring is a heuristic and is separate from the severity threshold.

Use `absolute` mode for a compliance gate that must reject all preview findings at the threshold.
Use repeated runs or controlled request headers when the serving layer is nondeterministic.

## Out of scope

PreviewShield does not currently assess:

- HTML, JavaScript, source maps, or response-body content;
- application authorization, injection, business logic, or API schemas;
- all possible CSP semantics or browser-specific behavior;
- the complete TLS configuration offered by a server; it records the negotiated connection;
- DNSSEC, certificate transparency, revocation, or external reputation;
- ports, hosts, or paths discovered by crawling; or
- exploitability of a reported hardening condition.

## Vulnerability reporting

Potential bypasses of address validation, DNS pinning, redirect credential stripping, report
sanitization, Action input handling, or policy parsing are security-sensitive. Report them
privately according to [SECURITY.md](../SECURITY.md), not in a public issue.
