# Rule catalog

Rule IDs are stable automation keys. Titles and remediation text may improve between releases,
but an existing ID will not be silently reassigned to a different security condition.

List the rules installed with your exact version:

```bash
previewshield rules
previewshield rules --json
```

Policy severity overrides are applied after rule evaluation. Some rules can emit more than once
on a route, such as one cookie finding per cookie.

## Built-in rules

| ID | Default | Category | Condition |
| --- | --- | --- | --- |
| `PS0001` | high | transport | Requested or final route is not protected by end-to-end HTTPS |
| `PS0002` | critical | transport | A redirect moves from HTTPS to HTTP |
| `PS1001` | high | headers | HTTPS response has no `Strict-Transport-Security` policy |
| `PS1002` | medium | headers | HSTS is invalid or shorter than the policy minimum |
| `PS1101` | high | content-security | No enforcing CSP is present; report-only is not enforcement |
| `PS1102` | high | content-security | Enforced CSP permits `'unsafe-eval'` |
| `PS1103` | medium | content-security | CSP permits unsafe inline code without a nonce or hash |
| `PS1104` | medium | content-security | CSP includes a broad wildcard source |
| `PS1105` | medium | content-security | CSP omits the `default-src` fallback |
| `PS1106` | medium | content-security | CSP does not block object sources with an empty or `'none'` list |
| `PS1107` | low | content-security | CSP does not constrain `base-uri` |
| `PS1201` | high | headers | Neither CSP `frame-ancestors` nor valid X-Frame-Options prevents framing |
| `PS1202` | medium | headers | `X-Content-Type-Options` is missing or not `nosniff` |
| `PS1203` | low | privacy | `Referrer-Policy` is missing or unsafe |
| `PS1204` | low | privacy | `Permissions-Policy` is missing |
| `PS1205` | info | headers | Deprecated `X-XSS-Protection` is enabled instead of `0` |
| `PS1301` | medium | cors | Credentials are advertised with an invalid wildcard origin policy |
| `PS1302` | high | cors | CORS trusts a broad or opaque origin; wildcard is emitted as medium |
| `PS1303` | info | cors | A specific allowed origin may need `Vary: Origin` if selected dynamically |
| `PS1401` | medium | cookies | Cookie lacks `Secure` |
| `PS1402` | low | cookies | Cookie lacks `HttpOnly` |
| `PS1403` | low | cookies | Cookie lacks a valid `SameSite` value |
| `PS1404` | high | cookies | `SameSite=None` cookie lacks `Secure` |
| `PS1405` | high | cookies | `__Host-` or `__Secure-` prefix contract is violated |
| `PS1501` | critical | tls | Negotiated TLS protocol is legacy |
| `PS1502` | high | tls | Certificate is expired or within the configured warning window |
| `PS1503` | high | tls | Negotiated cipher contains a known weak marker |
| `PS1601` | low | information-disclosure | `Server` or `X-Powered-By` exposes technology details |
| `PS1602` | high | availability | Route returned a server error response |
| `PS1603` | medium | availability | Route returned a client error response |

Some observations are raised above their catalog default when evidence is unequivocally worse:
invalid or zero-age HSTS and unsafe effective referrer policies are high and medium respectively,
while an expired certificate is critical. Policy overrides are applied after this context.

## Custom required-header rules

`checks.required_headers` creates deterministic IDs by uppercasing the header and replacing
non-alphanumeric groups with underscores:

| Header | Rule ID |
| --- | --- |
| `X-Robots-Tag` | `CUSTOM.X_ROBOTS_TAG` |
| `Cross-Origin-Resource-Policy` | `CUSTOM.CROSS_ORIGIN_RESOURCE_POLICY` |

Custom rules support presence, exact-value, or substring requirements. See
[Required headers](policy-reference.md#required_headers) for configuration.

## Interpreting findings

A PreviewShield finding is a hardening observation, not proof of exploitability. Browser support,
application behavior, CDN behavior, and threat model still matter. Use references and remediation
as a review starting point, test the change, and use policy overrides only when the risk decision
is documented.

Rules inspect the final response and negotiated connection metadata. Redirect downgrade checks
also inspect the redirect chain. PreviewShield does not crawl links or parse response bodies.
