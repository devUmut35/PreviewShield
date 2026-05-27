# Security Header Auditor

<p align="center">
  <img src="https://img.shields.io/badge/Author-devUmut35-blue?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Category-Web%20Security-cyan?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Python-3.x-yellow?style=for-the-badge&logo=python&logoColor=white" />
</p>

<p align="center">
  <b>A simple HTTP security header and cookie configuration audit tool.</b>
</p>

---

## About

**Security Header Auditor** is a Python tool that checks the basic security configuration of a website.

The tool does not attack the target.  
It sends a normal HTTP request and audits the response headers and cookie flags.

It checks:

- HTTPS usage
- Missing HTTP security headers
- Cross-origin security headers
- Cookie security flags
- Basic security score
- Audit findings

---

## What Is It Useful For?

This tool does not prove that a website is exploitable.

It helps identify weak security hardening such as:

- Missing `Strict-Transport-Security`
- Missing `X-Frame-Options`
- Missing `X-Content-Type-Options`
- Missing `Referrer-Policy`
- Missing `Permissions-Policy`
- Missing `Secure`, `HttpOnly`, or `SameSite` cookie flags

These findings are generally evaluated as **security misconfiguration** or **web hardening issues**.

---

## Features

- Interactive mode
- Direct scan mode
- Cyan terminal theme
- Windows CMD title support
- Safe `Ctrl+C` exit
- HTTP security header audit
- Cookie flag audit
- HTTPS detection
- Score and grade output
- JSON output support
- Report export

---

## Installation

```bash
git clone https://github.com/devUmut35/security-header-auditor.git
cd security-header-auditor
pip install -r requirements.txt
```

---

## Usage

Direct scan:

```bash
py security_header_auditor.py https://example.com
```

Interactive mode:

```bash
py security_header_auditor.py
```

Then:

```txt
scan https://example.com
```

JSON output:

```bash
py security_header_auditor.py https://example.com --json
```

Save report:

```bash
py security_header_auditor.py https://example.com -o report.json
```

Set timeout:

```bash
py security_header_auditor.py https://example.com --timeout 10
```

---

## Checked Headers

| Header | Purpose |
|---|---|
| `Content-Security-Policy` | Helps reduce XSS and content injection risks |
| `Strict-Transport-Security` | Forces browsers to use HTTPS |
| `X-Frame-Options` | Helps protect against clickjacking |
| `X-Content-Type-Options` | Helps reduce MIME sniffing risks |
| `Referrer-Policy` | Controls referrer information |
| `Permissions-Policy` | Limits browser feature permissions |

---

## Cookie Checks

| Flag | Purpose |
|---|---|
| `Secure` | Sends cookies only over HTTPS |
| `HttpOnly` | Blocks JavaScript access to cookies |
| `SameSite` | Helps reduce CSRF risk |

---

## Example Output

```txt
Target     : https://example.com
Final URL  : https://example.com/
Status     : 200
HTTPS      : YES
Score      : 40/100
Grade      : D
--------------------------------------------------------------------------------
Required Headers
[OK]      Content-Security-Policy: upgrade-insecure-requests
[MISSING] Strict-Transport-Security - Forces browsers to use HTTPS for future requests.
[MISSING] X-Frame-Options - Helps protect against clickjacking.
--------------------------------------------------------------------------------
Findings
- Strict-Transport-Security header is missing.
- X-Frame-Options header is missing.
```

---

## Project Structure

```txt
security-header-auditor/
├── security_header_auditor.py
├── requirements.txt
├── README.md
└── .gitignore
```

---

## Legal Notice

Use only on systems you own, CTF/lab environments, or targets where you have explicit permission.

---

## Author

**devUmut35**
