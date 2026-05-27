from __future__ import annotations

import argparse
import atexit
import ctypes
import json
import os
import shlex
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlparse

import requests


AUTHOR = "devUmut35"
TOOL_NAME = "devUmut35 Security Header Auditor"

CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

REQUIRED_HEADERS = {
    "Content-Security-Policy": "Helps reduce XSS and content injection risks.",
    "Strict-Transport-Security": "Forces browsers to use HTTPS for future requests.",
    "X-Frame-Options": "Helps protect against clickjacking.",
    "X-Content-Type-Options": "Helps reduce MIME sniffing risks.",
    "Referrer-Policy": "Controls how much referrer information is shared.",
    "Permissions-Policy": "Limits browser features such as camera, microphone and geolocation.",
}

OPTIONAL_HEADERS = {
    "Cross-Origin-Opener-Policy": "Helps isolate browsing contexts.",
    "Cross-Origin-Resource-Policy": "Controls which origins can load resources.",
    "Cross-Origin-Embedder-Policy": "Helps strengthen cross-origin isolation.",
}


@dataclass
class HeaderResult:
    name: str
    present: bool
    value: str | None
    note: str


@dataclass
class CookieResult:
    name: str
    secure: bool
    httponly: bool
    samesite: str | None


@dataclass
class ScanResult:
    target: str
    final_url: str
    status_code: int
    https: bool
    score: int
    grade: str
    headers: list[HeaderResult]
    optional_headers: list[HeaderResult]
    cookies: list[CookieResult]
    findings: list[str]


def enable_windows_ansi() -> None:
    if os.name != "nt":
        return
    try:
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 4)
    except Exception:
        pass


def set_title(title: str) -> None:
    if os.name == "nt":
        os.system(f"title {title}")
    else:
        sys.stdout.write(f"\033]0;{title}\007")


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def restore_console() -> None:
    sys.stdout.write(RESET)
    sys.stdout.flush()
    if os.name == "nt":
        os.system("color 07 >nul 2>&1")
        os.system("title Command Prompt")


def start_style() -> None:
    enable_windows_ansi()
    set_title(TOOL_NAME)
    clear_screen()
    if os.name == "nt":
        os.system("color 0B")
    sys.stdout.write(CYAN + BOLD)
    sys.stdout.flush()


def banner() -> None:
    print(r"""
+----------------------------------------------------------------------------+
|                                                                            |
|     ____                      _ _          _   _                _            |
|    / ___|  ___  ___ _   _ _ __(_) |_ _   _| | | | ___  __ _  __| | ___ _ __ |
|    \___ \ / _ \/ __| | | | '__| | __| | | | |_| |/ _ \/ _` |/ _` |/ _ \ '__||
|     ___) |  __/ (__| |_| | |  | | |_| |_| |  _  |  __/ (_| | (_| |  __/ |   |
|    |____/ \___|\___|\__,_|_|  |_|\__|\__, |_| |_|\___|\__,_|\__,_|\___|_|   |
|                                      |___/                                   |
|                           AUDITOR                                           |
|                       signature: devUmut35                                  |
|                                                                            |
+----------------------------------------------------------------------------+
""")


def example_text() -> None:
    print("Example:")
    print("  scan https://example.com")
    print("  scan https://example.com --json")
    print("  scan https://example.com -o report.json")
    print("  scan https://example.com --timeout 10")
    print()


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url:
        raise ValueError("Target URL cannot be empty.")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def check_header(headers: dict, name: str, note: str) -> HeaderResult:
    value = headers.get(name)
    return HeaderResult(name=name, present=value is not None, value=value, note=note)


def parse_cookies(response: requests.Response) -> list[CookieResult]:
    results: list[CookieResult] = []
    raw_headers = []

    if hasattr(response.raw.headers, "get_all"):
        raw_headers = response.raw.headers.get_all("Set-Cookie") or []

    for raw_cookie in raw_headers:
        parts = [part.strip() for part in raw_cookie.split(";")]
        if not parts:
            continue

        cookie_name = parts[0].split("=", 1)[0]
        flags = {part.lower(): part for part in parts[1:]}
        samesite = None

        for part in parts[1:]:
            if part.lower().startswith("samesite="):
                samesite = part.split("=", 1)[1]

        results.append(
            CookieResult(
                name=cookie_name,
                secure="secure" in flags,
                httponly="httponly" in flags,
                samesite=samesite,
            )
        )

    return results


def calculate_score(headers: list[HeaderResult], cookies: list[CookieResult], https: bool) -> int:
    score = 20 if https else 0
    header_points = 60 // len(headers)

    for header in headers:
        if header.present:
            score += header_points

    if cookies:
        cookie_score = 0
        for cookie in cookies:
            cookie_score += int(cookie.secure)
            cookie_score += int(cookie.httponly)
            cookie_score += int(bool(cookie.samesite))
        score += int((cookie_score / (len(cookies) * 3)) * 20)
    else:
        score += 10

    return min(score, 100)


def grade(score: int) -> str:
    if score >= 85:
        return "A"
    if score >= 70:
        return "B"
    if score >= 55:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def build_findings(headers: list[HeaderResult], cookies: list[CookieResult], https: bool) -> list[str]:
    findings = []

    if not https:
        findings.append("HTTPS is not enabled.")

    for header in headers:
        if not header.present:
            findings.append(f"{header.name} header is missing.")

    for cookie in cookies:
        if not cookie.secure:
            findings.append(f"Secure flag is missing on cookie: {cookie.name}.")
        if not cookie.httponly:
            findings.append(f"HttpOnly flag is missing on cookie: {cookie.name}.")
        if not cookie.samesite:
            findings.append(f"SameSite flag is missing on cookie: {cookie.name}.")

    if not findings:
        findings.append("No critical basic header or cookie issue was detected.")

    return findings


def scan(url: str, timeout: float) -> ScanResult:
    target = normalize_url(url)

    response = requests.get(
        target,
        timeout=timeout,
        allow_redirects=True,
        headers={"User-Agent": f"{AUTHOR}-security-header-auditor/1.0"},
    )

    parsed = urlparse(response.url)
    https = parsed.scheme == "https"

    headers = [check_header(response.headers, name, note) for name, note in REQUIRED_HEADERS.items()]
    optional_headers = [check_header(response.headers, name, note) for name, note in OPTIONAL_HEADERS.items()]
    cookies = parse_cookies(response)
    score = calculate_score(headers, cookies, https)
    findings = build_findings(headers, cookies, https)

    return ScanResult(
        target=target,
        final_url=response.url,
        status_code=response.status_code,
        https=https,
        score=score,
        grade=grade(score),
        headers=headers,
        optional_headers=optional_headers,
        cookies=cookies,
        findings=findings,
    )


def print_header_result(result: HeaderResult) -> None:
    if result.present:
        print(f"[OK]      {result.name}: {result.value}")
    else:
        print(f"[MISSING] {result.name} - {result.note}")


def print_cookie_result(cookie: CookieResult) -> None:
    secure = "OK" if cookie.secure else "MISSING"
    httponly = "OK" if cookie.httponly else "MISSING"
    samesite = cookie.samesite or "MISSING"

    print(f"[COOKIE]  {cookie.name}")
    print(f"          Secure   : {secure}")
    print(f"          HttpOnly : {httponly}")
    print(f"          SameSite : {samesite}")


def print_report(result: ScanResult) -> None:
    print(f"Target     : {result.target}")
    print(f"Final URL  : {result.final_url}")
    print(f"Status     : {result.status_code}")
    print(f"HTTPS      : {'YES' if result.https else 'NO'}")
    print(f"Score      : {result.score}/100")
    print(f"Grade      : {result.grade}")
    print("-" * 80)

    print("Required Headers")
    for header in result.headers:
        print_header_result(header)

    print("-" * 80)
    print("Optional Headers")
    for header in result.optional_headers:
        print_header_result(header)

    print("-" * 80)
    print("Cookies")
    if result.cookies:
        for cookie in result.cookies:
            print_cookie_result(cookie)
    else:
        print("No Set-Cookie header detected.")

    print("-" * 80)
    print("Findings")
    for item in result.findings:
        print(f"- {item}")

    print("-" * 80)


def result_to_json(result: ScanResult) -> str:
    return json.dumps(asdict(result), indent=2, ensure_ascii=False)


def ask(question: str, default: bool) -> bool:
    suffix = "Y/n" if default else "y/N"
    try:
        answer = input(f"{question} [{suffix}]: ").strip().lower()
    except KeyboardInterrupt:
        print()
        return default
    if not answer:
        return default
    return answer in {"y", "yes"}


def run_scan(target: str, timeout: float, json_output: bool, output: str | None) -> int:
    try:
        result = scan(target, timeout)
    except requests.RequestException as error:
        print(f"Request error: {error}", file=sys.stderr)
        return 1
    except ValueError as error:
        print(f"Input error: {error}", file=sys.stderr)
        return 1

    if json_output:
        print(result_to_json(result))
    else:
        print_report(result)

    if output:
        Path(output).write_text(result_to_json(result), encoding="utf-8")
        print(f"Saved: {output}")

    return 0


def parser() -> argparse.ArgumentParser:
    app = argparse.ArgumentParser(prog="security_header_auditor", description="Security Header Auditor by devUmut35")
    app.add_argument("target", nargs="?")
    app.add_argument("-u", "--url")
    app.add_argument("--timeout", type=float, default=6.0)
    app.add_argument("--json", action="store_true")
    app.add_argument("-o", "--output")
    return app


def help_text() -> None:
    print("Commands:")
    print("  scan https://example.com")
    print("  scan https://example.com --json")
    print("  scan https://example.com -o report.json")
    print("  scan https://example.com --timeout 10")
    print("  clear")
    print("  help")
    print("  exit")
    print()


def interactive() -> int:
    app = parser()
    example_text()

    while True:
        try:
            command = input("HeaderAudit> ").strip()
        except KeyboardInterrupt:
            print()
            if ask("Exit Security Header Auditor?", False):
                print("bye.")
                time.sleep(0.7)
                clear_screen()
                return 0
            continue
        except EOFError:
            print()
            return 0

        if not command:
            continue

        lowered = command.lower()

        if lowered in {"exit", "quit"}:
            print("bye.")
            time.sleep(0.7)
            clear_screen()
            return 0

        if lowered in {"help", "?"}:
            help_text()
            continue

        if lowered in {"clear", "cls"}:
            clear_screen()
            banner()
            example_text()
            continue

        if lowered.startswith("scan "):
            try:
                args = app.parse_args(shlex.split(command)[1:])
            except SystemExit:
                print("Invalid command. Type help.")
                continue

            target = args.target or args.url
            if not target:
                print("Example: scan https://example.com")
                continue

            run_scan(target, args.timeout, args.json, args.output)
            continue

        print("Unknown command. Type help.")


def main() -> int:
    atexit.register(restore_console)
    start_style()
    banner()

    app = parser()
    args = app.parse_args()
    target = args.target or args.url

    if not target:
        return interactive()

    try:
        return run_scan(target, args.timeout, args.json, args.output)
    except KeyboardInterrupt:
        print()
        if ask("Exit Security Header Auditor?", True):
            print("bye.")
            time.sleep(0.7)
            clear_screen()
            return 130
        return 0
    except Exception as error:
        print(f"Error: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
