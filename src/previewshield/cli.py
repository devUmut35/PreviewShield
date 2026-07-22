"""Command-line interface for local scans and CI security regression gates."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import NoReturn, cast

from previewshield._version import __version__
from previewshield.checks import RULES
from previewshield.diffing import diff_targets
from previewshield.exceptions import ConfigurationError, PreviewShieldError, ReportError
from previewshield.models import DiffReport, ScanReport, Severity
from previewshield.policy import default_policy_yaml, load_policy
from previewshield.reporters import render, supported_formats
from previewshield.scanner import scan
from previewshield.utils import parse_threshold, validate_header_name

_CONTROL_CHARACTER = re.compile(r"[\x00-\x1f\x7f]")
_MIN_UI_PORT = 1_024
_MAX_UI_PORT = 65_535
Report = ScanReport | DiffReport


class _Parser(argparse.ArgumentParser):
    """Translate parser failures into the documented configuration exit code."""

    def error(self, message: str) -> NoReturn:
        raise ConfigurationError(message)


def build_parser() -> argparse.ArgumentParser:
    """Build the complete PreviewShield command surface."""

    parser = _Parser(
        prog="previewshield",
        description=(
            "Policy-as-code web security checks and production-to-preview regression gates."
        ),
    )
    parser.add_argument("--version", action="store_true", help="Show the installed version.")
    commands = parser.add_subparsers(dest="command", metavar="COMMAND")

    scan_parser = commands.add_parser("scan", help="Scan one deployment.")
    scan_parser.add_argument("target", help="Origin or URL to scan (HTTPS is assumed).")
    _add_scan_options(scan_parser)

    diff_parser = commands.add_parser("diff", help="Compare production with a preview.")
    diff_parser.add_argument("--baseline", required=True, help="Production origin or URL.")
    diff_parser.add_argument("--preview", required=True, help="Preview origin or URL.")
    _add_scan_options(diff_parser)

    ui_parser = commands.add_parser("ui", help="Open the local browser interface.")
    ui_parser.add_argument(
        "--port",
        type=_ui_port,
        default=8765,
        help="Loopback port (default: 8765).",
    )
    ui_parser.add_argument("--no-open", action="store_true", help="Do not open a browser.")
    ui_parser.add_argument(
        "--allow-private-targets",
        action="store_true",
        help="Unlock private/loopback targets for this trusted local UI session.",
    )

    init_parser = commands.add_parser("init", help="Create a starter policy file.")
    init_parser.add_argument(
        "--output",
        "-o",
        default=".previewshield.yml",
        help="Policy path (default: .previewshield.yml).",
    )
    init_parser.add_argument("--force", action="store_true", help="Replace an existing file.")

    policy_parser = commands.add_parser("policy", help="Inspect policy configuration.")
    policy_commands = policy_parser.add_subparsers(dest="policy_command", metavar="COMMAND")
    validate_parser = policy_commands.add_parser("validate", help="Validate a policy file.")
    validate_parser.add_argument("config", help="YAML policy path.")
    validate_parser.add_argument(
        "--profile",
        choices=("balanced", "strict"),
        default="balanced",
        help="Fallback profile for omitted policy fields.",
    )

    rules_parser = commands.add_parser("rules", help="List built-in security checks.")
    rules_parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    return parser


def _add_scan_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--config", "-c", help="PreviewShield YAML policy.")
    parser.add_argument(
        "--profile",
        choices=("balanced", "strict"),
        default="balanced",
        help="Built-in profile or fallback for an incomplete policy.",
    )
    parser.add_argument(
        "--path",
        dest="paths",
        action="append",
        metavar="ROUTE",
        help="Origin-relative route; repeat to scan multiple routes.",
    )
    parser.add_argument(
        "--header",
        dest="headers",
        action="append",
        metavar="NAME:VALUE",
        help="Request header; repeat as needed. Values are never written to reports.",
    )
    parser.add_argument(
        "--fail-on",
        choices=tuple(severity.value for severity in Severity),
        help="Override the policy failure threshold.",
    )
    parser.add_argument(
        "--allow-private",
        action="store_true",
        default=None,
        help="Allow private/loopback targets. Use only for trusted local environments.",
    )
    parser.add_argument(
        "--format",
        "-f",
        default="console",
        choices=supported_formats(),
        help="Primary report format.",
    )
    parser.add_argument("--output", "-o", help="Write the primary report to this file.")
    parser.add_argument(
        "--also-format",
        action="append",
        default=[],
        metavar="FORMAT=PATH",
        help="Write another format, for example sarif=previewshield.sarif.",
    )


def main(argv: Sequence[str] | None = None) -> int:  # noqa: PLR0911
    """Run PreviewShield and return a stable process exit code."""

    try:
        parser = build_parser()
        args = parser.parse_args(argv)
        if bool(getattr(args, "version", False)):
            print(f"PreviewShield {__version__}")
            return 0
        command = cast(str | None, getattr(args, "command", None))
        if command == "scan":
            return _run_scan(args)
        if command == "diff":
            return _run_diff(args)
        if command == "ui":
            return _run_ui(args)
        if command == "init":
            return _run_init(args)
        if command == "policy":
            return _run_policy(args)
        if command == "rules":
            return _run_rules(args)
        parser.print_help()
        return 0
    except PreviewShieldError as error:
        print(f"previewshield: {error}", file=sys.stderr)
        return error.exit_code
    except KeyboardInterrupt:
        print("previewshield: interrupted", file=sys.stderr)
        return 130
    except Exception:  # noqa: BLE001 - CLI boundary intentionally hides internals and secrets
        print(
            "previewshield: an unexpected internal error occurred; please open an issue",
            file=sys.stderr,
        )
        return 4


def _run_scan(args: argparse.Namespace) -> int:
    policy = load_policy(_optional_str(args, "config"), profile=_required_str(args, "profile"))
    report = scan(
        _required_str(args, "target"),
        policy=policy,
        paths=_optional_string_list(args, "paths"),
        request_headers=_parse_headers(_optional_string_list(args, "headers")),
        fail_on=_threshold(args),
        allow_private=_optional_bool(args, "allow_private"),
    )
    _emit_reports(report, args)
    return 0 if report.passed else 1


def _run_diff(args: argparse.Namespace) -> int:
    policy = load_policy(_optional_str(args, "config"), profile=_required_str(args, "profile"))
    report = diff_targets(
        _required_str(args, "baseline"),
        _required_str(args, "preview"),
        policy=policy,
        paths=_optional_string_list(args, "paths"),
        request_headers=_parse_headers(_optional_string_list(args, "headers")),
        fail_on=_threshold(args),
        allow_private=_optional_bool(args, "allow_private"),
    )
    _emit_reports(report, args)
    return 0 if report.passed else 1


def _run_ui(args: argparse.Namespace) -> int:
    from previewshield.webui import serve_ui  # noqa: PLC0415 - optional interactive surface

    port = _required_int(args, "port")
    try:
        serve_ui(
            port=port,
            open_browser=not bool(getattr(args, "no_open", False)),
            private_targets_enabled=bool(getattr(args, "allow_private_targets", False)),
        )
    except OSError as error:
        raise ConfigurationError(
            f"Could not start the local UI on port {port}: {error}."
        ) from error
    return 0


def _run_init(args: argparse.Namespace) -> int:
    output = Path(_required_str(args, "output"))
    if output.exists() and not bool(getattr(args, "force", False)):
        raise ConfigurationError(f"{output} already exists; use --force to replace it.")
    _write_text(output, default_policy_yaml())
    print(f"Created {output}")
    return 0


def _run_policy(args: argparse.Namespace) -> int:
    command = cast(str | None, getattr(args, "policy_command", None))
    if command != "validate":
        raise ConfigurationError("policy requires a command (try: policy validate FILE).")
    policy = load_policy(_required_str(args, "config"), profile=_required_str(args, "profile"))
    print(f"Policy '{policy.name}' is valid (profile={policy.profile}, version={policy.version}).")
    return 0


def _run_rules(args: argparse.Namespace) -> int:
    rules = [RULES[rule_id] for rule_id in sorted(RULES)]
    if bool(getattr(args, "json", False)):
        payload = [
            {
                "id": rule.rule_id,
                "title": rule.title,
                "severity": rule.severity.value,
                "category": rule.category,
                "remediation": rule.remediation,
                "references": list(rule.references),
            }
            for rule in rules
        ]
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        for rule in rules:
            print(f"{rule.rule_id:<7} {rule.severity.value:<8} {rule.title}")
    return 0


def _emit_reports(report: Report, args: argparse.Namespace) -> None:
    primary_format = _required_str(args, "format")
    primary_output = _optional_str(args, "output")
    destinations: list[tuple[str, Path]] = []
    if primary_output is None:
        print(render(report, primary_format))
    else:
        destinations.append((primary_format, Path(primary_output)))

    raw_additional = _optional_string_list(args, "also_format") or ()
    for item in raw_additional:
        format_name, separator, path_value = item.partition("=")
        if not separator or not format_name or not path_value:
            raise ConfigurationError("--also-format must use FORMAT=PATH.")
        normalized = format_name.strip().lower()
        if normalized not in supported_formats():
            choices = ", ".join(supported_formats())
            raise ConfigurationError(
                f"Unsupported report format '{format_name}'. Expected one of: {choices}."
            )
        destinations.append((normalized, Path(path_value.strip())))

    seen: set[Path] = set()
    for format_name, destination in destinations:
        key = destination.resolve()
        if key in seen:
            raise ConfigurationError(f"Multiple reports target the same path: {destination}.")
        seen.add(key)
        _write_text(destination, render(report, format_name))


def _write_text(path: Path, content: str) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content.rstrip() + "\n", encoding="utf-8", newline="\n")
    except (OSError, UnicodeError) as error:
        raise ReportError(f"Cannot write report to {path}: {error}.") from error


def _parse_headers(values: Sequence[str] | None) -> Mapping[str, str] | None:
    if values is None:
        return None
    headers: dict[str, str] = {}
    lowered_names: set[str] = set()
    for raw in values:
        name, separator, value = raw.partition(":")
        if not separator:
            raise ConfigurationError("--header must use NAME:VALUE.")
        normalized_name = validate_header_name(name.strip())
        if _CONTROL_CHARACTER.search(value):
            raise ConfigurationError(f"Request header '{normalized_name}' contains control data.")
        lowered = normalized_name.lower()
        if lowered in lowered_names:
            raise ConfigurationError(f"Duplicate request header: {normalized_name}.")
        lowered_names.add(lowered)
        headers[normalized_name] = value.strip()
    return headers


def _threshold(args: argparse.Namespace) -> Severity | None:
    value = _optional_str(args, "fail_on")
    return parse_threshold(value) if value is not None else None


def _required_str(args: argparse.Namespace, name: str) -> str:
    value = getattr(args, name, None)
    if not isinstance(value, str):
        raise ConfigurationError(f"Missing command option: {name}.")
    return value


def _optional_str(args: argparse.Namespace, name: str) -> str | None:
    value = getattr(args, name, None)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ConfigurationError(f"Invalid command option: {name}.")
    return value


def _optional_string_list(args: argparse.Namespace, name: str) -> tuple[str, ...] | None:
    value = getattr(args, name, None)
    if value is None:
        return None
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ConfigurationError(f"Invalid repeated command option: {name}.")
    return tuple(value)


def _optional_bool(args: argparse.Namespace, name: str) -> bool | None:
    value = getattr(args, name, None)
    if value is None or isinstance(value, bool):
        return value
    raise ConfigurationError(f"Invalid command option: {name}.")


def _required_int(args: argparse.Namespace, name: str) -> int:
    value = getattr(args, name, None)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigurationError(f"Missing command option: {name}.")
    return value


def _ui_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("port must be an integer") from error
    if not _MIN_UI_PORT <= port <= _MAX_UI_PORT:
        raise argparse.ArgumentTypeError("port must be between 1024 and 65535")
    return port


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
