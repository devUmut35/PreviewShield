from __future__ import annotations

import json
from pathlib import Path

import pytest

from previewshield import cli
from previewshield.models import DiffReport, ResponseSnapshot, RouteReport, ScanReport, Severity


def scan_report(*, passed: bool = True) -> ScanReport:
    url = "https://example.com/"
    snapshot = ResponseSnapshot(
        requested_url=url,
        final_url=url,
        status_code=200,
        reason="OK",
        headers={},
        resolved_ip="203.0.113.10",
        elapsed_ms=1,
    )
    return ScanReport(
        schema_version="1.0",
        tool_version="1.0.0",
        generated_at="2026-01-01T00:00:00Z",
        policy_name="test",
        target=url,
        routes=(RouteReport(snapshot=snapshot),),
        score=100 if passed else 50,
        grade="A+" if passed else "F",
        fail_on=Severity.HIGH,
        passed=passed,
    )


def diff_report(*, passed: bool = True) -> DiffReport:
    baseline = scan_report(passed=True)
    preview = scan_report(passed=passed)
    return DiffReport(
        schema_version="1.0",
        tool_version="1.0.0",
        generated_at="2026-01-01T00:00:00Z",
        policy_name="test",
        baseline=baseline,
        preview=preview,
        deltas=(),
        fail_on=Severity.HIGH,
        passed=passed,
    )


def test_version_and_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["--version"]) == 0
    assert "PreviewShield 1.0.0" in capsys.readouterr().out

    assert cli.main([]) == 0
    assert "production-to-preview" in capsys.readouterr().out
    assert "ui" in cli.build_parser().format_help()


def test_parse_error_uses_configuration_exit_code(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["scan"]) == 2
    assert "required" in capsys.readouterr().err


def test_scan_forwards_safe_options_and_returns_policy_exit(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    observed: dict[str, object] = {}

    def fake_scan(target: str, **kwargs: object) -> ScanReport:
        observed["target"] = target
        observed.update(kwargs)
        return scan_report(passed=False)

    monkeypatch.setattr(cli, "scan", fake_scan)
    monkeypatch.setattr(cli, "render", lambda _report, format_name: f"format={format_name}")

    exit_code = cli.main(
        [
            "scan",
            "preview.example",
            "--path",
            "/",
            "--path",
            "/health",
            "--header",
            "Authorization:Bearer do-not-print",
            "--fail-on",
            "medium",
            "--allow-private",
            "--format",
            "json",
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out.strip() == "format=json"
    assert "do-not-print" not in captured.out + captured.err
    assert observed["target"] == "preview.example"
    assert observed["paths"] == ("/", "/health")
    assert observed["request_headers"] == {"Authorization": "Bearer do-not-print"}
    assert observed["fail_on"] is Severity.MEDIUM
    assert observed["allow_private"] is True


def test_duplicate_and_injected_headers_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "scan", lambda *_args, **_kwargs: scan_report())

    assert (
        cli.main(
            [
                "scan",
                "example.com",
                "--header",
                "X-Test:first",
                "--header",
                "x-test:second",
            ]
        )
        == 2
    )
    assert "Duplicate request header" in capsys.readouterr().err

    assert cli.main(["scan", "example.com", "--header", "BrokenHeader"]) == 2
    assert "NAME:VALUE" in capsys.readouterr().err


def test_diff_command_and_secondary_reports(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(cli, "diff_targets", lambda *_args, **_kwargs: diff_report())
    monkeypatch.setattr(cli, "render", lambda _report, format_name: f"{format_name} report")
    primary = tmp_path / "reports" / "result.json"
    sarif = tmp_path / "reports" / "result.sarif"

    exit_code = cli.main(
        [
            "diff",
            "--baseline",
            "prod.example",
            "--preview",
            "preview.example",
            "--format",
            "json",
            "--output",
            str(primary),
            "--also-format",
            f"sarif={sarif}",
        ]
    )

    assert exit_code == 0
    assert primary.read_text(encoding="utf-8") == "json report\n"
    assert sarif.read_text(encoding="utf-8") == "sarif report\n"


def test_duplicate_report_destination_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(cli, "scan", lambda *_args, **_kwargs: scan_report())
    output = tmp_path / "same.json"

    assert (
        cli.main(
            [
                "scan",
                "example.com",
                "--format",
                "json",
                "--output",
                str(output),
                "--also-format",
                f"json={output}",
            ]
        )
        == 2
    )
    assert "same path" in capsys.readouterr().err


def test_init_and_policy_validate(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    policy_path = tmp_path / "nested" / ".previewshield.yml"

    assert cli.main(["init", "--output", str(policy_path)]) == 0
    assert "version: 1" in policy_path.read_text(encoding="utf-8")
    capsys.readouterr()

    assert cli.main(["init", "--output", str(policy_path)]) == 2
    assert "already exists" in capsys.readouterr().err

    assert cli.main(["policy", "validate", str(policy_path)]) == 0
    assert "is valid" in capsys.readouterr().out


def test_policy_requires_a_subcommand(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["policy"]) == 2
    assert "requires a command" in capsys.readouterr().err


def test_rules_json_is_machine_readable(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["rules", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)

    assert payload[0]["id"].startswith("PS")
    assert {item["id"] for item in payload} >= {"PS0001", "PS1501"}


def test_unexpected_error_is_redacted(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail(*_args: object, **_kwargs: object) -> ScanReport:
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(cli, "scan", fail)

    assert cli.main(["scan", "example.com"]) == 4
    error = capsys.readouterr().err
    assert "unexpected internal error" in error
    assert "secret internal detail" not in error
