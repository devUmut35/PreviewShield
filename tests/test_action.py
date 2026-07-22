from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path

import pytest

from previewshield import cli
from previewshield.action import (
    ACTION_USAGE_ERROR,
    ActionInputError,
    ActionInputs,
    build_cli_argv,
    build_output_plan,
    invoke_cli,
    run_action,
)
from previewshield.models import ScanReport, Severity


def _value_after(argv: Sequence[str], option: str) -> str:
    return argv[argv.index(option) + 1]


def _sidecar_after(argv: Sequence[str], report_format: str) -> Path:
    for index, value in enumerate(argv):
        if value == "--also-format" and argv[index + 1].startswith(f"{report_format}="):
            return Path(argv[index + 1].split("=", maxsplit=1)[1])
    raise AssertionError(f"Missing {report_format} sidecar")


def test_scan_arguments_are_passed_as_an_argv_list(tmp_path: Path) -> None:
    inputs = ActionInputs.from_values(
        target="https://preview.example",
        config="policy.yml",
        paths="/\n/api, /health; echo unsafe",
        fail_on="medium",
        output=str(tmp_path / "report.json"),
        allow_private="true",
    )
    outputs = build_output_plan(inputs.report_format, inputs.output)

    argv = build_cli_argv(inputs, outputs)

    assert argv[:2] == ["scan", "https://preview.example"]
    assert argv.count("--path") == 3
    assert "/health; echo unsafe" in argv
    assert argv[2:4] == ["--config", "policy.yml"]
    assert _value_after(argv, "--format") == "json"
    assert _value_after(argv, "--output") == str(tmp_path / "report.json")
    assert argv[-1] == "--allow-private"


def test_diff_arguments_and_public_markdown_output(tmp_path: Path) -> None:
    inputs = ActionInputs.from_values(
        baseline="https://www.example.com",
        preview="https://pr.example.com",
        report_format="markdown",
        output=str(tmp_path / "security-report.md"),
    )
    outputs = build_output_plan(inputs.report_format, inputs.output)

    argv = build_cli_argv(inputs, outputs)

    assert argv[:5] == [
        "diff",
        "--baseline",
        "https://www.example.com",
        "--preview",
        "https://pr.example.com",
    ]
    assert outputs.exposed == tmp_path / "security-report.md"
    assert outputs.markdown == outputs.exposed
    assert outputs.json != outputs.exposed


@pytest.mark.parametrize(
    ("report_format", "misleading_name"),
    [("json", "report.md"), ("markdown", "report.json"), ("sarif", "report.md")],
)
def test_selected_output_wins_extension_collisions(
    report_format: str, misleading_name: str, tmp_path: Path
) -> None:
    output = tmp_path / misleading_name

    plan = build_output_plan(report_format, output)

    assert plan.exposed == output
    assert getattr(plan, report_format) == output
    assert len({plan.json, plan.markdown, plan.sarif}) == 3


@pytest.mark.parametrize(
    ("values", "message"),
    [
        ({}, "Provide target"),
        ({"target": "https://a", "baseline": "https://b", "preview": "https://c"}, "not both"),
        ({"baseline": "https://a"}, "provided together"),
        ({"target": "https://a", "allow_private": "perhaps"}, "true or false"),
        ({"target": "https://a", "report_format": "xml"}, "Unsupported format"),
    ],
)
def test_invalid_inputs_are_rejected(values: dict[str, str], message: str) -> None:
    with pytest.raises(ActionInputError, match=message):
        ActionInputs.from_values(**values)


def test_environment_supports_hyphenated_github_input_names() -> None:
    inputs = ActionInputs.from_environment(
        {
            "INPUT_TARGET": "https://preview.example",
            "INPUT_FAIL-ON": "critical",
            "INPUT_ALLOW-PRIVATE": "true",
        }
    )

    assert inputs.fail_on == "critical"
    assert inputs.allow_private is True


def test_invoke_cli_normalizes_main_conventions() -> None:
    assert invoke_cli(lambda _argv: None, ["scan", "https://example.com"]) == 0

    def exits(_argv: Sequence[str] | None) -> int:
        raise SystemExit("usage")

    assert invoke_cli(exits, ["scan", "https://example.com"]) == ACTION_USAGE_ERROR


def test_run_action_publishes_scan_outputs_and_summary(tmp_path: Path) -> None:
    github_output = tmp_path / "github-output"
    github_summary = tmp_path / "github-summary"
    captured: list[str] = []

    def fake_cli(argv: Sequence[str] | None) -> int:
        assert argv is not None
        captured.extend(argv)
        json_path = Path(_value_after(argv, "--output"))
        markdown_path = _sidecar_after(argv, "markdown")
        json_path.write_text(
            json.dumps({"score": 84, "grade": "B", "passed": False}), encoding="utf-8"
        )
        markdown_path.write_text("# Security report\n\nOne regression.\n", encoding="utf-8")
        return 1

    inputs = ActionInputs.from_values(
        target="https://preview.example",
        output=str(tmp_path / "report.json"),
    )
    result = run_action(
        inputs,
        cli_main=fake_cli,
        environ={
            "GITHUB_OUTPUT": str(github_output),
            "GITHUB_STEP_SUMMARY": str(github_summary),
        },
    )

    assert result == 1
    assert captured[0] == "scan"
    output_commands = github_output.read_text(encoding="utf-8")
    assert "report<<PREVIEWSHIELD_" in output_commands
    assert f"\n{tmp_path / 'report.json'}\n" in output_commands
    assert "\n84\n" in output_commands
    assert "\nB\n" in output_commands
    assert "\nfalse\n" in output_commands
    assert github_summary.read_text(encoding="utf-8") == "# Security report\n\nOne regression.\n"


def test_run_action_reads_nested_diff_metadata(tmp_path: Path) -> None:
    github_output = tmp_path / "github-output"

    def fake_cli(argv: Sequence[str] | None) -> int:
        assert argv is not None
        Path(_value_after(argv, "--output")).write_text(
            json.dumps({"preview": {"score": 71, "grade": "C"}, "passed": True}),
            encoding="utf-8",
        )
        return 0

    inputs = ActionInputs.from_values(
        baseline="https://production.example",
        preview="https://preview.example",
        report_format="sarif",
        output=str(tmp_path / "report.sarif"),
    )

    result = run_action(inputs, cli_main=fake_cli, environ={"GITHUB_OUTPUT": str(github_output)})

    assert result == 0
    commands = github_output.read_text(encoding="utf-8")
    assert f"\n{tmp_path / 'report.sarif'}\n" in commands
    assert "\n71\n" in commands
    assert "\nC\n" in commands
    assert "\ntrue\n" in commands


def test_cli_exit_code_survives_missing_reports(tmp_path: Path) -> None:
    github_output = tmp_path / "github-output"
    github_summary = tmp_path / "github-summary"
    inputs = ActionInputs.from_values(
        target="https://unreachable.example",
        output=str(tmp_path / "missing.json"),
    )
    inputs.output.write_text(
        json.dumps({"score": 100, "grade": "A", "passed": True}), encoding="utf-8"
    )

    result = run_action(
        inputs,
        cli_main=lambda _argv: 3,
        environ={
            "GITHUB_OUTPUT": str(github_output),
            "GITHUB_STEP_SUMMARY": str(github_summary),
        },
    )

    assert result == 3
    assert "\nfalse\n" in github_output.read_text(encoding="utf-8")
    assert "\n100\n" not in github_output.read_text(encoding="utf-8")
    assert "Status: **Failed**" in github_summary.read_text(encoding="utf-8")


def test_action_integrates_with_real_cli_and_reporters(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    report = ScanReport(
        schema_version="1.0",
        tool_version="1.0.0",
        generated_at="2026-07-22T12:00:00Z",
        policy_name="action-smoke",
        target="https://preview.example",
        routes=(),
        score=96,
        grade="A",
        fail_on=Severity.HIGH,
        passed=True,
    )

    def fake_scan(*_args: object, **_kwargs: object) -> ScanReport:
        return report

    monkeypatch.setattr(cli, "scan", fake_scan)
    github_output = tmp_path / "github-output"
    github_summary = tmp_path / "github-summary"
    output = tmp_path / "real-cli-report.json"
    inputs = ActionInputs.from_values(
        target="https://preview.example",
        paths="/\n/health",
        output=str(output),
    )

    result = run_action(
        inputs,
        cli_main=cli.main,
        environ={
            "GITHUB_OUTPUT": str(github_output),
            "GITHUB_STEP_SUMMARY": str(github_summary),
        },
    )

    plan = build_output_plan("json", output)
    assert result == 0
    assert json.loads(plan.json.read_text(encoding="utf-8"))["score"] == 96
    assert plan.markdown.read_text(encoding="utf-8").startswith("## PreviewShield")
    assert json.loads(plan.sarif.read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert "\n96\n" in github_output.read_text(encoding="utf-8")
    assert github_summary.read_text(encoding="utf-8").startswith("## PreviewShield")
