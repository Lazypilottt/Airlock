"""Tests for Airlock CLI commands."""

from __future__ import annotations

from typer.testing import CliRunner

from airlock.cli import app

runner = CliRunner()

ALL_COMMANDS: list[str] = [
    "wrap",
    "serve",
    "init",
    "uninstall",
    "tools",
    "policy",
    "honeytokens",
    "logs",
    "report",
    "attack",
    "dashboard",
]


def test_cli_help_lists_every_command() -> None:
    """The --help flag output contains all required CLI commands."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for cmd in ALL_COMMANDS:
        assert cmd in result.output, f"Command '{cmd}' not found in CLI help output"


def test_no_command_is_a_placeholder_any_more() -> None:
    """Every command does something: none prints 'not implemented yet'."""
    for cmd in ALL_COMMANDS:
        result = runner.invoke(app, [cmd, "--help"])
        assert result.exit_code == 0, cmd
        assert "not implemented" not in result.output, cmd


def test_wrap_without_command_fails() -> None:
    """Running wrap with no target command prints an error and exits 1."""
    result = runner.invoke(app, ["wrap"])
    assert result.exit_code == 1
    assert "No command specified to wrap" in result.stderr
