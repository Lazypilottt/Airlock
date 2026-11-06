"""Tests for Airlock CLI commands."""

from __future__ import annotations

import pytest
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

PLACEHOLDER_COMMANDS: list[str] = [
    cmd for cmd in ALL_COMMANDS if cmd not in ("wrap", "logs", "tools", "policy")
]


def test_cli_help_lists_every_command() -> None:
    """The --help flag output contains all required CLI commands."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for cmd in ALL_COMMANDS:
        assert cmd in result.output, f"Command '{cmd}' not found in CLI help output"


@pytest.mark.parametrize("cmd", PLACEHOLDER_COMMANDS)
def test_placeholder_commands_exit_1_and_print_not_implemented(cmd: str) -> None:
    """Every placeholder command prints 'not implemented yet' to stderr and exits with 1."""
    result = runner.invoke(app, [cmd])
    assert result.exit_code == 1
    assert "not implemented yet" in result.stderr


def test_wrap_without_command_fails() -> None:
    """Running wrap with no target command prints an error and exits 1."""
    result = runner.invoke(app, ["wrap"])
    assert result.exit_code == 1
    assert "No command specified to wrap" in result.stderr
