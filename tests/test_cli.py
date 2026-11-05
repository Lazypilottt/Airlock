"""Tests for Airlock CLI commands."""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from airlock.cli import app

runner = CliRunner()

COMMANDS: list[str] = [
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
    for cmd in COMMANDS:
        assert cmd in result.output, f"Command '{cmd}' not found in CLI help output"


@pytest.mark.parametrize("cmd", COMMANDS)
def test_placeholder_commands_exit_1_and_print_not_implemented(cmd: str) -> None:
    """Every placeholder command prints 'not implemented yet' to stderr and exits with 1."""
    result = runner.invoke(app, [cmd])
    assert result.exit_code == 1
    assert "not implemented yet" in result.stderr
