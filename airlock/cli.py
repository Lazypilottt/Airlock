"""Command line interface for Airlock."""

from __future__ import annotations

import sys

import typer

app = typer.Typer(
    name="airlock",
    help="Airlock: Firewall for AI agents using MCP tools.",
    no_args_is_help=True,
)


def _not_implemented() -> None:
    sys.stderr.write("not implemented yet\n")
    raise typer.Exit(code=1)


@app.command()
def wrap() -> None:
    """Wrap an MCP client or server with the Airlock proxy."""
    _not_implemented()


@app.command()
def serve() -> None:
    """Start the Airlock proxy service."""
    _not_implemented()


@app.command()
def init() -> None:
    """Initialize Airlock configuration and local data directory."""
    _not_implemented()


@app.command()
def uninstall() -> None:
    """Uninstall Airlock configurations and wrappers."""
    _not_implemented()


@app.command()
def tools() -> None:
    """Inspect and manage registered MCP tools and definition hashes."""
    _not_implemented()


@app.command()
def policy() -> None:
    """Inspect and validate security policies."""
    _not_implemented()


@app.command()
def honeytokens() -> None:
    """Manage planted honeytokens and fake credentials."""
    _not_implemented()


@app.command()
def logs() -> None:
    """Query audit logs and tool execution decisions."""
    _not_implemented()


@app.command()
def report() -> None:
    """Generate security inspection and compliance reports."""
    _not_implemented()


@app.command()
def attack() -> None:
    """Run prompt injection and security attack simulations."""
    _not_implemented()


@app.command()
def dashboard() -> None:
    """Launch the local web dashboard."""
    _not_implemented()


def main() -> None:
    app()


if __name__ == "__main__":
    main()
