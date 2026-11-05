"""Command line interface for Airlock."""

from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from airlock.audit.store import AuditStore
from airlock.config import load_config
from airlock.engine import Engine
from airlock.registry.store import ToolRegistry
from airlock.transport.stdio import run_stdio_proxy

app = typer.Typer(
    name="airlock",
    help="Airlock: Firewall for AI agents using MCP tools.",
    no_args_is_help=True,
)

tools_app = typer.Typer(
    name="tools",
    help="Inspect and manage registered MCP tools and definition hashes.",
    no_args_is_help=True,
)
app.add_typer(tools_app, name="tools")


def _not_implemented() -> None:
    sys.stderr.write("not implemented yet\n")
    raise typer.Exit(code=1)


@app.command(
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def wrap(
    ctx: typer.Context,
    name: Annotated[
        str | None,
        typer.Option("--name", "-n", help="Logical name of the wrapped server."),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to airlock.yaml configuration file."),
    ] = None,
    command: Annotated[
        list[str] | None,
        typer.Argument(help="Server command and arguments to wrap."),
    ] = None,
) -> None:
    """Wrap an MCP server with the Airlock stdio proxy."""
    full_cmd = list(command or []) + ctx.args
    if not full_cmd:
        sys.stderr.write("Error: No command specified to wrap.\n")
        raise typer.Exit(code=1)

    cfg = load_config(config)
    engine = Engine(config=cfg)

    exit_code = asyncio.run(run_stdio_proxy(full_cmd, name=name, engine=engine))
    raise typer.Exit(code=exit_code)


@app.command()
def logs(
    session: Annotated[
        str | None,
        typer.Option("--session", "-s", help="Filter by session ID."),
    ] = None,
    tool: Annotated[
        str | None,
        typer.Option("--tool", "-t", help="Filter by tool name."),
    ] = None,
    verdict: Annotated[
        str | None,
        typer.Option(
            "--verdict",
            "-v",
            help="Filter by verdict (ALLOW, REDACT, ASK, DENY).",
        ),
    ] = None,
    since: Annotated[
        str | None,
        typer.Option(
            "--since",
            help="Filter decisions since duration (e.g. 2h, 7d, 30m).",
        ),
    ] = None,
    limit: Annotated[
        int,
        typer.Option("--limit", "-n", help="Maximum number of rows to return."),
    ] = 50,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output decisions as JSON."),
    ] = False,
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to airlock.yaml configuration file."),
    ] = None,
) -> None:
    """Inspect and query audit logs from SQLite."""
    cfg = load_config(config)
    store = AuditStore(cfg.data_dir / "audit.db")

    try:
        rows = store.query_decisions(
            session=session,
            tool=tool,
            verdict=verdict,
            since=since,
            limit=limit,
        )
    except ValueError as exc:
        sys.stderr.write(f"Error: {exc}\n")
        raise typer.Exit(code=1) from exc

    if json_output:
        print(json.dumps(rows, indent=2))
        return

    if not rows:
        print("No decisions logged yet.")
        return

    console = Console()
    table = Table(title=f"Airlock Decisions (Latest {len(rows)})")
    table.add_column("Time", style="cyan", no_wrap=True)
    table.add_column("Dir", style="magenta", no_wrap=True)
    table.add_column("Tool", style="bold", no_wrap=True)
    table.add_column("Verdict", no_wrap=True)
    table.add_column("Rule", style="dim", no_wrap=True)
    table.add_column("Latency (ms)", justify="right", no_wrap=True)
    table.add_column("Details", style="dim")

    verdict_styles = {
        "ALLOW": "[green]ALLOW[/green]",
        "REDACT": "[yellow]REDACT[/yellow]",
        "ASK": "[blue]ASK[/blue]",
        "DENY": "[bold red]DENY[/bold red]",
    }

    for row in rows:
        ts_str = datetime.fromtimestamp(row["ts"]).strftime("%Y-%m-%d %H:%M:%S")
        v_styled = verdict_styles.get(row["verdict"], row["verdict"])
        details = (
            "; ".join(row["reasons"])
            if row["reasons"]
            else (row["result_preview"] or row["args_preview"] or "")
        )
        if len(details) > 80:
            details = details[:77] + "..."

        table.add_row(
            ts_str,
            row["direction"],
            row["tool_name"] or "-",
            v_styled,
            row["rule"] or "-",
            f"{row['latency_ms']:.1f}",
            details,
        )

    console.print(table)


# =========================================================================
# Tools subcommands
# =========================================================================


@tools_app.command(name="list")
def tools_list(
    server: Annotated[
        str | None,
        typer.Option("--server", "-s", help="Filter tools by server ID."),
    ] = None,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Output tools as JSON."),
    ] = False,
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to airlock.yaml configuration file."),
    ] = None,
) -> None:
    """List registered tools and their approval status."""
    cfg = load_config(config)
    registry = ToolRegistry(cfg.data_dir / "registry.db")
    tool_rows = registry.list_tools(server_id=server)

    if json_output:
        print(json.dumps(tool_rows, indent=2))
        return

    if not tool_rows:
        print("No registered tools found.")
        return

    console = Console()
    table = Table(title=f"Registered MCP Tools ({len(tool_rows)})")
    table.add_column("Server", style="cyan", no_wrap=True)
    table.add_column("Tool", style="bold", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Hash", style="dim", no_wrap=True)
    table.add_column("Status Reason", style="dim")
    table.add_column("Last Seen", style="dim", no_wrap=True)

    status_styles = {
        "approved": "[green]approved[/green]",
        "pending": "[yellow]pending[/yellow]",
        "quarantined": "[bold red]quarantined[/bold red]",
    }

    for t in tool_rows:
        status_styled = status_styles.get(t["status"], t["status"])
        last_seen_str = datetime.fromtimestamp(t["last_seen"]).strftime("%Y-%m-%d %H:%M:%S")
        table.add_row(
            t["server_id"],
            t["tool_name"],
            status_styled,
            t["hash"][:12],
            t["status_reason"] or "-",
            last_seen_str,
        )

    console.print(table)


@tools_app.command(name="diff")
def tools_diff(
    server: Annotated[str, typer.Argument(help="Server ID.")],
    tool: Annotated[str, typer.Argument(help="Tool name.")],
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to airlock.yaml configuration file."),
    ] = None,
) -> None:
    """Show unified diff between previous and current definitions of a tool."""
    cfg = load_config(config)
    registry = ToolRegistry(cfg.data_dir / "registry.db")
    diff_text = registry.get_tool_diff(server_id=server, tool_name=tool)

    if diff_text is None:
        sys.stderr.write(f"Error: Tool '{tool}' not found on server '{server}'.\n")
        raise typer.Exit(code=1)

    if not diff_text.strip():
        print(f"No definition changes recorded for tool '{tool}' on server '{server}'.")
        return

    print(diff_text)


@tools_app.command(name="approve")
def tools_approve(
    server: Annotated[str, typer.Argument(help="Server ID.")],
    tool: Annotated[
        str | None,
        typer.Argument(help="Tool name to approve (omit if using --all)."),
    ] = None,
    all_tools: Annotated[
        bool,
        typer.Option("--all", "-a", help="Approve all tools on this server."),
    ] = False,
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to airlock.yaml configuration file."),
    ] = None,
) -> None:
    """Approve a quarantined or pending tool on a server."""
    if not all_tools and not tool:
        sys.stderr.write(
            f"Error: Specify a tool name or --all to approve tools on server '{server}'.\n"
        )
        raise typer.Exit(code=1)

    cfg = load_config(config)
    registry = ToolRegistry(cfg.data_dir / "registry.db")

    if all_tools:
        count = registry.approve_tool(server_id=server, all_tools=True)
        print(f"Approved all ({count}) tools on server '{server}'.")
    else:
        assert tool is not None
        count = registry.approve_tool(server_id=server, tool_name=tool)
        if count == 0:
            sys.stderr.write(f"Error: Tool '{tool}' not found on server '{server}'.\n")
            raise typer.Exit(code=1)
        print(f"Approved tool '{tool}' on server '{server}'.")


@tools_app.command(name="reset")
def tools_reset(
    server: Annotated[str, typer.Argument(help="Server ID to reset.")],
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to airlock.yaml configuration file."),
    ] = None,
) -> None:
    """Delete all tools for a server; next discovery will be trust-on-first-use (TOFU)."""
    cfg = load_config(config)
    registry = ToolRegistry(cfg.data_dir / "registry.db")
    count = registry.reset_server(server_id=server)
    print(
        f"Reset server '{server}' ({count} tools removed). "
        "Next discovery will be trust-on-first-use."
    )


# =========================================================================
# Remaining placeholder commands
# =========================================================================


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
def policy() -> None:
    """Inspect and validate security policies."""
    _not_implemented()


@app.command()
def honeytokens() -> None:
    """Manage planted honeytokens and fake credentials."""
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
