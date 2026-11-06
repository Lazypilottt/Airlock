"""Command line interface for Airlock."""

from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from airlock import install
from airlock.audit.store import AuditStore
from airlock.config import ConfigError, find_config_path, load_config
from airlock.engine_factory import build_engine
from airlock.honeytokens.cli import honeytokens_app
from airlock.policy.cli import policy_app
from airlock.policy.schema import PolicyError
from airlock.registry.store import ToolRegistry, labels_from_row
from airlock.registry.trifecta import find_trifecta
from airlock.report import build_report, render_markdown, render_text
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
app.add_typer(policy_app, name="policy")
app.add_typer(honeytokens_app, name="honeytokens")


class Mode(StrEnum):
    enforce = "enforce"
    shadow = "shadow"


class Client(StrEnum):
    all = "all"
    claude_desktop = "claude-desktop"
    cursor = "cursor"


class ReportFormat(StrEnum):
    text = "text"
    markdown = "markdown"


_APP_TITLES = {"claude-desktop": "Claude Desktop", "cursor": "Cursor"}


def _targets(client: Client, config_paths: list[Path] | None) -> list[tuple[str, Path]]:
    """``(label, path)`` of the client configs to work on."""
    if config_paths:
        return [(str(path), path.expanduser()) for path in config_paths]
    apps = install.APPS if client is Client.all else (client.value,)
    found: list[tuple[str, Path]] = []
    for app_name in apps:
        for path in install.config_paths(app_name):  # type: ignore[arg-type]
            if path.is_file():
                found.append((_APP_TITLES[app_name], path))
    return found


def _looked_in(client: Client) -> str:
    apps = install.APPS if client is Client.all else (client.value,)
    return ", ".join(
        str(path)
        for app_name in apps
        for path in install.config_paths(app_name)  # type: ignore[arg-type]
    )


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
    mode: Annotated[
        Mode | None,
        typer.Option(
            "--mode", help="shadow: log what would happen, block nothing. Overrides config."
        ),
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

    try:
        cfg = load_config(config)
        if mode is not None:
            cfg = cfg.model_copy(update={"mode": mode.value})
        engine = build_engine(cfg)
        if mode is not None:
            engine.mode_override = mode.value
    except (ConfigError, PolicyError) as exc:
        sys.stderr.write(f"Error: {exc}\n")
        raise typer.Exit(code=1) from exc

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
    for row in tool_rows:
        resolved = labels_from_row(row).to_record()
        row["labels"] = resolved["labels"]
        row["arg_roles"] = resolved["arg_roles"]
        row["label_origin"] = resolved["origin"]
        row["label_source"] = resolved["source"]

    trifectas = [
        found
        for client in registry.clients()
        if (found := find_trifecta(registry, client)) is not None
        and (
            server is None
            or any(t.startswith(f"{server}.") for t in found.sink + found.private + found.untrusted)
        )
    ]

    if json_output:
        print(json.dumps(tool_rows, indent=2))
        for found in trifectas:
            sys.stderr.write(f"Warning: {found.message(limit=50)}\n")
        return

    if not tool_rows:
        print("No registered tools found.")
        return

    console = Console()
    table = Table(title=f"Registered MCP Tools ({len(tool_rows)})")
    table.add_column("Server", style="cyan", no_wrap=True)
    table.add_column("Tool", style="bold", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Labels", no_wrap=True)
    table.add_column("Label origin", style="dim", no_wrap=True)
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
        origin = t["label_origin"]
        origin_text = f"{origin}:{t['label_source']}" if origin == "pack" else origin
        table.add_row(
            t["server_id"],
            t["tool_name"],
            status_styled,
            ", ".join(t["labels"]) or "-",
            origin_text,
            t["hash"][:12],
            t["status_reason"] or "-",
            last_seen_str,
        )

    console.print(table)
    for found in trifectas:
        console.print()
        console.print(Text.assemble(("Warning: ", "bold yellow"), found.message(limit=50)))


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


ClientOption = Annotated[
    Client,
    typer.Option("--client", help="Which app's MCP config to change."),
]
ConfigPathOption = Annotated[
    list[Path] | None,
    typer.Option(
        "--config-path",
        help="An MCP config file to use instead of the apps' default locations (repeatable), "
        "for example a project's .cursor/mcp.json.",
    ),
]
YesOption = Annotated[bool, typer.Option("--yes", "-y", help="Do not ask for confirmation.")]


@app.command()
def init(
    client: ClientOption = Client.all,
    config_path: ConfigPathOption = None,
    mode: Annotated[
        Mode | None,
        typer.Option("--mode", help="Wrap servers in shadow mode: log only, block nothing."),
    ] = None,
    yes: YesOption = False,
    airlock_command: Annotated[
        str | None,
        typer.Option("--airlock-command", help="Command written into the configs."),
    ] = None,
) -> None:
    """Wrap the stdio MCP servers of Claude Desktop and Cursor with Airlock."""
    targets = _targets(client, config_path)
    if not targets:
        print(f"No MCP client config found. Looked in: {_looked_in(client)}")
        print("Pass --config-path to point at one.")
    command = airlock_command or install.default_airlock_command()
    plans: list[tuple[str, install.ConfigPlan]] = []
    for label, path in targets:
        try:
            config_plan = install.plan(path)
        except install.InstallError as exc:
            sys.stderr.write(f"Error: {exc}\n")
            raise typer.Exit(code=1) from exc
        plans.append((label, config_plan))
        print(f"{label}: {path}")
        if not config_plan.servers:
            print("  no servers configured")
        for server in config_plan.servers:
            if server.status == "wrap":
                entry = config_plan.data["mcpServers"][server.name]
                original = " ".join([entry["command"], *map(str, entry.get("args", []))])
                print(f"  wrap  {server.name}: {original}")
            else:
                print(f"  skip  {server.name}: {server.note}")

    pending = [(label, plan_) for label, plan_ in plans if plan_.to_wrap]
    if pending:
        count = sum(len(plan_.to_wrap) for _, plan_ in pending)
        shadow = " in shadow mode" if mode is Mode.shadow else ""
        if not yes and not typer.confirm(
            f"\nWrap {count} server(s){shadow} with {command}?", default=False
        ):
            print("Nothing changed.")
            raise typer.Exit(code=1)
        for _label, config_plan in pending:
            try:
                saved = install.apply_init(
                    config_plan, command, mode.value if mode is Mode.shadow else None
                )
            except (OSError, install.InstallError) as exc:
                sys.stderr.write(f"Error: could not update {config_plan.path}: {exc}\n")
                raise typer.Exit(code=1) from exc
            print(f"Updated {config_plan.path} (backup: {saved})")
        apps = ", ".join(sorted({label for label, _ in pending}))
        print(f"Restart {apps} to load the wrapped servers. Undo with `airlock uninstall`.")
    elif plans:
        print("\nNothing to wrap.")

    existing = find_config_path()
    if existing is not None:
        print(f"Using Airlock config {existing} (left unchanged).")
        return
    starter = install.starter_config_path()
    if yes or typer.confirm(f"Write a starter Airlock config to {starter}?", default=True):
        if install.write_starter_config(starter):
            print(f"Wrote {starter}")
        else:
            print(f"{starter} already exists; left unchanged.")


@app.command()
def uninstall(
    client: ClientOption = Client.all,
    config_path: ConfigPathOption = None,
    yes: YesOption = False,
) -> None:
    """Undo `airlock init`: restore the latest backup, or unwrap in place if there is none."""
    targets = _targets(client, config_path)
    if not targets:
        print(f"No MCP client config found. Looked in: {_looked_in(client)}")
        return
    for label, path in targets:
        saved = install.latest_backup(path)
        if saved is not None:
            question = (
                f"{label}: restore {path} from {saved.name}? "
                "Changes made to it after `airlock init` are lost."
            )
            if yes or typer.confirm(question, default=False):
                install.restore(path, saved)
                print(f"Restored {path} from {saved}")
            continue
        try:
            config_plan = install.plan(path)
        except install.InstallError as exc:
            sys.stderr.write(f"Error: {exc}\n")
            raise typer.Exit(code=1) from exc
        names = [server.name for server in config_plan.wrapped]
        if not names:
            print(f"{label}: nothing wrapped in {path}")
            continue
        question = f"{label}: no backup found; unwrap {', '.join(names)} in {path}?"
        if yes or typer.confirm(question, default=False):
            install.apply_unwrap_in_place(config_plan)
            print(f"Unwrapped {', '.join(names)} in {path}")


@app.command()
def report(
    since: Annotated[str, typer.Option("--since", help="Period, e.g. 24h, 7d, 4w.")] = "7d",
    output_format: Annotated[
        ReportFormat, typer.Option("--format", help="text or markdown.")
    ] = ReportFormat.text,
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to airlock.yaml configuration file."),
    ] = None,
) -> None:
    """Summarise decisions, shadow-mode findings, quarantines, trifectas and honeytoken alerts."""
    try:
        cfg = load_config(config)
        built = build_report(cfg, since)
    except (ConfigError, ValueError) as exc:
        sys.stderr.write(f"Error: {exc}\n")
        raise typer.Exit(code=1) from exc
    rendered = (
        render_markdown(built) if output_format is ReportFormat.markdown else render_text(built)
    )
    sys.stdout.write(rendered)


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
