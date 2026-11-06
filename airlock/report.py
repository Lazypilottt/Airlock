"""``airlock report``: what Airlock saw and did over a period."""

from __future__ import annotations

import sqlite3
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from airlock.audit.store import AuditStore, parse_duration_to_seconds
from airlock.config import AirlockConfig
from airlock.registry.store import ToolRegistry
from airlock.registry.trifecta import Trifecta, find_trifecta

VERDICTS = ("ALLOW", "REDACT", "ASK", "DENY")


@dataclass
class Report:
    since: float
    until: float
    total: int = 0
    by_verdict: Counter[str] = field(default_factory=Counter)
    by_direction: Counter[str] = field(default_factory=Counter)
    top_rules: list[tuple[str, int]] = field(default_factory=list)
    shadow: Counter[str] = field(default_factory=Counter)
    shadow_tools: list[tuple[str, str, int]] = field(default_factory=list)
    quarantined: list[tuple[str, str, str]] = field(default_factory=list)
    trifectas: list[Trifecta] = field(default_factory=list)
    honeytoken_alerts: list[dict[str, Any]] = field(default_factory=list)


def _decision_rows(db_path: Path, since: float) -> list[sqlite3.Row]:
    if not db_path.is_file():
        return []
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    try:
        has_table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'decisions'"
        ).fetchone()
        if not has_table:
            return []
        return conn.execute(
            "SELECT direction, server_id, tool_name, verdict, would_have, rule "
            "FROM decisions WHERE ts >= ? AND direction != 'list'",
            (since,),
        ).fetchall()
    finally:
        conn.close()


def build_report(config: AirlockConfig, since: str = "7d", now: float | None = None) -> Report:
    """Collect the report from the audit log and the tool registry in ``data_dir``."""
    until = time.time() if now is None else now
    start = until - parse_duration_to_seconds(since)
    report = Report(since=start, until=until)

    rules: Counter[str] = Counter()
    shadow_tools: Counter[tuple[str, str]] = Counter()
    for row in _decision_rows(config.data_dir / "audit.db", start):
        report.total += 1
        report.by_verdict[row["verdict"]] += 1
        report.by_direction[row["direction"]] += 1
        effective = row["would_have"] or row["verdict"]
        if row["rule"] and effective != "ALLOW":
            rules[row["rule"]] += 1
        if row["would_have"] and row["would_have"] != "ALLOW":
            report.shadow[row["would_have"]] += 1
            shadow_tools[(f"{row['server_id']}.{row['tool_name']}", row["would_have"])] += 1
    report.top_rules = rules.most_common(10)
    report.shadow_tools = [
        (tool, verdict, count) for (tool, verdict), count in shadow_tools.most_common(10)
    ]

    registry_path = config.data_dir / "registry.db"
    if registry_path.is_file():
        registry = ToolRegistry(registry_path)
        report.quarantined = [
            (row["server_id"], row["tool_name"], row.get("status_reason") or "")
            for row in registry.list_tools()
            if row["status"] == "quarantined"
        ]
        report.trifectas = [
            found
            for client in registry.clients()
            if (found := find_trifecta(registry, client)) is not None
        ]
    report.honeytoken_alerts = AuditStore(config.data_dir / "audit.db").query_alerts(
        kind="honeytoken", since=start, limit=50
    )
    return report


def _when(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


def _verdict_line(report: Report) -> str:
    return ", ".join(f"{verdict} {report.by_verdict.get(verdict, 0)}" for verdict in VERDICTS)


def render_text(report: Report) -> str:
    lines = [
        f"Airlock report: {_when(report.since)} to {_when(report.until)}",
        "",
        f"Decisions: {report.total} ({_verdict_line(report)})",
        f"  calls {report.by_direction.get('call', 0)}, "
        f"results {report.by_direction.get('result', 0)}",
        "",
        "Top rules (non-ALLOW decisions):",
    ]
    lines += [f"  {count:>5}  {rule}" for rule, count in report.top_rules] or ["  none"]
    lines += ["", f"Shadow mode, would have been stopped: {sum(report.shadow.values())}"]
    lines += [f"  {count:>5}  {verdict:<6} {tool}" for tool, verdict, count in report.shadow_tools]
    lines += ["", f"Quarantined tools: {len(report.quarantined)}"]
    lines += [f"  {server}.{tool}: {reason}" for server, tool, reason in report.quarantined]
    lines += ["", f"Lethal-trifecta warnings: {len(report.trifectas)}"]
    lines += [f"  {found.message(limit=10)}" for found in report.trifectas]
    lines += ["", f"Honeytoken alerts: {len(report.honeytoken_alerts)}"]
    lines += [
        f"  {_when(alert['ts'])}  {alert['server_id']}.{alert['tool_name']}: {alert['message']}"
        for alert in report.honeytoken_alerts
    ]
    return "\n".join(lines) + "\n"


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(report: Report) -> str:
    out = [
        "# Airlock report",
        "",
        f"{_when(report.since)} to {_when(report.until)}",
        "",
        "## Decisions",
        "",
        "| Verdict | Count |",
        "|---|---:|",
        *(f"| {verdict} | {report.by_verdict.get(verdict, 0)} |" for verdict in VERDICTS),
        f"| **Total** | **{report.total}** |",
        "",
        f"Calls: {report.by_direction.get('call', 0)}. "
        f"Results: {report.by_direction.get('result', 0)}.",
        "",
        "## Top rules",
        "",
    ]
    if report.top_rules:
        out += ["| Rule | Count |", "|---|---:|"]
        out += [f"| `{_cell(rule)}` | {count} |" for rule, count in report.top_rules]
    else:
        out.append("No rule stopped or changed anything.")
    out += ["", "## Shadow mode", ""]
    if report.shadow_tools:
        out += [
            f"{sum(report.shadow.values())} decisions would have been stopped.",
            "",
            "| Tool | Would have | Count |",
            "|---|---|---:|",
        ]
        out += [
            f"| `{_cell(tool)}` | {verdict} | {count} |"
            for tool, verdict, count in report.shadow_tools
        ]
    else:
        out.append("Nothing would have been stopped.")
    out += ["", "## Quarantined tools", ""]
    out += [
        f"- `{_cell(server)}.{_cell(tool)}`: {_cell(reason)}"
        for server, tool, reason in report.quarantined
    ] or ["None."]
    out += ["", "## Lethal-trifecta warnings", ""]
    out += [f"- {_cell(found.message(limit=10))}" for found in report.trifectas] or ["None."]
    out += ["", "## Honeytoken alerts", ""]
    if report.honeytoken_alerts:
        out += ["| Time | Tool | Alert |", "|---|---|---|"]
        out += [
            f"| {_when(alert['ts'])} | `{_cell(str(alert['server_id']))}."
            f"{_cell(str(alert['tool_name']))}` | {_cell(alert['message'])} |"
            for alert in report.honeytoken_alerts
        ]
    else:
        out.append("None.")
    return "\n".join(out) + "\n"


__all__ = ["Report", "build_report", "render_markdown", "render_text"]
