"""Read-only queries for the dashboard (audit log, registry, flows, feedback)."""

from __future__ import annotations

import json
import re
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from airlock.audit.store import parse_duration_to_seconds

_COLUMNS = (
    "id, ts, session_id, server_id, direction, tool_name, verdict, would_have, rule, "
    "reasons, scores, latency_ms, args_preview, result_preview"
)
# "argument `to` contains alice@evil.example, which came from web.read_page 1 call ago"
_FLOW = re.compile(
    r"argument `(?P<arg>[^`]+)` (?:contains|is) (?P<value>.+?)"
    r"(?: \([^)]*\))?, (?:which came from|an id returned by) (?P<source>[\w.-]+)"
)


@dataclass(frozen=True)
class Filters:
    verdict: str | None = None
    tool: str | None = None
    server: str | None = None
    direction: str | None = None
    since: str | None = None
    limit: int = 100


def _connect(db_path: Path) -> sqlite3.Connection | None:
    if not db_path.is_file():
        return None
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    has_table = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'decisions'"
    ).fetchone()
    if not has_table:
        conn.close()
        return None
    return conn


def _row(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    for key in ("reasons", "scores"):
        try:
            item[key] = json.loads(item[key] or ("[]" if key == "reasons" else "{}"))
        except ValueError:
            item[key] = [] if key == "reasons" else {}
    return item


def decisions(
    db_path: Path, filters: Filters | None = None, after_id: int = 0
) -> list[dict[str, Any]]:
    """Newest first; ``after_id`` returns only rows newer than that id (live updates)."""
    filters = filters or Filters()
    conn = _connect(db_path)
    if conn is None:
        return []
    clauses = ["direction != 'list'", "id > ?"]
    params: list[Any] = [after_id]
    for column, value in (
        ("verdict", filters.verdict.upper() if filters.verdict else None),
        ("tool_name", filters.tool),
        ("server_id", filters.server),
        ("direction", filters.direction),
    ):
        if value:
            clauses.append(f"{column} = ?")
            params.append(value)
    if filters.since:
        clauses.append("ts >= ?")
        params.append(time.time() - parse_duration_to_seconds(filters.since))
    params.append(max(1, min(filters.limit, 1000)))
    try:
        rows = conn.execute(
            f"SELECT {_COLUMNS} FROM decisions WHERE {' AND '.join(clauses)} "
            "ORDER BY id DESC LIMIT ?",
            params,
        ).fetchall()
        return [_row(row) for row in rows]
    finally:
        conn.close()


def decision(db_path: Path, decision_id: int) -> dict[str, Any] | None:
    conn = _connect(db_path)
    if conn is None:
        return None
    try:
        row = conn.execute(
            f"SELECT {_COLUMNS} FROM decisions WHERE id = ?", (decision_id,)
        ).fetchone()
        return _row(row) if row else None
    finally:
        conn.close()


@dataclass(frozen=True)
class Flow:
    decision_id: int
    source: str
    value: str
    argument: str
    sink: str
    verdict: str
    rule: str


def flows(db_path: Path, since: str = "7d", limit: int = 50) -> list[Flow]:
    """Taint blocks: source tool -> tainted value -> sink tool, parsed from decision reasons."""
    found: list[Flow] = []
    for row in decisions(db_path, Filters(direction="call", since=since, limit=1000)):
        effective = row["would_have"] or row["verdict"]
        if effective == "ALLOW" and not str(row["rule"] or "").startswith("approval:"):
            continue
        for reason in row["reasons"]:
            match = _FLOW.search(str(reason))
            if match:
                found.append(
                    Flow(
                        decision_id=int(row["id"]),
                        source=match["source"],
                        value=match["value"],
                        argument=match["arg"],
                        sink=f"{row['server_id']}.{row['tool_name']}",
                        verdict=effective,
                        rule=str(row["rule"] or ""),
                    )
                )
        if len(found) >= limit:
            break
    return found[:limit]


def save_feedback(data_dir: Path, row: dict[str, Any]) -> Path:
    """Store a decision marked as a false positive in ``data_dir/feedback/`` (for training)."""
    folder = data_dir / "feedback"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"decision-{int(row['id'])}.json"
    record = {
        "marked_at": time.time(),
        "label": "false_positive",
        "decision": row,
        "text": row.get("result_preview") or row.get("args_preview") or "",
    }
    path.write_text(json.dumps(record, indent=2, default=str), encoding="utf-8")
    return path


__all__ = ["Filters", "Flow", "decision", "decisions", "flows", "save_feedback"]
