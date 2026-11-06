"""SQLite-backed audit store for Airlock decisions."""

from __future__ import annotations

import asyncio
import json
import re
import sqlite3
import time
from pathlib import Path
from typing import Any

from airlock.audit.secrets import sanitize_preview


def parse_duration_to_seconds(since_str: str) -> float:
    """Convert human-readable duration strings (e.g. 30m, 2h, 7d) to seconds."""
    clean = since_str.strip().lower()
    units: dict[str, float] = {
        "s": 1.0,
        "m": 60.0,
        "h": 3600.0,
        "d": 86400.0,
        "w": 604800.0,
    }
    match = re.match(r"^(\d+(?:\.\d+)?)\s*([smhdw])$", clean)
    if not match:
        raise ValueError(
            f"Invalid duration format: '{since_str}'. Expected format like '30m', '2h', '7d'."
        )
    value, unit = match.groups()
    return float(value) * units[unit]


class AuditStore:
    """Asynchronous, non-blocking SQLite audit store using WAL mode."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()
        self._worker_task: asyncio.Task[None] | None = None
        self._started = False

    def _init_db(self, conn: sqlite3.Connection) -> None:
        """Initialize SQLite WAL mode and table schema."""
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                session_id TEXT NOT NULL,
                server_id TEXT NOT NULL,
                direction TEXT NOT NULL,
                tool_name TEXT,
                verdict TEXT NOT NULL,
                would_have TEXT,
                rule TEXT,
                reasons TEXT NOT NULL,
                scores TEXT NOT NULL,
                latency_ms REAL NOT NULL,
                args_preview TEXT,
                result_preview TEXT
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_decisions_ts ON decisions(ts);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_decisions_session ON decisions(session_id);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_decisions_tool ON decisions(tool_name);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_decisions_verdict ON decisions(verdict);")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                kind TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                session_id TEXT,
                server_id TEXT,
                tool_name TEXT
            );
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);")
        conn.commit()

    def start(self) -> None:
        """Start the background writer task if not already running."""
        if not self._started:
            self._started = True
            self._worker_task = asyncio.create_task(self._worker())

    async def _worker(self) -> None:
        """Background loop reading decision records and writing to SQLite."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._init_db(conn)

        try:
            while True:
                item = await self._queue.get()
                if item is None:
                    self._queue.task_done()
                    break

                try:
                    if item.get("_table") == "alerts":
                        conn.execute(
                            """
                            INSERT INTO alerts (
                                ts, kind, severity, message, session_id, server_id, tool_name
                            ) VALUES (?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                item["ts"],
                                item["kind"],
                                item["severity"],
                                item["message"],
                                item["session_id"],
                                item["server_id"],
                                item["tool_name"],
                            ),
                        )
                        conn.commit()
                        continue
                    conn.execute(
                        """
                        INSERT INTO decisions (
                            ts, session_id, server_id, direction, tool_name,
                            verdict, would_have, rule, reasons, scores,
                            latency_ms, args_preview, result_preview
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            item["ts"],
                            item["session_id"],
                            item["server_id"],
                            item["direction"],
                            item["tool_name"],
                            item["verdict"],
                            item["would_have"],
                            item["rule"],
                            json.dumps(item["reasons"]),
                            json.dumps(item["scores"]),
                            item["latency_ms"],
                            item["args_preview"],
                            item["result_preview"],
                        ),
                    )
                    conn.commit()
                except Exception as exc:
                    import sys

                    sys.stderr.write(f"[airlock audit error] Failed to insert: {exc}\n")
                finally:
                    self._queue.task_done()
        finally:
            conn.close()

    async def log_decision(
        self,
        session_id: str,
        server_id: str,
        direction: str,
        verdict: str,
        latency_ms: float,
        tool_name: str | None = None,
        would_have: str | None = None,
        rule: str | None = None,
        reasons: list[str] | None = None,
        scores: dict[str, float] | None = None,
        args: Any | None = None,
        result: Any | None = None,
        args_preview: str | None = None,
        result_preview: str | None = None,
        ts: float | None = None,
    ) -> None:
        """Enqueue a decision record for asynchronous writing."""
        self.start()

        final_args_preview = args_preview if args_preview is not None else sanitize_preview(args)
        final_result_preview = (
            result_preview if result_preview is not None else sanitize_preview(result)
        )

        record: dict[str, Any] = {
            "ts": ts if ts is not None else time.time(),
            "session_id": session_id,
            "server_id": server_id,
            "direction": direction,
            "tool_name": tool_name,
            "verdict": verdict,
            "would_have": would_have,
            "rule": rule,
            "reasons": reasons or [],
            "scores": scores or {},
            "latency_ms": latency_ms,
            "args_preview": final_args_preview or None,
            "result_preview": final_result_preview or None,
        }
        await self._queue.put(record)

    async def log_alert(
        self,
        *,
        kind: str,
        severity: str,
        message: str,
        session_id: str | None = None,
        server_id: str | None = None,
        tool_name: str | None = None,
    ) -> None:
        """Queue an alert (honeytoken hit, lethal trifecta...) for the ``alerts`` table."""
        self.start()
        await self._queue.put(
            {
                "_table": "alerts",
                "ts": time.time(),
                "kind": kind,
                "severity": severity,
                "message": sanitize_preview(message, max_length=2000),
                "session_id": session_id,
                "server_id": server_id,
                "tool_name": tool_name,
            }
        )

    def query_alerts(
        self, kind: str | None = None, since: str | float | None = None, limit: int = 50
    ) -> list[dict[str, Any]]:
        """Most recent alerts first."""
        if not self.db_path.is_file():
            return []
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            has_table = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'alerts'"
            ).fetchone()
            if not has_table:
                return []
            clauses: list[str] = []
            params: list[Any] = []
            if kind:
                clauses.append("kind = ?")
                params.append(kind)
            if since is not None:
                cutoff = (
                    float(since)
                    if isinstance(since, (int, float))
                    else time.time() - parse_duration_to_seconds(str(since))
                )
                clauses.append("ts >= ?")
                params.append(cutoff)
            where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            params.append(limit)
            rows = conn.execute(
                f"SELECT * FROM alerts {where_sql} ORDER BY id DESC LIMIT ?", params
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    async def flush(self) -> None:
        """Wait until all queued records are written to SQLite."""
        if self._started:
            await self._queue.join()

    async def close(self) -> None:
        """Flush remaining records and cleanly terminate the background worker."""
        if self._started and self._worker_task is not None:
            await self._queue.put(None)
            await self._worker_task
            self._started = False
            self._worker_task = None

    def query_decisions(
        self,
        session: str | None = None,
        tool: str | None = None,
        verdict: str | None = None,
        since: str | float | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """Query decisions matching criteria from SQLite database."""
        if not self.db_path.is_file():
            return []

        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            clauses: list[str] = []
            params: list[Any] = []

            if session:
                clauses.append("session_id = ?")
                params.append(session)

            if tool:
                clauses.append("tool_name = ?")
                params.append(tool)

            if verdict:
                clauses.append("verdict = ?")
                params.append(verdict.upper())

            if since is not None:
                if isinstance(since, (int, float)):
                    cutoff = float(since)
                else:
                    seconds = parse_duration_to_seconds(str(since))
                    cutoff = time.time() - seconds
                clauses.append("ts >= ?")
                params.append(cutoff)

            where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            query_sql = f"""
                SELECT id, ts, session_id, server_id, direction, tool_name,
                       verdict, would_have, rule, reasons, scores,
                       latency_ms, args_preview, result_preview
                FROM decisions
                {where_sql}
                ORDER BY id DESC
                LIMIT ?
            """
            params.append(limit)

            cursor = conn.execute(query_sql, params)
            rows = cursor.fetchall()
            results: list[dict[str, Any]] = []
            for row in rows:
                item = dict(row)
                try:
                    item["reasons"] = json.loads(item["reasons"])
                except Exception:
                    pass
                try:
                    item["scores"] = json.loads(item["scores"])
                except Exception:
                    pass
                results.append(item)
            return results
        finally:
            conn.close()


__all__ = [
    "AuditStore",
    "parse_duration_to_seconds",
]
