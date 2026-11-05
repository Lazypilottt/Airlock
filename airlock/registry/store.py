"""SQLite-backed tool registry with hash pinning, quarantine, and TOFU."""

from __future__ import annotations

import difflib
import hashlib
import json
import sqlite3
import sys
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from airlock.audit.secrets import mask_secrets
from airlock.models import ToolDef
from airlock.registry.checks import DescriptionCheck


def compute_tool_hash(tool: ToolDef | dict[str, Any]) -> tuple[str, str]:
    """Compute sha256 of canonical JSON representation of tool definition.

    Returns (sha256_hex, canonical_json_string).
    """
    if isinstance(tool, ToolDef):
        name = tool.name
        description = tool.description
        input_schema = tool.input_schema
        annotations = tool.annotations
    else:
        name = tool.get("name", "")
        description = tool.get("description", "")
        input_schema = tool.get("inputSchema") or tool.get("input_schema") or {}
        annotations = tool.get("annotations")

    canonical_dict: dict[str, Any] = {
        "annotations": annotations,
        "description": description,
        "input_schema": input_schema,
        "name": name,
    }
    canonical_json = json.dumps(
        canonical_dict,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    hash_hex = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    return hash_hex, canonical_json


def generate_unified_diff(old_json: str, new_json: str, tool_name: str) -> str:
    """Generate readable unified diff between old and new tool definitions."""
    try:
        old_obj = json.loads(old_json)
        old_lines = json.dumps(old_obj, indent=2, sort_keys=True).splitlines(keepends=True)
    except Exception:
        old_lines = old_json.splitlines(keepends=True)

    try:
        new_obj = json.loads(new_json)
        new_lines = json.dumps(new_obj, indent=2, sort_keys=True).splitlines(keepends=True)
    except Exception:
        new_lines = new_json.splitlines(keepends=True)

    diff = difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=f"a/{tool_name}",
        tofile=f"b/{tool_name}",
    )
    return "".join(diff)


class ToolRegistry:
    """Manages MCP tool definitions, integrity hash pinning, and status lifecycle."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        conn = self._get_connection()
        try:
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS tools (
                    server_id TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    hash TEXT NOT NULL,
                    definition_json TEXT NOT NULL,
                    previous_definition_json TEXT,
                    first_seen REAL NOT NULL,
                    last_seen REAL NOT NULL,
                    status TEXT NOT NULL, -- approved, pending, quarantined
                    status_reason TEXT,
                    labels TEXT NOT NULL, -- JSON list
                    PRIMARY KEY (server_id, tool_name)
                );
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_tools_status ON tools(status);")
            conn.commit()
        finally:
            conn.close()

    def is_server_known(self, server_id: str) -> bool:
        """Check if any tools for server_id have been registered previously."""
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                "SELECT COUNT(*) as count FROM tools WHERE server_id = ?",
                (server_id,),
            )
            row = cursor.fetchone()
            return bool(row and row["count"] > 0)
        finally:
            conn.close()

    def get_tool(self, server_id: str, tool_name: str) -> dict[str, Any] | None:
        """Retrieve tool record by server_id and tool_name."""
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                "SELECT * FROM tools WHERE server_id = ? AND tool_name = ?",
                (server_id, tool_name),
            )
            row = cursor.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def list_tools(self, server_id: str | None = None) -> list[dict[str, Any]]:
        """List all tools, optionally filtered by server_id."""
        conn = self._get_connection()
        try:
            if server_id:
                cursor = conn.execute(
                    "SELECT * FROM tools WHERE server_id = ? ORDER BY tool_name",
                    (server_id,),
                )
            else:
                cursor = conn.execute("SELECT * FROM tools ORDER BY server_id, tool_name")
            return [dict(r) for r in cursor.fetchall()]
        finally:
            conn.close()

    async def process_server_tools(
        self,
        server_id: str,
        tools: Sequence[ToolDef],
        description_checks: Sequence[DescriptionCheck] | None = None,
        auto_approve_new_tools: bool = False,
    ) -> tuple[list[ToolDef], list[tuple[str, str]]]:
        """Update tool registry, perform TOFU / hash checks, and return visible tools.

        Returns (visible_tools, [(tool_name, unified_diff), ...]).
        """
        now = time.time()
        conn = self._get_connection()
        checks = description_checks or []
        visible_tools: list[ToolDef] = []
        changed_diffs: list[tuple[str, str]] = []

        try:
            server_known = self.is_server_known(server_id)

            for tool in tools:
                hash_hex, def_json = compute_tool_hash(tool)
                cursor = conn.execute(
                    "SELECT * FROM tools WHERE server_id = ? AND tool_name = ?",
                    (server_id, tool.name),
                )
                existing = cursor.fetchone()

                if existing is None:
                    # New tool
                    flagged = False
                    flag_reason: str | None = None
                    for chk in checks:
                        is_flagged, reason = await chk.check(tool)
                        if is_flagged:
                            flagged = True
                            flag_reason = reason
                            break

                    if flagged:
                        status = "quarantined"
                        status_reason = flag_reason or "Flagged by description check"
                    elif not server_known:
                        # Trust On First Use
                        status = "approved"
                        status_reason = "Trust on first use"
                    else:
                        # Known server with new tool
                        if auto_approve_new_tools:
                            status = "approved"
                            status_reason = "Auto-approved new tool"
                        else:
                            status = "pending"
                            status_reason = "New tool on known server pending approval"

                    conn.execute(
                        """
                        INSERT INTO tools (
                            server_id, tool_name, hash, definition_json,
                            previous_definition_json, first_seen, last_seen,
                            status, status_reason, labels
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            server_id,
                            tool.name,
                            hash_hex,
                            def_json,
                            None,
                            now,
                            now,
                            status,
                            status_reason,
                            json.dumps([]),
                        ),
                    )

                else:
                    # Existing tool; verify pinned hash
                    old_hash = existing["hash"]
                    old_def = existing["definition_json"]
                    current_status = existing["status"]

                    if hash_hex != old_hash:
                        # Definition changed (rug pull)
                        diff = generate_unified_diff(old_def, def_json, tool.name)
                        changed_diffs.append((tool.name, diff))
                        status = "quarantined"
                        status_reason = (
                            f"Definition hash changed from {old_hash[:8]} to {hash_hex[:8]}"
                        )
                        safe_diff = mask_secrets(diff)
                        if len(safe_diff) > 4000:
                            safe_diff = safe_diff[:4000] + "\n[diff truncated]"
                        sys.stderr.write(
                            f"[airlock warning] Tool '{tool.name}' definition changed on server "
                            f"'{server_id}'! Quarantining tool.\nDiff:\n{safe_diff}\n"
                        )
                        sys.stderr.flush()

                        conn.execute(
                            """
                            UPDATE tools
                            SET hash = ?,
                                previous_definition_json = ?,
                                definition_json = ?,
                                last_seen = ?,
                                status = ?,
                                status_reason = ?
                            WHERE server_id = ? AND tool_name = ?
                            """,
                            (
                                hash_hex,
                                old_def,
                                def_json,
                                now,
                                status,
                                status_reason,
                                server_id,
                                tool.name,
                            ),
                        )
                    else:
                        # Definition unchanged
                        status = current_status
                        conn.execute(
                            "UPDATE tools SET last_seen = ? WHERE server_id = ? AND tool_name = ?",
                            (now, server_id, tool.name),
                        )

                # Only approved tools are visible to the MCP client
                if status == "approved":
                    visible_tools.append(tool)

            conn.commit()
            return visible_tools, changed_diffs
        finally:
            conn.close()

    def approve_tool(
        self,
        server_id: str,
        tool_name: str | None = None,
        all_tools: bool = False,
    ) -> int:
        """Approve a specific tool or all tools on a server."""
        conn = self._get_connection()
        now = time.time()
        try:
            if all_tools:
                cursor = conn.execute(
                    """
                    UPDATE tools
                    SET status = 'approved',
                        status_reason = 'Manually approved',
                        last_seen = ?
                    WHERE server_id = ?
                    """,
                    (now, server_id),
                )
            elif tool_name:
                cursor = conn.execute(
                    """
                    UPDATE tools
                    SET status = 'approved',
                        status_reason = 'Manually approved',
                        last_seen = ?
                    WHERE server_id = ? AND tool_name = ?
                    """,
                    (now, server_id, tool_name),
                )
            else:
                return 0
            count = cursor.rowcount
            conn.commit()
            return count
        finally:
            conn.close()

    def reset_server(self, server_id: str) -> int:
        """Delete all tools for server_id so next list is treated as first use (TOFU)."""
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                "DELETE FROM tools WHERE server_id = ?",
                (server_id,),
            )
            count = cursor.rowcount
            conn.commit()
            return count
        finally:
            conn.close()

    def get_tool_diff(self, server_id: str, tool_name: str) -> str | None:
        """Retrieve unified diff between previous and current definitions for a tool."""
        tool = self.get_tool(server_id, tool_name)
        if not tool:
            return None

        previous_def: str | None = (
            str(tool["previous_definition_json"])
            if tool["previous_definition_json"] is not None
            else None
        )
        current_def = str(tool["definition_json"])

        if previous_def is None:
            # No prior version; show formatted current definition
            try:
                obj = json.loads(current_def)
                return json.dumps(obj, indent=2)
            except Exception:
                return current_def

        return generate_unified_diff(previous_def, current_def, tool_name)


__all__ = [
    "ToolRegistry",
    "compute_tool_hash",
    "generate_unified_diff",
]
