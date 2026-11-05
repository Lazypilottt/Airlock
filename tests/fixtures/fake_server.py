"""Fake MCP server for Airlock integration tests."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

try:
    from mcp.server.fastmcp import FastMCP
except (ImportError, ModuleNotFoundError):
    from mcp.server.mcpserver import MCPServer as FastMCP  # type: ignore[no-redef]

server = FastMCP("fake-server")
PAGES_DIR = Path(__file__).parent / "pages"


@server.tool()
def echo(text: str) -> str:
    """Return text unchanged."""
    return text


@server.tool()
def read_page(url: str) -> str:
    """Return canned page text from tests/fixtures/pages."""
    # Attempt domain-based filename first
    clean_name = url.replace("https://", "").replace("http://", "").split("/")[0]
    candidate = PAGES_DIR / f"{clean_name}.txt"
    if candidate.is_file():
        return candidate.read_text(encoding="utf-8")

    default_file = PAGES_DIR / "default.txt"
    if default_file.is_file():
        return default_file.read_text(encoding="utf-8")

    return f"Canned response for {url}"


@server.tool()
def send_email(to: str, body: str) -> str:
    """Record email to record file."""
    record_file = os.environ.get("AIRLOCK_FAKE_SERVER_RECORD_FILE")
    if record_file:
        rec_path = Path(record_file)
        data: list[dict[str, Any]] = []
        if rec_path.is_file():
            try:
                data = json.loads(rec_path.read_text(encoding="utf-8"))
            except Exception:
                data = []
        data.append({"to": to, "body": body})
        rec_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    return f"Email sent to {to}"


if __name__ == "__main__":
    server.run(transport="stdio")
