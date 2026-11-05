"""Tests for Airlock stdio transport proxy."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from airlock.engine import Engine, Session
from airlock.models import Decision, ToolResult, Verdict
from airlock.transport.stdio import get_server_id, run_stdio_proxy

FIXTURES_DIR = Path(__file__).parent / "fixtures"
FAKE_SERVER = FIXTURES_DIR / "fake_server.py"
WRAP_WITH_DENY = FIXTURES_DIR / "wrap_with_deny.py"


def test_server_id_generation() -> None:
    """Explicit name is used if provided; otherwise a stable 12-char hash is computed."""
    assert get_server_id(["python", "srv.py"], name="my-server") == "my-server"
    h1 = get_server_id(["python", "srv.py"])
    h2 = get_server_id(["python", "srv.py"])
    assert len(h1) == 12
    assert h1 == h2
    assert h1 != get_server_id(["python", "other.py"])


@pytest.mark.asyncio
async def test_integration_direct_vs_wrapped_equals() -> None:
    """Results from calling airlock wrap must equal calling the server directly."""
    # 1. Connect directly to fake_server
    direct_params = StdioServerParameters(
        command=sys.executable,
        args=[str(FAKE_SERVER)],
        env=dict(os.environ),
    )
    async with stdio_client(direct_params) as (read_d, write_d):
        async with ClientSession(read_d, write_d) as direct_session:
            await direct_session.initialize()
            direct_tools = await direct_session.list_tools()
            direct_echo = await direct_session.call_tool("echo", {"text": "hello direct"})

    # 2. Connect via airlock wrap
    wrapped_params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "airlock.cli",
            "wrap",
            "--name",
            "fake-server",
            "--",
            sys.executable,
            str(FAKE_SERVER),
        ],
        env=dict(os.environ),
    )
    async with stdio_client(wrapped_params) as (read_w, write_w):
        async with ClientSession(read_w, write_w) as wrapped_session:
            await wrapped_session.initialize()
            wrapped_tools = await wrapped_session.list_tools()
            wrapped_echo = await wrapped_session.call_tool("echo", {"text": "hello direct"})

    # Compare results
    direct_tool_names = sorted(t.name for t in direct_tools.tools)
    wrapped_tool_names = sorted(t.name for t in wrapped_tools.tools)
    assert direct_tool_names == wrapped_tool_names
    assert wrapped_echo.is_error == direct_echo.is_error
    assert wrapped_echo.content[0].text == direct_echo.content[0].text  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_integration_deny_send_email(tmp_path: Path) -> None:
    """When a check denies send_email, client receives isError=True and record file stays empty."""
    record_file = tmp_path / "emails_recorded.json"
    env = dict(os.environ)
    env["AIRLOCK_FAKE_SERVER_RECORD_FILE"] = str(record_file)

    wrapped_params = StdioServerParameters(
        command=sys.executable,
        args=[
            str(WRAP_WITH_DENY),
            "--",
            sys.executable,
            str(FAKE_SERVER),
        ],
        env=env,
    )
    async with stdio_client(wrapped_params) as (read_w, write_w):
        async with ClientSession(read_w, write_w) as session:
            await session.initialize()

            # Calling allowed tool works
            echo_res = await session.call_tool("echo", {"text": "echo allowed"})
            assert echo_res.is_error is False or echo_res.is_error is None

            # Calling denied tool returns is_error=True
            denied_res = await session.call_tool(
                "send_email",
                {"to": "victim@example.com", "body": "classified"},
            )
            assert denied_res.is_error is True
            assert any(
                "Blocked by Airlock" in (c.text or "")  # type: ignore[union-attr]
                for c in (denied_res.content or [])
            )

    # Record file should not have been created or modified
    assert not record_file.exists() or record_file.read_text(encoding="utf-8") == ""


@pytest.mark.asyncio
async def test_tool_result_redaction_and_denial(tmp_path: Path) -> None:
    """Inbound tool results can be denied or redacted via on_tool_result."""

    class InboundInspectorCheck:
        name = "inbound_inspector"

        async def check(self, result: ToolResult, session: Session) -> Decision:
            if result.tool_name == "read_page":
                return Decision(
                    verdict=Verdict.REDACT,
                    modified_payload=[{"type": "text", "text": "REDACTED PAGE"}],
                )
            return Decision(verdict=Verdict.ALLOW)

    engine = Engine(tool_result_checks=[InboundInspectorCheck()])

    # Pipe client simulation
    client_in_reader = asyncio.StreamReader()
    out_lines: list[str] = []

    def capture_stdout(line: str) -> None:
        out_lines.append(line)

    proxy_task = asyncio.create_task(
        run_stdio_proxy(
            [sys.executable, str(FAKE_SERVER)],
            name="test-inbound",
            engine=engine,
            stdin_reader=client_in_reader,
            stdout_writer=capture_stdout,
        )
    )

    # Send initialize request
    init_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0"},
        },
    }
    client_in_reader.feed_data((json.dumps(init_req) + "\n").encode("utf-8"))

    # Send read_page call
    call_req = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "read_page", "arguments": {"url": "https://example.com"}},
    }
    client_in_reader.feed_data((json.dumps(call_req) + "\n").encode("utf-8"))

    # Give child server time to process and respond
    for _ in range(50):
        if any('"id": 2' in line or '"id":2' in line for line in out_lines):
            break
        await asyncio.sleep(0.05)

    # Close client
    client_in_reader.feed_eof()
    await proxy_task

    call_response_line = next(
        line_item for line_item in out_lines if '"id": 2' in line_item or '"id":2' in line_item
    )
    call_response = json.loads(call_response_line)
    assert call_response["result"]["content"][0]["text"] == "REDACTED PAGE"


@pytest.mark.asyncio
async def test_tools_list_filtering() -> None:
    """Tools listed by server are filtered by on_tools_listed check."""

    class FilterEchoCheck:
        name = "filter_echo"

        async def check(self, server_id: str, tools: list[Any]) -> list[Any]:
            return [t for t in tools if t.name != "echo"]

    engine = Engine(tools_listed_checks=[FilterEchoCheck()])

    client_in_reader = asyncio.StreamReader()
    out_lines: list[str] = []

    def capture_stdout(line: str) -> None:
        out_lines.append(line)

    proxy_task = asyncio.create_task(
        run_stdio_proxy(
            [sys.executable, str(FAKE_SERVER)],
            name="filter-srv",
            engine=engine,
            stdin_reader=client_in_reader,
            stdout_writer=capture_stdout,
        )
    )

    init_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0"},
        },
    }
    client_in_reader.feed_data((json.dumps(init_req) + "\n").encode("utf-8"))

    list_req = {
        "jsonrpc": "2.0",
        "id": 10,
        "method": "tools/list",
        "params": {},
    }
    client_in_reader.feed_data((json.dumps(list_req) + "\n").encode("utf-8"))

    for _ in range(50):
        if any('"id": 10' in line or '"id":10' in line for line in out_lines):
            break
        await asyncio.sleep(0.05)

    client_in_reader.feed_eof()
    await proxy_task

    response_line = next(
        line_item for line_item in out_lines if '"id": 10' in line_item or '"id":10' in line_item
    )
    resp = json.loads(response_line)
    tool_names = [t["name"] for t in resp["result"]["tools"]]
    assert "echo" not in tool_names
    assert "read_page" in tool_names
