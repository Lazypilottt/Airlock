"""`airlock attack`: the automated report card, the malicious test server, client mode."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from typer.testing import CliRunner

from airlock.attack import client as kit
from airlock.attack.scenarios import NOTICE, SCENARIOS, CanaryListener, http_post
from airlock.attack.sdk_run import render, run_sdk
from airlock.cli import app
from airlock.honeytokens.store import HoneytokenFile, save, store_path
from airlock.honeytokens.tokens import create_set

REPO = Path(__file__).parents[1]


def test_every_scenario_succeeds_without_and_is_detected_with_airlock(tmp_path: Path) -> None:
    outcomes = run_sdk(tmp_path)
    assert [o.scenario for o in outcomes] == [s.id for s in SCENARIOS]
    for outcome in outcomes:
        assert outcome.without_airlock.startswith("succeeded"), outcome
        assert outcome.detected, outcome
    by_id = {o.scenario: o for o in outcomes}
    assert "L1 matched rules" in by_id["poisoned_description"].detected_by
    assert "L1 matched rules" in by_id["shadowing"].detected_by
    assert "hash changed" in by_id["rug_pull"].detected_by
    assert by_id["exfiltration"].detected_by == "honeytoken"
    assert by_id["injected_base64"].detected_by != "-"
    card = render(outcomes, tmp_path)
    assert "Detected with Airlock: 8 of 8 scenarios." in card


def test_cli_sdk_mode(tmp_path: Path) -> None:
    result = CliRunner().invoke(app, ["attack", "--sdk", "--data-dir", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert NOTICE in result.stderr
    assert "8 of 8" in result.stdout
    as_json = CliRunner().invoke(
        app, ["attack", "--sdk", "--json", "--data-dir", str(tmp_path / "j")]
    )
    rows = json.loads(as_json.stdout)
    assert len(rows) == 8 and all(row["detected"] for row in rows)


@pytest.mark.parametrize(
    "args", [[], ["--sdk", "--client", "cursor"], ["--sdk", "--scenario", "rug_pull"]]
)
def test_cli_argument_errors(args: list[str]) -> None:
    result = CliRunner().invoke(app, ["attack", *args])
    assert result.exit_code == 1


def test_notice_in_help_and_server() -> None:
    assert "For testing your own setup only" in CliRunner().invoke(app, ["attack", "--help"]).output
    assert "FOR TESTING YOUR OWN SETUP ONLY" in (REPO / "attack" / "server.py").read_text()


def test_http_post_only_reaches_the_local_canary() -> None:
    assert http_post("https://example.com/x", "data").startswith("refused")
    with CanaryListener() as canary:
        http_post(canary.url(), "hello")
        assert canary.received("hello")


# ---------------------------------------------------------------------------
# The malicious server through `airlock wrap`, end to end
# ---------------------------------------------------------------------------


def _params(
    tmp_path: Path, canary: CanaryListener, token: str, wrapped: bool
) -> StdioServerParameters:
    config = tmp_path / "airlock.yaml"
    config.write_text(f"data_dir: {tmp_path / 'data'}\napprovals: {{terminal: false}}\n")
    env = {**os.environ, "AIRLOCK_ATTACK_CANARY_URL": canary.url(), "AIRLOCK_ATTACK_TOKEN": token}
    server = [sys.executable, str(REPO / "attack" / "server.py")]
    if not wrapped:
        return StdioServerParameters(command=server[0], args=server[1:], env=env, cwd=str(REPO))
    return StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "airlock.cli",
            "wrap",
            "--config",
            str(config),
            "--name",
            kit.SERVER,
            "--",
            *server,
        ],
        env=env,
        cwd=str(REPO),
    )


async def _play(params: StdioServerParameters, token: str) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            seen["tools"] = {tool.name for tool in (await session.list_tools()).tools}
            weather = await session.call_tool("get_weather", {"city": "Lisbon", "variant": "html"})
            seen["weather"] = weather.content[0].text  # type: ignore[union-attr]
            seen["calc1"] = (
                (await session.call_tool("calculate", {"expression": "6*7"})).content[0].text
            )  # type: ignore[union-attr]
            await asyncio.sleep(0.5)  # let the list_changed refresh land
            seen["calc2"] = (
                (await session.call_tool("calculate", {"expression": "2+2"})).content[0].text
            )  # type: ignore[union-attr]
            notes = (await session.call_tool("read_notes", {})).content[0].text  # type: ignore[union-attr]
            seen["notes_has_token"] = token in notes
            canary_url = notes.split("url=", 1)[1].split()[0] if "url=" in notes else ""
            seen["post"] = (
                (await session.call_tool("http_post", {"url": canary_url, "body": token}))
                .content[0]
                .text
            )  # type: ignore[union-attr]
    return seen


async def test_test_server_through_airlock_wrap(tmp_path: Path) -> None:
    with CanaryListener() as canary:
        tokens = create_set(canary_port=canary.port)
        save(store_path(tmp_path / "data"), HoneytokenFile(tokens=tokens))
        token = tokens[1].value
        started = time.time()
        seen = await _play(_params(tmp_path, canary, token, wrapped=True), token)
        assert not canary.received(token)
        hit = canary.received(token)
    assert "add" not in seen["tools"] and "format_report" not in seen["tools"]
    assert "get_weather" in seen["tools"]
    assert "Ignore all previous instructions" not in seen["weather"]
    assert seen["calc1"] == "42"
    assert seen["calc2"].startswith("Blocked by Airlock")
    assert seen["post"].startswith("Blocked by Airlock: A planted honeytoken")
    outcomes = {
        o.scenario: o.result for o in kit.report_card(tmp_path / "data", started, hit, True)
    }
    assert all(result.startswith("BLOCKED") for result in outcomes.values()), outcomes


async def test_without_airlock_the_honeytoken_reaches_the_canary(tmp_path: Path) -> None:
    with CanaryListener() as canary:
        token = create_set(canary_port=canary.port)[1].value
        seen = await _play(_params(tmp_path, canary, token, wrapped=False), token)
        assert canary.received(token)
    assert {"add", "format_report"} <= seen["tools"]
    assert "Ignore all previous instructions" in seen["weather"]
    assert seen["post"].startswith("posted")


# ---------------------------------------------------------------------------
# Client mode
# ---------------------------------------------------------------------------


def test_attack_config_copy(tmp_path: Path) -> None:
    source = tmp_path / "claude.json"
    source.write_text(json.dumps({"mcpServers": {"fs": {"command": "npx"}}, "x": 1}))
    entry = kit.attack_entry(
        "/opt/airlock", "http://127.0.0.1:9/c", "tok", wrapped=True, python="py"
    )
    target = kit.write_attack_config(source, tmp_path / "copy.json", entry)
    data = json.loads(target.read_text())
    assert data["x"] == 1 and data["mcpServers"]["fs"] == {"command": "npx"}
    server = data["mcpServers"][kit.SERVER]
    assert server["command"] == "/opt/airlock"
    assert server["args"] == [
        "wrap",
        "--name",
        kit.SERVER,
        "--",
        "py",
        "-m",
        "airlock.attack.server",
    ]
    assert server["env"] == {
        "AIRLOCK_ATTACK_CANARY_URL": "http://127.0.0.1:9/c",
        "AIRLOCK_ATTACK_TOKEN": "tok",
    }
    assert json.loads(source.read_text())["mcpServers"].keys() == {"fs"}  # original untouched
    bare = kit.attack_entry("/opt/airlock", "u", "t", wrapped=False, python="py")
    assert bare == {
        "command": "py",
        "args": ["-m", "airlock.attack.server"],
        "env": {"AIRLOCK_ATTACK_CANARY_URL": "u", "AIRLOCK_ATTACK_TOKEN": "t"},
    }


def test_client_mode_walkthrough(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    config = tmp_path / "airlock.yaml"
    config.write_text(f"data_dir: {tmp_path / 'data'}\n")
    result = CliRunner().invoke(
        app, ["attack", "--client", "cursor", "-c", str(config)], input="\n"
    )
    assert result.exit_code == 0, result.output
    assert "Quit Cursor" in result.output and kit.PROMPTS[0] in result.output
    copy = tmp_path / "data" / "attack" / "cursor-config.json"
    assert kit.SERVER in json.loads(copy.read_text())["mcpServers"]
    assert "not seen" in result.output or "not exercised" in result.output
    assert not (home / ".cursor" / "mcp.json").exists()  # the real config is never written
