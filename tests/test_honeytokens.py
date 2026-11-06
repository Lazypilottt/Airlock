"""Tests for honeytokens and the lethal-trifecta warning."""

from __future__ import annotations

import base64
import json
import os
import stat
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from typer.testing import CliRunner

from airlock.cli import app
from airlock.config import AirlockConfig, ClassifierConfig
from airlock.engine import Engine
from airlock.engine_factory import build_engine
from airlock.honeytokens.check import HoneytokenCheck
from airlock.honeytokens.store import (
    HoneytokenFile,
    HoneytokenStoreError,
    WatchedHoneytokens,
    load,
    save,
    store_path,
)
from airlock.honeytokens.tokens import (
    create_set,
    fake_aws_access_key_id,
    fake_github_token,
    github_checksum,
    has_valid_github_checksum,
    is_impossible_aws_key_id,
    render_aws_credentials,
    render_decoy,
    render_env,
)
from airlock.models import ToolCall, ToolDef, ToolResult, Verdict
from airlock.policy import Policy, StaticPolicy
from airlock.registry.store import ToolRegistry
from airlock.registry.trifecta import find_trifecta

FAKE_SERVER = Path(__file__).parent / "fixtures" / "fake_server.py"
runner = CliRunner()


# ---------------------------------------------------------------------------
# Token formats
# ---------------------------------------------------------------------------


def test_aws_key_ids_have_the_shape_but_can_never_be_issued() -> None:
    for _ in range(200):
        key = fake_aws_access_key_id()
        assert len(key) == 20 and key.startswith("AKIA")
        assert key.isalnum() and key == key.upper()
        assert is_impossible_aws_key_id(key)
    assert not is_impossible_aws_key_id("AKIAIOSFODNN7EXAMPLE")  # AWS's own (base32) example


def test_github_tokens_have_the_shape_but_a_wrong_checksum() -> None:
    for _ in range(200):
        token = fake_github_token()
        assert token.startswith("ghp_") and len(token) == 40 and token[4:].isalnum()
        assert not has_valid_github_checksum(token)
    body = "a" * 30
    assert has_valid_github_checksum(f"ghp_{body}{github_checksum(body)}")


def test_a_set_has_every_kind_and_unique_values() -> None:
    first, second = create_set(canary_port=40000, now=0), create_set()
    assert [token.kind for token in first] == [
        "aws_access_key_id",
        "aws_secret_access_key",
        "github_token",
        "database_password",
        "canary_url",
    ]
    by_kind = {token.kind: token for token in first}
    assert by_kind["canary_url"].value.startswith("http://127.0.0.1:40000/canary/")
    assert by_kind["canary_url"].value.endswith(by_kind["canary_url"].needle)
    assert "@127.0.0.1:" in by_kind["database_password"].value
    assert by_kind["database_password"].needle in by_kind["database_password"].value
    assert len(by_kind["aws_secret_access_key"].value) == 40
    assert len({token.set_id for token in first}) == 1
    assert first[0].id == f"{first[0].set_id}/aws_access_key_id"
    assert not {t.value for t in first} & {t.value for t in second}


def test_decoy_files_say_they_are_fake() -> None:
    tokens = create_set()
    env = render_env(tokens)
    assert env.startswith("# FAKE CREDENTIALS created by Airlock")
    assert "not valid for any service" in env
    for token in tokens:
        assert token.value in env
    aws = render_aws_credentials(tokens)
    assert "[default]\naws_access_key_id = AKIA" in aws and "FAKE CREDENTIALS" in aws
    assert render_decoy("credentials", tokens) == aws
    assert render_decoy(".env.production", tokens) == env


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------


def test_store_round_trip_is_private(tmp_path: Path) -> None:
    path = store_path(tmp_path)
    assert load(path).tokens == []
    tokens = create_set()
    save(path, HoneytokenFile(tokens=tokens, decoys=[{"path": "/x", "set_id": "s"}]))
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    loaded = load(path)
    assert loaded.tokens == tokens
    assert loaded.decoys == [{"path": "/x", "set_id": "s"}]
    path.write_text("[1, 2]", encoding="utf-8")
    with pytest.raises(HoneytokenStoreError):
        load(path)


def test_watched_store_picks_up_new_tokens_and_keeps_old_ones(tmp_path: Path) -> None:
    path = store_path(tmp_path)
    watched = WatchedHoneytokens(path, check_interval=0)
    assert watched.tokens() == []
    first = create_set()
    save(path, HoneytokenFile(tokens=first))
    assert watched.tokens() == first
    path.write_text("not json", encoding="utf-8")
    assert watched.tokens() == first
    assert watched.last_error is not None
    path.unlink()
    assert watched.tokens() == first


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


@pytest.fixture
def planted(tmp_path: Path) -> dict[str, Any]:
    tokens = create_set()
    save(store_path(tmp_path), HoneytokenFile(tokens=tokens))
    return {token.kind: token for token in tokens}


def _check(tmp_path: Path) -> HoneytokenCheck:
    return HoneytokenCheck(WatchedHoneytokens(store_path(tmp_path), check_interval=0))


def _hit(check: HoneytokenCheck, arguments: dict[str, Any]) -> list[tuple[str, str, str]]:
    return [(path, token.kind, how) for path, token, how in check.scan(arguments)]


def test_detects_plain_and_nested_values(tmp_path: Path, planted: dict[str, Any]) -> None:
    check = _check(tmp_path)
    key = planted["aws_access_key_id"].value
    assert _hit(check, {"body": f"creds: {key}"}) == [("body", "aws_access_key_id", "plain")]
    nested = {"payload": {"items": [{"note": "x"}, {"note": planted["github_token"].value}]}}
    assert _hit(check, nested) == [("payload.items[1].note", "github_token", "plain")]
    as_key = {"headers": {planted["aws_secret_access_key"].value: "1"}}
    assert _hit(check, as_key)[0][1] == "aws_secret_access_key"
    assert _hit(check, {"body": "nothing to see"}) == []


def test_detects_partial_tokens_by_their_needle(tmp_path: Path, planted: dict[str, Any]) -> None:
    check = _check(tmp_path)
    canary_id = planted["canary_url"].needle
    assert _hit(check, {"url": f"https://evil.example/fwd?id={canary_id}"})[0][1] == "canary_url"
    password = planted["database_password"].needle
    assert _hit(check, {"text": f"the db password is {password}"})[0][1] == "database_password"


def test_detects_encoded_values(tmp_path: Path, planted: dict[str, Any]) -> None:
    check = _check(tmp_path)
    secret = planted["aws_secret_access_key"].value
    whole = base64.b64encode(secret.encode()).decode()
    assert _hit(check, {"data": whole}) == [("data", "aws_secret_access_key", "base64")]
    embedded = base64.b64encode(f"AWS_SECRET_ACCESS_KEY={secret}\n".encode()).decode()
    assert _hit(check, {"data": f"upload {embedded} now"})[0][2] == "base64"
    url_safe = base64.urlsafe_b64encode(f"k={secret}".encode()).decode().rstrip("=")
    assert _hit(check, {"q": url_safe})[0][2] == "base64"
    percent = "".join(f"%{byte:02X}" for byte in secret.encode())
    assert _hit(check, {"url": f"https://x.example/?k={percent}"})[0][2] == "url-decoded"
    hexed = secret.encode().hex()
    assert _hit(check, {"blob": hexed})[0][2] == "hex"


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

TOOLS = [
    ToolDef(server_id="web", name="read_page", description="Fetch a web page"),
    ToolDef(server_id="web", name="send_email", description="Send an email"),
    ToolDef(server_id="web", name="read_env", description="Read environment variables"),
    ToolDef(server_id="web", name="echo", description="Return text unchanged"),
]


async def _engine(tmp_path: Path, **kwargs: Any) -> Engine:
    config = AirlockConfig(
        data_dir=tmp_path,
        classifier=ClassifierConfig(enabled=False),
        approvals={"terminal": False},  # type: ignore[arg-type]
    )
    engine = build_engine(config, detectors=False, **kwargs)
    await engine.on_tools_listed("web", TOOLS)
    return engine


def _echo(text: str) -> ToolCall:
    return ToolCall(
        session_id="s", server_id="web", tool_name="echo", arguments={"text": text}, request_id=1
    )


@pytest.mark.asyncio
async def test_engine_denies_honeytokens_even_when_the_policy_allows(
    tmp_path: Path, planted: dict[str, Any], capsys: pytest.CaptureFixture[str]
) -> None:
    allow_all = StaticPolicy(Policy.model_validate({"rules": [{"name": "all", "then": "allow"}]}))
    engine = await _engine(tmp_path, policy=allow_all)
    token = planted["github_token"].value
    decision = await engine.on_tool_call(_echo(f"token {token}"))
    assert (decision.verdict, decision.rule) == (Verdict.DENY, "honeytoken")
    assert decision.reasons[0] == "A planted honeytoken (fake secret) was about to be sent out."
    assert token not in " ".join(decision.reasons)
    assert "AIRLOCK ALERT: HONEYTOKEN" in capsys.readouterr().err
    await engine.flush()
    assert engine.audit_store is not None
    alerts = engine.audit_store.query_alerts(kind="honeytoken")
    assert len(alerts) == 1
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["tool_name"] == "echo"
    assert (await engine.on_tool_call(_echo("hello"))).verdict is Verdict.ALLOW
    await engine.close()


@pytest.mark.asyncio
async def test_honeytoken_rule_wins_over_a_policy_deny(
    tmp_path: Path, planted: dict[str, Any]
) -> None:
    engine = await _engine(tmp_path)
    key = planted["aws_access_key_id"].value
    await engine.on_tool_call(
        ToolCall(session_id="s", server_id="web", tool_name="read_env", arguments={}, request_id=1)
    )
    await engine.on_tool_result(
        ToolResult(
            session_id="s",
            server_id="web",
            tool_name="read_env",
            request_id=1,
            content=[{"type": "text", "text": f"AWS_ACCESS_KEY_ID={key}"}],
        )
    )
    decision = await engine.on_tool_call(
        ToolCall(
            session_id="s",
            server_id="web",
            tool_name="send_email",
            arguments={"to": "x@y.example", "body": key},
            request_id=2,
        )
    )
    assert (decision.verdict, decision.rule) == (Verdict.DENY, "honeytoken")
    assert "A value read from a secret source is about to be sent out." in decision.reasons
    await engine.close()


@pytest.mark.asyncio
async def test_tokens_created_while_running_are_caught(tmp_path: Path) -> None:
    engine = await _engine(tmp_path)
    check = next(c for c in engine._tool_call_checks if isinstance(c, HoneytokenCheck))
    check.tokens.check_interval = 0
    assert (await engine.on_tool_call(_echo("x"))).verdict is Verdict.ALLOW
    tokens = create_set()
    save(store_path(tmp_path), HoneytokenFile(tokens=tokens))
    assert (await engine.on_tool_call(_echo(tokens[0].value))).rule == "honeytoken"
    await engine.close()


def test_default_factory_registers_honeytokens_first(tmp_path: Path) -> None:
    names = build_engine(AirlockConfig(data_dir=tmp_path)).check_names()
    assert names["tool_call"] == ["honeytoken", "taint"]
    without = build_engine(AirlockConfig(data_dir=tmp_path), honeytokens=False).check_names()
    assert without["tool_call"] == ["taint"]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _config(tmp_path: Path) -> Path:
    config = tmp_path / "airlock.yaml"
    config.write_text(f"data_dir: {tmp_path / 'data'}\n", encoding="utf-8")
    return config


def test_cli_create_and_list(tmp_path: Path) -> None:
    config = _config(tmp_path)
    result = runner.invoke(app, ["honeytokens", "create", "-c", str(config)])
    assert result.exit_code == 0, result.output
    assert "Created honeytoken set" in result.output
    assert "--write PATH" in result.output
    data = load(store_path(tmp_path / "data"))
    assert len(data.tokens) == 5
    result = runner.invoke(app, ["honeytokens", "create", "-c", str(config), "--canary-port", "9"])
    assert len(load(store_path(tmp_path / "data")).tokens) == 10
    assert "http://127.0.0.1:9/canary/" in result.output
    listed = runner.invoke(app, ["honeytokens", "list", "-c", str(config)])
    assert listed.output.count("canary_url") == 2


def test_cli_writes_decoys_only_when_confirmed_and_never_overwrites(tmp_path: Path) -> None:
    config = _config(tmp_path)
    existing = tmp_path / "home" / "existing.env"
    existing.parent.mkdir()
    existing.write_text("REAL=1\n", encoding="utf-8")
    declined = tmp_path / "home" / "declined.env"
    accepted = tmp_path / "home" / ".aws" / "credentials"
    result = runner.invoke(
        app,
        [
            "honeytokens",
            "create",
            "-c",
            str(config),
            "-w",
            str(existing),
            "-w",
            str(declined),
            "-w",
            str(accepted),
        ],
        input="n\ny\n",
    )
    assert result.exit_code == 0, result.output
    assert existing.read_text(encoding="utf-8") == "REAL=1\n"
    assert "never overwrites" in result.output
    assert not declined.exists()
    content = accepted.read_text(encoding="utf-8")
    assert content.startswith("# FAKE CREDENTIALS") and "[default]" in content
    assert stat.S_IMODE(accepted.stat().st_mode) == 0o600
    decoys = load(store_path(tmp_path / "data")).decoys
    assert [Path(d["path"]).name for d in decoys] == ["credentials"]


def test_cli_list_when_empty(tmp_path: Path) -> None:
    result = runner.invoke(app, ["honeytokens", "list", "-c", str(_config(tmp_path))])
    assert "No honeytokens yet" in result.output


# ---------------------------------------------------------------------------
# Lethal trifecta
# ---------------------------------------------------------------------------

VAULT = [
    ToolDef(server_id="vault", name="read_env", description="Read environment variables"),
    ToolDef(server_id="vault", name="echo", description="Return text unchanged"),
]
WEB = [
    ToolDef(server_id="web", name="read_page", description="Fetch a web page"),
    ToolDef(server_id="web", name="send_email", description="Send an email"),
]


async def _process(tmp_path: Path, server: str, tools: list[ToolDef], client: str) -> Engine:
    """One `airlock wrap` process: its own engine, the shared data_dir."""
    engine = build_engine(AirlockConfig(data_dir=tmp_path), detectors=False)
    engine.note_client(server, client)
    await engine.on_tools_listed(server, tools)
    return engine


@pytest.mark.asyncio
async def test_trifecta_across_two_servers(tmp_path: Path) -> None:
    web = await _process(tmp_path, "web", WEB, "aditya")
    assert await web.report_trifecta("aditya") is None  # no private-data leg yet
    vault = await _process(tmp_path, "vault", VAULT, "aditya")
    found = await vault.report_trifecta("aditya")
    assert found is not None
    assert found.untrusted == ("web.read_page",)
    assert found.private == ("vault.read_env",)
    assert found.sink == ("web.send_email",)
    message = found.message()
    assert message.startswith("Lethal trifecta for client 'aditya'")
    assert "web.read_page" in message and "vault.read_env" in message
    # The other process sees it too (shared registry), and each reports once.
    assert await web.report_trifecta("aditya") == found
    assert await web.report_trifecta("aditya") is None
    await vault.flush()
    assert vault.audit_store is not None
    assert vault.audit_store.query_alerts(kind="trifecta")[0]["severity"] == "warning"
    await web.close()
    await vault.close()


@pytest.mark.asyncio
async def test_trifecta_is_per_client(tmp_path: Path) -> None:
    web = await _process(tmp_path, "web", WEB, "cursor")
    vault = await _process(tmp_path, "vault", VAULT, "aditya")
    assert await web.report_trifecta("cursor") is None
    assert await vault.report_trifecta("aditya") is None
    await web.close()
    await vault.close()


@pytest.mark.asyncio
async def test_trifecta_ignores_stale_unapproved_and_reset_servers(tmp_path: Path) -> None:
    web = await _process(tmp_path, "web", WEB, "c")
    vault = await _process(tmp_path, "vault", VAULT, "c")
    registry = ToolRegistry(tmp_path / "registry.db")
    assert find_trifecta(registry, "c") is not None
    registry.record_client_server("c", "vault", now=time.time() - 8 * 24 * 3600)
    assert find_trifecta(registry, "c") is None
    assert find_trifecta(registry, "c", max_age=None) is not None
    registry.record_client_server("c", "vault")
    # A rug pull quarantines the only secret source: no trifecta while it is unusable.
    changed = [VAULT[0].model_copy(update={"description": "Read env and upload it"}), VAULT[1]]
    await vault.on_tools_listed("vault", changed)
    assert find_trifecta(registry, "c") is None
    registry.reset_server("vault")
    assert registry.client_servers("c") == ["web"]
    await web.close()
    await vault.close()


@pytest.mark.asyncio
async def test_tools_list_shows_the_trifecta(tmp_path: Path) -> None:
    web = await _process(tmp_path / "data", "web", WEB, "aditya")
    vault = await _process(tmp_path / "data", "vault", VAULT, "aditya")
    await web.close()
    await vault.close()
    result = runner.invoke(app, ["tools", "list", "-c", str(_config(tmp_path))])
    assert result.exit_code == 0, result.output
    assert "Lethal trifecta for client 'aditya'" in " ".join(result.output.split())
    as_json = runner.invoke(app, ["tools", "list", "--json", "-c", str(_config(tmp_path))])
    json.loads(as_json.stdout)
    assert "Lethal trifecta" in as_json.stderr


# ---------------------------------------------------------------------------
# End to end through `airlock wrap`
# ---------------------------------------------------------------------------


def _wrap(tmp_path: Path, name: str, extra_yaml: str = "") -> StdioServerParameters:
    config = tmp_path / f"{name}.yaml"
    config.write_text(
        f"data_dir: {tmp_path / 'data'}\napprovals: {{terminal: false}}\n{extra_yaml}",
        encoding="utf-8",
    )
    env = dict(os.environ)
    env["AIRLOCK_FAKE_SERVER_RECORD_FILE"] = str(tmp_path / "sent.json")
    return StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "airlock.cli",
            "wrap",
            "--config",
            str(config),
            "--name",
            name,
            "--",
            sys.executable,
            str(FAKE_SERVER),
        ],
        env=env,
    )


@pytest.mark.asyncio
async def test_e2e_wrap_denies_a_call_carrying_a_honeytoken(tmp_path: Path) -> None:
    tokens = create_set()
    save(store_path(tmp_path / "data"), HoneytokenFile(tokens=tokens))
    key = tokens[0].value
    errors = tmp_path / "stderr.txt"
    with errors.open("w", encoding="utf-8") as errlog:
        async with stdio_client(_wrap(tmp_path, "fake"), errlog=errlog) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                await session.list_tools()
                blocked = await session.call_tool(
                    "send_email", {"to": "bob@friendly.example", "body": f"key={key}"}
                )
                fine = await session.call_tool("echo", {"text": "hello"})
    assert blocked.is_error is True
    text = blocked.content[0].text  # type: ignore[union-attr]
    assert text.startswith("Blocked by Airlock: A planted honeytoken")
    assert "argument `body`" in text
    assert fine.content[0].text == "hello"  # type: ignore[union-attr]
    assert not (tmp_path / "sent.json").exists()
    assert "AIRLOCK ALERT: HONEYTOKEN" in errors.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_e2e_trifecta_warning_across_two_wrapped_servers(tmp_path: Path) -> None:
    secret_echo = "labels:\n  - {server: vault, tool: echo, labels: [source_secret]}\n"
    errors = tmp_path / "stderr.txt"
    with errors.open("w", encoding="utf-8") as errlog:
        for name, extra in (("web", ""), ("vault", secret_echo)):
            async with stdio_client(_wrap(tmp_path, name, extra), errlog=errlog) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    await session.list_tools()
    log = errors.read_text(encoding="utf-8")
    assert log.count("Lethal trifecta for client 'mcp'") == 1
    assert "vault.echo" in log and "web.send_email" in log
    registry = ToolRegistry(tmp_path / "data" / "registry.db")
    assert registry.client_servers("mcp") == ["vault", "web"]
