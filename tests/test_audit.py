"""Tests for Airlock audit store, secret masking, and logs CLI."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from airlock.audit.secrets import mask_secrets, sanitize_preview
from airlock.audit.store import AuditStore, parse_duration_to_seconds
from airlock.cli import app
from airlock.config import AirlockConfig
from airlock.engine import Engine, Session
from airlock.models import Decision, ToolCall, ToolResult, Verdict

runner = CliRunner(env={"COLUMNS": "160"})


def test_mask_secrets_patterns() -> None:
    """Secret patterns (AWS, GitHub, Bearer, Private keys, API keys) are masked."""
    # 1. AWS key
    aws_text = "My AWS key is AKIA1234567890ABCDEF in production"
    assert "AKIA1234567890ABCDEF" not in mask_secrets(aws_text)
    assert "[REDACTED_AWS_KEY]" in mask_secrets(aws_text)

    # 2. GitHub token
    gh_text = "github_token: ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    assert "ghp_1234567890" not in mask_secrets(gh_text)
    assert "[REDACTED_GITHUB_TOKEN]" in mask_secrets(gh_text)

    # 3. Bearer token
    bearer_text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz"
    assert "eyJhbGci" not in mask_secrets(bearer_text)
    assert "[REDACTED_BEARER_TOKEN]" in mask_secrets(bearer_text)

    # 4. Private key block
    priv_key = (
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
    )
    assert "MIIEowIBAAKCAQEA0" not in mask_secrets(priv_key)
    assert "[REDACTED_PRIVATE_KEY]" in mask_secrets(priv_key)

    # 5. Sensitive keyword assignment
    kw_text = 'api_key: "very_long_secret_api_token_123456789"'
    assert "very_long_secret_api_token" not in mask_secrets(kw_text)
    assert "[REDACTED_SECRET]" in mask_secrets(kw_text)


def test_sanitize_preview_truncation_and_masking() -> None:
    """Previews mask secrets first and truncate to max_length characters."""
    secret = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    long_data = {"key": secret, "payload": "A" * 600}
    sanitized = sanitize_preview(long_data, max_length=500)

    assert len(sanitized) <= 500
    assert secret not in sanitized
    assert "[REDACTED_GITHUB_TOKEN]" in sanitized


@pytest.mark.asyncio
async def test_audit_store_allow_and_deny_rows(tmp_path: Path) -> None:
    """Store persists ALLOW and DENY decision rows with correct attributes."""
    db_path = tmp_path / "test_audit.db"
    store = AuditStore(db_path)

    # Log ALLOW
    await store.log_decision(
        session_id="sess-allow",
        server_id="srv-1",
        direction="call",
        tool_name="read_file",
        verdict="ALLOW",
        latency_ms=12.5,
        args={"path": "/home/user/doc.txt"},
    )

    # Log DENY
    await store.log_decision(
        session_id="sess-deny",
        server_id="srv-1",
        direction="call",
        tool_name="send_email",
        verdict="DENY",
        rule="policy:no_exfil",
        reasons=["Sink exfiltration disallowed"],
        latency_ms=45.2,
        args={"to": "external@attacker.com", "api_key": "secret_key_value_123456"},
    )

    await store.close()

    # Query back
    rows = store.query_decisions(limit=10)
    assert len(rows) == 2

    deny_row = next(r for r in rows if r["verdict"] == "DENY")
    assert deny_row["session_id"] == "sess-deny"
    assert deny_row["tool_name"] == "send_email"
    assert deny_row["rule"] == "policy:no_exfil"
    assert "Sink exfiltration disallowed" in deny_row["reasons"]
    assert "secret_key_value" not in (deny_row["args_preview"] or "")
    assert "[REDACTED_SECRET]" in (deny_row["args_preview"] or "")

    allow_row = next(r for r in rows if r["verdict"] == "ALLOW")
    assert allow_row["session_id"] == "sess-allow"
    assert allow_row["tool_name"] == "read_file"
    assert allow_row["latency_ms"] == 12.5


@pytest.mark.asyncio
async def test_audit_store_queue_flush_on_shutdown(tmp_path: Path) -> None:
    """All decisions queued in background task are flushed on close()."""
    db_path = tmp_path / "flush_test.db"
    store = AuditStore(db_path)

    # Rapidly enqueue 100 records
    for i in range(100):
        await store.log_decision(
            session_id=f"sess-{i}",
            server_id="srv-fast",
            direction="call",
            tool_name="echo",
            verdict="ALLOW",
            latency_ms=1.0,
        )

    # Shutdown immediately
    await store.close()

    rows = store.query_decisions(limit=200)
    assert len(rows) == 100


@pytest.mark.asyncio
async def test_engine_writes_rows_per_decision(tmp_path: Path) -> None:
    """Engine automatically logs one row per on_tool_call and on_tool_result."""
    db_path = tmp_path / "engine_audit.db"
    store = AuditStore(db_path)
    config = AirlockConfig(data_dir=tmp_path)

    class DummyBlockEmail:
        name = "block_email"

        async def check(self, call: ToolCall, session: Session) -> Decision:
            if call.tool_name == "send_email":
                return Decision(
                    verdict=Verdict.DENY,
                    reasons=["No emails allowed"],
                    rule="rule:block_email",
                )
            return Decision(verdict=Verdict.ALLOW)

    engine = Engine(config=config, tool_call_checks=[DummyBlockEmail()], audit_store=store)

    call1 = ToolCall(
        session_id="s1",
        server_id="srv",
        tool_name="echo",
        arguments={"text": "hello"},
        request_id=1,
    )
    await engine.on_tool_call(call1)

    call2 = ToolCall(
        session_id="s2",
        server_id="srv",
        tool_name="send_email",
        arguments={"to": "target@domain.com"},
        request_id=2,
    )
    await engine.on_tool_call(call2)

    result1 = ToolResult(
        session_id="s1",
        server_id="srv",
        tool_name="echo",
        request_id=1,
        content=[{"type": "text", "text": "hello"}],
    )
    await engine.on_tool_result(result1)

    await engine.close()

    rows = store.query_decisions(limit=10)
    assert len(rows) == 3

    tool_names = [r["tool_name"] for r in rows]
    assert tool_names.count("echo") == 2
    assert tool_names.count("send_email") == 1

    denied = next(r for r in rows if r["verdict"] == "DENY")
    assert denied["rule"] == "rule:block_email"
    assert "No emails allowed" in denied["reasons"]


def test_cli_logs_filters(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """CLI airlock logs filters by session, tool, verdict, since, and formats json."""
    db_path = tmp_path / "audit.db"
    store = AuditStore(db_path)

    # Create dummy entries with various timestamps
    now = time.time()
    two_hours_ago = now - 7200
    one_day_ago = now - 86400

    async def seed() -> None:
        # 1. ALLOW call 2 hours ago
        await store.log_decision(
            session_id="sess-A",
            server_id="srv1",
            direction="call",
            tool_name="echo",
            verdict="ALLOW",
            latency_ms=10.0,
            ts=two_hours_ago,
        )
        # 2. DENY call 1 day ago
        await store.log_decision(
            session_id="sess-B",
            server_id="srv1",
            direction="call",
            tool_name="send_email",
            verdict="DENY",
            rule="pol:deny",
            reasons=["Blocked by policy"],
            latency_ms=5.0,
            ts=one_day_ago,
        )
        # 3. REDACT result 10 mins ago
        await store.log_decision(
            session_id="sess-C",
            server_id="srv2",
            direction="result",
            tool_name="read_file",
            verdict="REDACT",
            latency_ms=15.0,
            ts=now - 600,
        )
        await store.close()

    import asyncio

    asyncio.run(seed())

    # Create airlock.yaml pointing to tmp_path
    config_file = tmp_path / "airlock.yaml"
    config_file.write_text(f"data_dir: {tmp_path}\n", encoding="utf-8")

    # 1. Test no filter (returns all 3 rows in table)
    res = runner.invoke(app, ["logs", "--config", str(config_file)])
    assert res.exit_code == 0
    assert "Airlock Decisions" in res.output
    assert "echo" in res.output
    assert "send_email" in res.output
    assert "read_file" in res.output

    # 2. Test --session filter
    res_sess = runner.invoke(app, ["logs", "--config", str(config_file), "--session", "sess-A"])
    assert res_sess.exit_code == 0
    assert "echo" in res_sess.output
    assert "send_email" not in res_sess.output

    # 3. Test --tool filter
    res_tool = runner.invoke(app, ["logs", "--config", str(config_file), "--tool", "send_email"])
    assert res_tool.exit_code == 0
    assert "send_email" in res_tool.output
    assert "read_file" not in res_tool.output

    # 4. Test --verdict filter
    res_verdict = runner.invoke(app, ["logs", "--config", str(config_file), "--verdict", "DENY"])
    assert res_verdict.exit_code == 0
    assert "DENY" in res_verdict.output
    assert "read_file" not in res_verdict.output

    # 5. Test --since filter (since 30m should include 10 mins ago, but exclude 2h and 1d ago)
    res_since = runner.invoke(app, ["logs", "--config", str(config_file), "--since", "30m"])
    assert res_since.exit_code == 0
    assert "read_file" in res_since.output
    assert "echo" not in res_since.output
    assert "send_email" not in res_since.output

    # 6. Test --json output
    res_json = runner.invoke(app, ["logs", "--config", str(config_file), "--json"])
    assert res_json.exit_code == 0
    parsed = json.loads(res_json.output)
    assert isinstance(parsed, list)
    assert len(parsed) == 3
    assert any(item["tool_name"] == "send_email" for item in parsed)


def test_parse_duration_to_seconds() -> None:
    """Duration parser parses units s, m, h, d, w correctly."""
    assert parse_duration_to_seconds("30s") == 30.0
    assert parse_duration_to_seconds("15m") == 900.0
    assert parse_duration_to_seconds("2h") == 7200.0
    assert parse_duration_to_seconds("1d") == 86400.0
    assert parse_duration_to_seconds("2w") == 1209600.0

    with pytest.raises(ValueError, match="Invalid duration format"):
        parse_duration_to_seconds("invalid")
