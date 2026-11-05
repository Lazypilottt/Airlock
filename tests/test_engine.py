"""Tests for Airlock core engine and decision combination logic."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from airlock.config import AirlockConfig
from airlock.engine import Engine, Session
from airlock.models import Decision, ToolCall, ToolDef, ToolResult, Verdict


class DummyCallCheck:
    """Helper test check for ToolCall."""

    def __init__(
        self,
        name: str,
        verdict: Verdict = Verdict.ALLOW,
        reasons: list[str] | None = None,
        scores: dict[str, float] | None = None,
        modified_payload: Any | None = None,
        rule: str | None = None,
        delay_sec: float = 0.0,
        should_fail: bool = False,
    ) -> None:
        self.name = name
        self.verdict = verdict
        self.reasons = reasons or []
        self.scores = scores or {}
        self.modified_payload = modified_payload
        self.rule = rule
        self.delay_sec = delay_sec
        self.should_fail = should_fail

    async def check(self, call: ToolCall, session: Session) -> Decision:
        if self.delay_sec > 0:
            await asyncio.sleep(self.delay_sec)
        if self.should_fail:
            raise RuntimeError(f"Check {self.name} deliberate explosion")
        return Decision(
            verdict=self.verdict,
            reasons=list(self.reasons),
            scores=dict(self.scores),
            modified_payload=self.modified_payload,
            rule=self.rule,
        )


def make_call(session_id: str = "sess-1") -> ToolCall:
    return ToolCall(
        session_id=session_id,
        server_id="srv-1",
        tool_name="read_file",
        arguments={"path": "/etc/passwd"},
        request_id="req-1",
    )


def make_result(session_id: str = "sess-1") -> ToolResult:
    return ToolResult(
        session_id=session_id,
        server_id="srv-1",
        tool_name="read_file",
        request_id="req-1",
        content=[{"type": "text", "text": "root:x:0:0:root:/root:/bin/bash"}],
    )


@pytest.mark.asyncio
async def test_combination_order_deny_overrides_all() -> None:
    """DENY overrides ASK, REDACT, and ALLOW regardless of check order."""
    checks = [
        DummyCallCheck("allow_chk", Verdict.ALLOW, reasons=["looks okay"]),
        DummyCallCheck("redact_chk", Verdict.REDACT, reasons=["redacting"]),
        DummyCallCheck("ask_chk", Verdict.ASK, reasons=["asking human"]),
        DummyCallCheck("deny_chk", Verdict.DENY, reasons=["blocked by policy"], rule="pol:block"),
    ]
    engine = Engine(tool_call_checks=checks)
    decision = await engine.on_tool_call(make_call())

    assert decision.verdict == Verdict.DENY
    assert decision.rule == "pol:block"
    assert "blocked by policy" in decision.reasons
    assert "asking human" in decision.reasons
    assert "redacting" in decision.reasons
    assert decision.modified_payload is None


@pytest.mark.asyncio
async def test_combination_order_ask_overrides_redact_and_allow() -> None:
    """ASK overrides REDACT and ALLOW when no DENY is present."""
    checks = [
        DummyCallCheck("allow_chk", Verdict.ALLOW),
        DummyCallCheck("redact_chk", Verdict.REDACT, modified_payload={"redacted": True}),
        DummyCallCheck("ask_chk", Verdict.ASK, rule="human_approval_required"),
    ]
    engine = Engine(tool_call_checks=checks)
    decision = await engine.on_tool_call(make_call())

    assert decision.verdict == Verdict.ASK
    assert decision.rule == "human_approval_required"
    assert decision.modified_payload is None


@pytest.mark.asyncio
async def test_combination_order_redact_overrides_allow() -> None:
    """REDACT overrides ALLOW when no DENY or ASK is present."""
    checks = [
        DummyCallCheck("allow_chk1", Verdict.ALLOW),
        DummyCallCheck(
            "redact_chk",
            Verdict.REDACT,
            modified_payload={"sanitized": True},
            rule="redact:secret",
        ),
        DummyCallCheck("allow_chk2", Verdict.ALLOW),
    ]
    engine = Engine(tool_call_checks=checks)
    decision = await engine.on_tool_call(make_call())

    assert decision.verdict == Verdict.REDACT
    assert decision.rule == "redact:secret"
    assert decision.modified_payload == {"sanitized": True}


@pytest.mark.asyncio
async def test_redact_payload_selection_first_winning() -> None:
    """When multiple checks return REDACT, the first winning REDACT payload is preserved."""
    checks = [
        DummyCallCheck("redact1", Verdict.REDACT, modified_payload={"first": 1}),
        DummyCallCheck("redact2", Verdict.REDACT, modified_payload={"second": 2}),
    ]
    engine = Engine(tool_call_checks=checks)
    decision = await engine.on_tool_call(make_call())

    assert decision.verdict == Verdict.REDACT
    assert decision.modified_payload == {"first": 1}


@pytest.mark.asyncio
async def test_redact_payload_selection_skips_none() -> None:
    """A REDACT with payload is selected over an earlier REDACT with None payload."""
    checks = [
        DummyCallCheck("redact_none", Verdict.REDACT, modified_payload=None),
        DummyCallCheck("redact_valid", Verdict.REDACT, modified_payload={"payload": "valid"}),
    ]
    engine = Engine(tool_call_checks=checks)
    decision = await engine.on_tool_call(make_call())

    assert decision.verdict == Verdict.REDACT
    assert decision.modified_payload == {"payload": "valid"}


@pytest.mark.asyncio
async def test_shadow_mode_stores_real_decision_and_returns_allow() -> None:
    """In shadow mode, would-be blocking verdict is saved in would_have, and ALLOW is returned."""
    config = AirlockConfig(mode="shadow")
    checks = [
        DummyCallCheck("deny_chk", Verdict.DENY, reasons=["malicious input"], rule="rule:deny"),
    ]
    engine = Engine(config=config, tool_call_checks=checks)
    decision = await engine.on_tool_call(make_call())

    assert decision.verdict == Verdict.ALLOW
    assert decision.would_have == Verdict.DENY
    assert "malicious input" in decision.reasons
    assert decision.rule == "rule:deny"
    assert decision.modified_payload is None


@pytest.mark.asyncio
async def test_fail_mode_closed_on_exception() -> None:
    """When a check raises an exception under fail_mode=closed, decision is DENY."""
    config = AirlockConfig(fail_mode="closed")
    checks = [
        DummyCallCheck("exploding_chk", should_fail=True),
    ]
    engine = Engine(config=config, tool_call_checks=checks)
    decision = await engine.on_tool_call(make_call())

    assert decision.verdict == Verdict.DENY
    assert any("deliberate explosion" in r for r in decision.reasons)
    assert any("fail-mode closed applied" in r for r in decision.reasons)


@pytest.mark.asyncio
async def test_fail_mode_open_on_exception() -> None:
    """When a check raises an exception under fail_mode=open, decision is ALLOW with reason."""
    config = AirlockConfig(fail_mode="open")
    checks = [
        DummyCallCheck("exploding_chk", should_fail=True),
    ]
    engine = Engine(config=config, tool_call_checks=checks)
    decision = await engine.on_tool_call(make_call())

    assert decision.verdict == Verdict.ALLOW
    assert any("deliberate explosion" in r for r in decision.reasons)
    assert any("fail-mode open applied" in r for r in decision.reasons)


@pytest.mark.asyncio
async def test_fail_mode_closed_on_timeout() -> None:
    """When a check times out under fail_mode=closed, decision is DENY with reason."""
    config = AirlockConfig(fail_mode="closed", check_timeout_ms=50)
    checks = [
        DummyCallCheck("slow_chk", delay_sec=0.2),
    ]
    engine = Engine(config=config, tool_call_checks=checks)
    decision = await engine.on_tool_call(make_call())

    assert decision.verdict == Verdict.DENY
    assert any("timed out after 50ms" in r for r in decision.reasons)
    assert any("fail-mode closed applied" in r for r in decision.reasons)


@pytest.mark.asyncio
async def test_fail_mode_open_on_timeout() -> None:
    """When a check times out under fail_mode=open, decision is ALLOW with reason."""
    config = AirlockConfig(fail_mode="open", check_timeout_ms=50)
    checks = [
        DummyCallCheck("slow_chk", delay_sec=0.2),
    ]
    engine = Engine(config=config, tool_call_checks=checks)
    decision = await engine.on_tool_call(make_call())

    assert decision.verdict == Verdict.ALLOW
    assert any("timed out after 50ms" in r for r in decision.reasons)
    assert any("fail-mode open applied" in r for r in decision.reasons)


@pytest.mark.asyncio
async def test_latency_recorded_per_check_and_total() -> None:
    """Per-check latency is recorded under latency.<check> and total latency_ms > 0."""
    checks = [
        DummyCallCheck("check_alpha", delay_sec=0.01),
        DummyCallCheck("check_beta", delay_sec=0.01),
    ]
    engine = Engine(tool_call_checks=checks)
    decision = await engine.on_tool_call(make_call())

    assert "latency.check_alpha" in decision.scores
    assert decision.scores["latency.check_alpha"] >= 9.0
    assert "latency.check_beta" in decision.scores
    assert decision.scores["latency.check_beta"] >= 9.0
    assert decision.latency_ms >= 18.0


@pytest.mark.asyncio
async def test_session_state_preserved() -> None:
    """A Session object per session_id persists state across calls."""
    engine = Engine()
    call = make_call("session-persistent")
    session = engine.get_or_create_session("session-persistent")
    session.state["seen_count"] = 1

    await engine.on_tool_call(call)
    res_session = engine.get_or_create_session("session-persistent")
    assert res_session.state["seen_count"] == 1


@pytest.mark.asyncio
async def test_on_tool_result_checks() -> None:
    """Inbound tool execution results trigger tool_result_checks properly."""

    class ResultRedactor:
        name = "result_redactor"

        async def check(self, result: ToolResult, session: Session) -> Decision:
            return Decision(
                verdict=Verdict.REDACT,
                modified_payload=[{"type": "text", "text": "root:x:0:0:[REDACTED]"}],
            )

    engine = Engine(tool_result_checks=[ResultRedactor()])
    decision = await engine.on_tool_result(make_result())

    assert decision.verdict == Verdict.REDACT
    assert decision.modified_payload == [{"type": "text", "text": "root:x:0:0:[REDACTED]"}]


@pytest.mark.asyncio
async def test_on_tools_listed() -> None:
    """Tools listed by an MCP server are normalized and can be filtered by checks."""

    class ToolFilterCheck:
        name = "filter_bash"

        async def check(self, server_id: str, tools: list[ToolDef]) -> list[ToolDef]:
            return [t for t in tools if t.name != "bash"]

    engine = Engine(tools_listed_checks=[ToolFilterCheck()])
    raw_tools: list[ToolDef | dict[str, Any]] = [
        {"name": "read_file", "description": "Read file"},
        ToolDef(server_id="s1", name="bash", description="Execute bash"),
    ]
    processed = await engine.on_tools_listed("s1", raw_tools)

    assert len(processed) == 1
    assert processed[0].name == "read_file"
    assert processed[0].server_id == "s1"
