"""The benchmark's Airlock gate, independent of AgentDojo's types.

``bench/agentdojo_adapter.py`` translates AgentDojo messages into these calls,
so everything Airlock decides during a benchmark can be tested without
installing AgentDojo.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from airlock.engine import Engine
from airlock.models import ToolCall, ToolDef, ToolResult, Verdict

SERVER = "agentdojo"
SESSION = "agentdojo"
BLOCKED_CALL = "Airlock blocked this tool call. You can continue with another request."
BLOCKED_RESULT = "Airlock blocked this tool result. You can continue with another request."


def run_sync(coro: Any) -> Any:
    """Run an Airlock coroutine from AgentDojo's synchronous pipeline."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    raise RuntimeError("AgentDojo pipeline query cannot run inside an active asyncio loop")


@dataclass
class GateStats:
    """What Airlock did during a run. ASK counts as a block and is also counted on its own."""

    calls: int = 0
    calls_denied: int = 0
    calls_asked: int = 0
    calls_redacted: int = 0
    results: int = 0
    results_denied: int = 0
    results_redacted: int = 0
    rules: dict[str, int] = field(default_factory=dict)

    def note(self, rule: str | None) -> None:
        if rule:
            self.rules[rule] = self.rules.get(rule, 0) + 1

    def as_dict(self) -> dict[str, Any]:
        return {
            "calls": self.calls,
            "calls_denied": self.calls_denied,
            "calls_asked": self.calls_asked,
            "calls_redacted": self.calls_redacted,
            "results": self.results,
            "results_denied": self.results_denied,
            "results_redacted": self.results_redacted,
            "rules": dict(sorted(self.rules.items(), key=lambda item: -item[1])),
        }


@dataclass(frozen=True)
class CallOutcome:
    allowed: bool
    verdict: Verdict
    arguments: dict[str, Any]
    message: str = ""


@dataclass(frozen=True)
class ResultOutcome:
    blocked: bool
    texts: list[str] | None = None  # replacement text blocks, when redacted


class AirlockToolGate:
    """Check AgentDojo tool calls before they run and their results after.

    In a benchmark nobody answers approvals, so ASK blocks the call like DENY
    (and is counted separately). REDACT on a call runs it with the redacted
    arguments.
    """

    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self.stats = GateStats()
        self._request_id = 0
        self._registered = False

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def register(self, tools: list[tuple[str, str, dict[str, Any]]]) -> None:
        """List the whole toolset once, like an MCP ``tools/list``, so it is pinned and labelled.

        All tools go in one listing: listing them one at a time would make
        every tool after the first a "new tool on a known server", pending
        approval, and so denied.
        """
        if self._registered:
            return
        self._registered = True
        defs = [
            ToolDef.model_validate(
                {
                    "server_id": SERVER,
                    "name": name,
                    "description": description,
                    "inputSchema": schema,
                }
            )
            for name, description, schema in tools
        ]
        run_sync(self.engine.on_tools_listed(SERVER, defs))

    def check_call(self, name: str, arguments: dict[str, Any]) -> CallOutcome:
        self.stats.calls += 1
        decision = run_sync(
            self.engine.on_tool_call(
                ToolCall(
                    session_id=SESSION,
                    server_id=SERVER,
                    tool_name=name,
                    arguments=arguments,
                    request_id=self._next_id(),
                )
            )
        )
        if decision.verdict in {Verdict.DENY, Verdict.ASK}:
            if decision.verdict is Verdict.ASK:
                self.stats.calls_asked += 1
            else:
                self.stats.calls_denied += 1
            self.stats.note(decision.rule)
            return CallOutcome(False, decision.verdict, arguments, BLOCKED_CALL)
        if decision.verdict is Verdict.REDACT and isinstance(decision.modified_payload, dict):
            self.stats.calls_redacted += 1
            self.stats.note(decision.rule)
            return CallOutcome(True, decision.verdict, decision.modified_payload)
        return CallOutcome(True, decision.verdict, arguments)

    def check_result(self, name: str, text: str, is_error: bool) -> ResultOutcome:
        self.stats.results += 1
        decision = run_sync(
            self.engine.on_tool_result(
                ToolResult(
                    session_id=SESSION,
                    server_id=SERVER,
                    tool_name=name,
                    request_id=self._next_id(),
                    content=[{"type": "text", "text": text}],
                    is_error=is_error,
                )
            )
        )
        if decision.verdict in {Verdict.DENY, Verdict.ASK}:
            self.stats.results_denied += 1
            self.stats.note(decision.rule)
            return ResultOutcome(True)
        payload = decision.modified_payload
        if decision.verdict is Verdict.REDACT and isinstance(payload, dict):
            self.stats.results_redacted += 1
            self.stats.note(decision.rule)
            content = payload.get("content")
            if isinstance(content, list):
                texts = [
                    str(item.get("text", ""))
                    for item in content
                    if isinstance(item, dict) and item.get("type") == "text"
                ]
                return ResultOutcome(False, texts)
        return ResultOutcome(False)


__all__ = [
    "BLOCKED_CALL",
    "BLOCKED_RESULT",
    "AirlockToolGate",
    "CallOutcome",
    "GateStats",
    "ResultOutcome",
    "run_sync",
]
