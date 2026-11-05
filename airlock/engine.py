"""Core engine for Airlock.

Transport-agnostic pure Python firewall engine.
"""

from __future__ import annotations

import asyncio
import inspect
import time
from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable

from airlock.config import AirlockConfig
from airlock.models import Decision, ToolCall, ToolDef, ToolResult, Verdict

VERDICT_SEVERITY: dict[Verdict, int] = {
    Verdict.ALLOW: 1,
    Verdict.REDACT: 2,
    Verdict.ASK: 3,
    Verdict.DENY: 4,
}


class Session:
    """Holds per-session state across tool calls and results."""

    def __init__(self, session_id: str) -> None:
        self.session_id: str = session_id
        self.state: dict[str, Any] = {}
        self.created_at: float = time.time()


@runtime_checkable
class ToolCallCheck(Protocol):
    """Protocol for checks evaluating outbound tool calls."""

    @property
    def name(self) -> str: ...

    async def check(self, call: ToolCall, session: Session) -> Decision: ...


@runtime_checkable
class ToolResultCheck(Protocol):
    """Protocol for checks evaluating inbound tool results."""

    @property
    def name(self) -> str: ...

    async def check(self, result: ToolResult, session: Session) -> Decision: ...


@runtime_checkable
class ToolsListedCheck(Protocol):
    """Protocol for checks inspecting tool definitions on discovery."""

    @property
    def name(self) -> str: ...

    async def check(
        self,
        server_id: str,
        tools: list[ToolDef],
        session: Session | None = None,
    ) -> list[ToolDef]: ...


class Engine:
    """Core firewall engine coordinating security checks across MCP events."""

    def __init__(
        self,
        config: AirlockConfig | None = None,
        tool_call_checks: Sequence[Any] | None = None,
        tool_result_checks: Sequence[Any] | None = None,
        tools_listed_checks: Sequence[Any] | None = None,
    ) -> None:
        self.config: AirlockConfig = config if config is not None else AirlockConfig()
        self.sessions: dict[str, Session] = {}
        self._tool_call_checks: list[Any] = list(tool_call_checks or [])
        self._tool_result_checks: list[Any] = list(tool_result_checks or [])
        self._tools_listed_checks: list[Any] = list(tools_listed_checks or [])

    def get_or_create_session(self, session_id: str) -> Session:
        """Retrieve existing session or instantiate a new one."""
        if session_id not in self.sessions:
            self.sessions[session_id] = Session(session_id)
        return self.sessions[session_id]

    def add_tool_call_check(self, check: Any) -> None:
        """Register a pluggable check for outbound tool calls."""
        self._tool_call_checks.append(check)

    def add_tool_result_check(self, check: Any) -> None:
        """Register a pluggable check for inbound tool results."""
        self._tool_result_checks.append(check)

    def add_tools_listed_check(self, check: Any) -> None:
        """Register a pluggable check for tool definitions."""
        self._tools_listed_checks.append(check)

    async def on_tools_listed(
        self,
        server_id: str,
        tools: Sequence[ToolDef | dict[str, Any]],
    ) -> list[ToolDef]:
        """Inspect and filter tools advertised by an MCP server."""
        normalized_tools: list[ToolDef] = []
        for item in tools:
            if isinstance(item, ToolDef):
                normalized_tools.append(item)
            elif isinstance(item, dict):
                data = dict(item)
                if "server_id" not in data:
                    data["server_id"] = server_id
                normalized_tools.append(ToolDef.model_validate(data))
            else:
                raise TypeError(f"Expected ToolDef or dict, got {type(item).__name__}")

        timeout_sec = self.config.check_timeout_ms / 1000.0
        current_tools = normalized_tools

        for check in self._tools_listed_checks:
            try:
                async with asyncio.timeout(timeout_sec):
                    if hasattr(check, "check") and callable(check.check):
                        res = check.check(server_id, current_tools)
                    else:
                        res = check(server_id, current_tools)
                    if inspect.isawaitable(res):
                        res = await res
                if isinstance(res, list):
                    current_tools = res
            except TimeoutError:
                if self.config.fail_mode == "open":
                    pass
                else:
                    return []
            except Exception:
                if self.config.fail_mode == "open":
                    pass
                else:
                    return []

        return current_tools

    async def on_tool_call(self, call: ToolCall) -> Decision:
        """Evaluate an outbound tool call through registered checks."""
        session = self.get_or_create_session(call.session_id)
        return await self._run_checks(self._tool_call_checks, call, session)

    async def on_tool_result(self, result: ToolResult) -> Decision:
        """Evaluate an inbound tool execution result through registered checks."""
        session = self.get_or_create_session(result.session_id)
        return await self._run_checks(self._tool_result_checks, result, session)

    async def _run_checks(
        self,
        checks: Sequence[Any],
        event: ToolCall | ToolResult,
        session: Session,
    ) -> Decision:
        """Run ordered checks with timeout, exception isolation, and decision merging."""
        start_total = time.perf_counter()
        timeout_sec = self.config.check_timeout_ms / 1000.0

        combined_verdict = Verdict.ALLOW
        combined_reasons: list[str] = []
        combined_scores: dict[str, float] = {}
        combined_rule: str | None = None
        winning_redact_payload: Any | None = None
        winning_redact_rule: str | None = None

        for check in checks:
            check_name = getattr(
                check,
                "name",
                getattr(check, "__name__", type(check).__name__),
            )
            check_start = time.perf_counter()
            try:
                async with asyncio.timeout(timeout_sec):
                    if hasattr(check, "check") and callable(check.check):
                        res = check.check(event, session)
                    else:
                        res = check(event, session)
                    if inspect.isawaitable(res):
                        decision = await res
                    else:
                        decision = res
                check_elapsed = (time.perf_counter() - check_start) * 1000.0
                combined_scores[f"latency.{check_name}"] = check_elapsed
            except TimeoutError:
                check_elapsed = (time.perf_counter() - check_start) * 1000.0
                combined_scores[f"latency.{check_name}"] = check_elapsed
                if self.config.fail_mode == "open":
                    decision = Decision(
                        verdict=Verdict.ALLOW,
                        reasons=[
                            f"Check '{check_name}' timed out after "
                            f"{self.config.check_timeout_ms}ms; fail-mode open applied"
                        ],
                    )
                else:
                    decision = Decision(
                        verdict=Verdict.DENY,
                        rule=f"timeout:{check_name}",
                        reasons=[
                            f"Check '{check_name}' timed out after "
                            f"{self.config.check_timeout_ms}ms; fail-mode closed applied"
                        ],
                    )
            except Exception as exc:
                check_elapsed = (time.perf_counter() - check_start) * 1000.0
                combined_scores[f"latency.{check_name}"] = check_elapsed
                if self.config.fail_mode == "open":
                    decision = Decision(
                        verdict=Verdict.ALLOW,
                        reasons=[
                            f"Check '{check_name}' failed "
                            f"({type(exc).__name__}: {exc}); fail-mode open applied"
                        ],
                    )
                else:
                    decision = Decision(
                        verdict=Verdict.DENY,
                        rule=f"error:{check_name}",
                        reasons=[
                            f"Check '{check_name}' failed "
                            f"({type(exc).__name__}: {exc}); fail-mode closed applied"
                        ],
                    )

            # Merge reasons preserving order without duplicate entries
            for reason in decision.reasons:
                if reason not in combined_reasons:
                    combined_reasons.append(reason)

            # Merge scores from check
            for k, v in decision.scores.items():
                if k not in combined_scores:
                    combined_scores[k] = v

            # Record winning REDACT payload
            if decision.verdict == Verdict.REDACT:
                if winning_redact_payload is None and decision.modified_payload is not None:
                    winning_redact_payload = decision.modified_payload
                    winning_redact_rule = decision.rule
                elif winning_redact_rule is None and decision.rule is not None:
                    winning_redact_rule = decision.rule

            # Combine decisions: DENY > ASK > REDACT > ALLOW
            if VERDICT_SEVERITY[decision.verdict] > VERDICT_SEVERITY[combined_verdict]:
                combined_verdict = decision.verdict
                combined_rule = decision.rule

        total_latency = (time.perf_counter() - start_total) * 1000.0

        if combined_verdict == Verdict.REDACT:
            final_payload = winning_redact_payload
            if combined_rule is None and winning_redact_rule is not None:
                combined_rule = winning_redact_rule
        else:
            final_payload = None

        real_decision = Decision(
            verdict=combined_verdict,
            would_have=None,
            reasons=combined_reasons,
            rule=combined_rule,
            scores=combined_scores,
            modified_payload=final_payload,
            latency_ms=total_latency,
        )

        if self.config.mode == "shadow":
            real_decision.would_have = combined_verdict
            real_decision.verdict = Verdict.ALLOW
            real_decision.modified_payload = None

        return real_decision


__all__ = [
    "VERDICT_SEVERITY",
    "Engine",
    "Session",
    "ToolCallCheck",
    "ToolResultCheck",
    "ToolsListedCheck",
]
