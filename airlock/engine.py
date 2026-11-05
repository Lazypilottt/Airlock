"""Core engine for Airlock.

Transport-agnostic pure Python firewall engine.
"""

from __future__ import annotations

import asyncio
import inspect
import time
from collections.abc import Sequence
from typing import Any, Protocol, runtime_checkable

from airlock.audit.store import AuditStore
from airlock.config import AirlockConfig
from airlock.detect.cascade import CascadeResultCheck
from airlock.detect.rules import L1DescriptionCheck
from airlock.models import Decision, ToolCall, ToolDef, ToolResult, Verdict
from airlock.registry.checks import DescriptionCheck, StubDescriptionCheck
from airlock.registry.labels import LabelResolver, ToolLabels
from airlock.registry.store import ToolRegistry
from airlock.taint.table import TaintTable
from airlock.taint.tracker import TrustedValues

VERDICT_SEVERITY: dict[Verdict, int] = {
    Verdict.ALLOW: 1,
    Verdict.REDACT: 2,
    Verdict.ASK: 3,
    Verdict.DENY: 4,
}


class Session:
    """Holds per-session state across tool calls and results."""

    def __init__(self, session_id: str, taint: TaintTable | None = None) -> None:
        self.session_id: str = session_id
        self.state: dict[str, Any] = {}
        self.created_at: float = time.time()
        # Number of tool calls seen so far; used to say "N calls ago" in taint reasons.
        self.call_count: int = 0
        self.taint: TaintTable = taint if taint is not None else TaintTable()
        # Values this session's user supplied themselves (SDK mode); never tainted.
        self.trusted: TrustedValues = TrustedValues()


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
        description_checks: Sequence[DescriptionCheck] | None = None,
        audit_store: AuditStore | None = None,
        registry: ToolRegistry | None = None,
        label_resolver: LabelResolver | None = None,
    ) -> None:
        self.config: AirlockConfig = config if config is not None else AirlockConfig()
        self.sessions: dict[str, Session] = {}
        self._tool_call_checks: list[Any] = list(tool_call_checks or [])
        self._tool_result_checks: list[Any] = (
            list(tool_result_checks)
            if tool_result_checks is not None
            else [CascadeResultCheck(self.config)]
        )
        self._tools_listed_checks: list[Any] = list(tools_listed_checks or [])
        self._description_checks: list[DescriptionCheck] = (
            list(description_checks)
            if description_checks is not None
            else [L1DescriptionCheck(), StubDescriptionCheck()]
        )
        self.audit_store: AuditStore | None = (
            audit_store
            if audit_store is not None
            else AuditStore(self.config.data_dir / "audit.db")
        )
        self.registry: ToolRegistry = (
            registry if registry is not None else ToolRegistry(self.config.data_dir / "registry.db")
        )
        self.label_resolver: LabelResolver = (
            label_resolver
            if label_resolver is not None
            else LabelResolver(user_entries=self.config.labels)
        )

    def labels_for(self, server_id: str, tool_name: str) -> ToolLabels:
        """Return a tool's stored labels.

        A tool that was never listed (the client called it without listing, or
        the server has not been seen) is resolved from its name alone, so packs,
        user overrides and the name heuristic still apply.
        """
        stored = self.registry.get_labels(server_id, tool_name)
        if stored is not None:
            return stored
        return self.label_resolver.resolve(
            server_id, ToolDef(server_id=server_id, name=tool_name, description="")
        )

    def get_or_create_session(self, session_id: str) -> Session:
        """Retrieve existing session or instantiate a new one."""
        if session_id not in self.sessions:
            taint = self.config.taint
            self.sessions[session_id] = Session(
                session_id,
                taint=TaintTable(
                    max_entries=taint.max_entries,
                    ttl_seconds=taint.ttl_seconds,
                    min_token_length=taint.min_token_length,
                    match_domains=taint.match_domains,
                ),
            )
        return self.sessions[session_id]

    def check_names(self) -> dict[str, list[str]]:
        """Names of the registered checks per hook, in the order they run."""

        def _names(checks: Sequence[Any]) -> list[str]:
            return [
                str(getattr(check, "name", getattr(check, "__name__", type(check).__name__)))
                for check in checks
            ]

        return {
            "tool_call": _names(self._tool_call_checks),
            "tool_result": _names(self._tool_result_checks),
            "tools_listed": _names(self._tools_listed_checks),
            "description": _names(self._description_checks),
        }

    def add_tool_call_check(self, check: Any) -> None:
        """Register a pluggable check for outbound tool calls."""
        self._tool_call_checks.append(check)

    def add_tool_result_check(self, check: Any) -> None:
        """Register a pluggable check for inbound tool results."""
        self._tool_result_checks.append(check)

    def add_tools_listed_check(self, check: Any) -> None:
        """Register a pluggable check for tool definitions."""
        self._tools_listed_checks.append(check)

    def add_description_check(self, check: DescriptionCheck) -> None:
        """Register a pluggable tool description check."""
        self._description_checks.append(check)

    async def on_tools_listed(
        self,
        server_id: str,
        tools: Sequence[ToolDef | dict[str, Any]],
    ) -> list[ToolDef]:
        """Inspect, pin hashes, quarantine rug-pulls, and filter tools for a server."""
        normalized_tools: list[ToolDef] = []
        for item in tools:
            try:
                if isinstance(item, ToolDef):
                    normalized_tools.append(item)
                elif isinstance(item, dict):
                    data = dict(item)
                    if "server_id" not in data:
                        data["server_id"] = server_id
                    normalized_tools.append(ToolDef.model_validate(data))
                else:
                    raise TypeError(f"Expected ToolDef or dict, got {type(item).__name__}")
            except Exception as exc:
                if self.config.fail_mode == "closed":
                    if self.audit_store:
                        await self.audit_store.log_decision(
                            session_id="discovery",
                            server_id=server_id,
                            direction="list",
                            tool_name=None,
                            verdict="DENY",
                            would_have=None,
                            rule="malformed_tool_definition",
                            reasons=[f"Malformed tool definition rejected: {type(exc).__name__}"],
                            scores={},
                            latency_ms=0.0,
                            args=None,
                            result=None,
                        )
                    return []
                continue

        # Update registry: TOFU, hash pinning, quarantine, description checking
        visible_tools, _diffs = await self.registry.process_server_tools(
            server_id=server_id,
            tools=normalized_tools,
            description_checks=self._description_checks,
            auto_approve_new_tools=self.config.auto_approve_new_tools,
            label_resolver=self.label_resolver,
        )

        timeout_sec = self.config.check_timeout_ms / 1000.0
        current_tools = visible_tools

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

        if self.audit_store:
            await self.audit_store.log_decision(
                session_id="discovery",
                server_id=server_id,
                direction="list",
                tool_name=None,
                verdict="ALLOW",
                would_have=None,
                rule=None,
                reasons=[],
                scores={},
                latency_ms=0.0,
                args=None,
                result=[t.name for t in current_tools],
            )

        return current_tools

    async def on_tool_call(self, call: ToolCall) -> Decision:
        """Evaluate an outbound tool call through registry status and registered checks."""
        session = self.get_or_create_session(call.session_id)
        session.call_count += 1

        # 1. Enforce Tool Registry status (quarantined/pending tools denied)
        tool_record = self.registry.get_tool(call.server_id, call.tool_name)
        if tool_record is not None:
            status = tool_record["status"]
            status_reason = tool_record.get("status_reason")
            if status == "quarantined":
                reason = (
                    f"Tool '{call.tool_name}' on server '{call.server_id}' is quarantined: "
                    f"{status_reason or 'definition hash changed'}"
                )
                denied_dec = Decision(
                    verdict=Verdict.DENY,
                    reasons=[reason],
                    rule="registry:quarantined",
                )
                if self.config.mode == "shadow":
                    denied_dec.would_have = Verdict.DENY
                    denied_dec.verdict = Verdict.ALLOW
                if self.audit_store:
                    await self.audit_store.log_decision(
                        session_id=call.session_id,
                        server_id=call.server_id,
                        direction="call",
                        tool_name=call.tool_name,
                        verdict=denied_dec.verdict.value,
                        would_have=(denied_dec.would_have.value if denied_dec.would_have else None),
                        rule=denied_dec.rule,
                        reasons=denied_dec.reasons,
                        scores=denied_dec.scores,
                        latency_ms=0.0,
                        args=call.arguments,
                    )
                return denied_dec

            elif status == "pending":
                reason = f"Tool '{call.tool_name}' on server '{call.server_id}' is pending approval"
                denied_dec = Decision(
                    verdict=Verdict.DENY,
                    reasons=[reason],
                    rule="registry:pending",
                )
                if self.config.mode == "shadow":
                    denied_dec.would_have = Verdict.DENY
                    denied_dec.verdict = Verdict.ALLOW
                if self.audit_store:
                    await self.audit_store.log_decision(
                        session_id=call.session_id,
                        server_id=call.server_id,
                        direction="call",
                        tool_name=call.tool_name,
                        verdict=denied_dec.verdict.value,
                        would_have=(denied_dec.would_have.value if denied_dec.would_have else None),
                        rule=denied_dec.rule,
                        reasons=denied_dec.reasons,
                        scores=denied_dec.scores,
                        latency_ms=0.0,
                        args=call.arguments,
                    )
                return denied_dec

        elif self.registry.is_server_known(call.server_id):
            reason = f"Tool '{call.tool_name}' is not registered on server '{call.server_id}'"
            denied_dec = Decision(
                verdict=Verdict.DENY,
                reasons=[reason],
                rule="registry:unknown",
            )
            if self.config.mode == "shadow":
                denied_dec.would_have = Verdict.DENY
                denied_dec.verdict = Verdict.ALLOW
            if self.audit_store:
                await self.audit_store.log_decision(
                    session_id=call.session_id,
                    server_id=call.server_id,
                    direction="call",
                    tool_name=call.tool_name,
                    verdict=denied_dec.verdict.value,
                    would_have=(denied_dec.would_have.value if denied_dec.would_have else None),
                    rule=denied_dec.rule,
                    reasons=denied_dec.reasons,
                    scores=denied_dec.scores,
                    latency_ms=0.0,
                    args=call.arguments,
                )
            return denied_dec

        # 2. Run pluggable tool call checks
        decision = await self._run_checks(self._tool_call_checks, call, session)
        if self.audit_store:
            await self.audit_store.log_decision(
                session_id=call.session_id,
                server_id=call.server_id,
                direction="call",
                tool_name=call.tool_name,
                verdict=decision.verdict.value,
                would_have=decision.would_have.value if decision.would_have else None,
                rule=decision.rule,
                reasons=decision.reasons,
                scores=decision.scores,
                latency_ms=decision.latency_ms,
                args=call.arguments,
                result=None,
            )
        return decision

    async def on_tool_result(self, result: ToolResult) -> Decision:
        """Evaluate an inbound tool execution result through registered checks."""
        session = self.get_or_create_session(result.session_id)
        decision = await self._run_checks(self._tool_result_checks, result, session)
        if self.audit_store:
            payload_to_log = (
                decision.modified_payload
                if decision.verdict == Verdict.REDACT and decision.modified_payload is not None
                else result.content
            )
            await self.audit_store.log_decision(
                session_id=result.session_id,
                server_id=result.server_id,
                direction="result",
                tool_name=result.tool_name,
                verdict=decision.verdict.value,
                would_have=decision.would_have.value if decision.would_have else None,
                rule=decision.rule,
                reasons=decision.reasons,
                scores=decision.scores,
                latency_ms=decision.latency_ms,
                args=None,
                result=payload_to_log,
            )
        return decision

    async def flush(self) -> None:
        """Flush pending audit store writes."""
        if self.audit_store:
            await self.audit_store.flush()

    async def close(self) -> None:
        """Flush and cleanly close engine resources and audit store."""
        if self.audit_store:
            await self.audit_store.close()

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
