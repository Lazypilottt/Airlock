"""Core engine for Airlock.

Transport-agnostic pure Python firewall engine.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import time
from collections.abc import Sequence
from typing import Any, Literal, Protocol, runtime_checkable

from airlock.approve import Answer, ApprovalOutcome, ApprovalRequest, Approver, NoApprover
from airlock.audit.secrets import mask_secrets
from airlock.audit.store import AuditStore
from airlock.config import AirlockConfig
from airlock.detect.cascade import CascadeResultCheck
from airlock.detect.rules import L1DescriptionCheck
from airlock.models import Decision, ToolCall, ToolDef, ToolResult, Verdict
from airlock.policy.actions import redact_arguments, withheld_result
from airlock.policy.schema import CompiledPolicy, PolicyEvent, PolicyMatch, TaintSignal
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
        # "Allow for this session" answers: (direction, server, tool, rule).
        self.approvals: set[tuple[str, str, str, str]] = set()


class PolicyProvider(Protocol):
    """Supplies the compiled policy (a :class:`~airlock.policy.PolicySource` reloads it)."""

    def current(self) -> CompiledPolicy: ...


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
    """Core firewall engine coordinating security checks across MCP events.

    Without a ``policy``, each check decides its own verdict and the most severe
    one wins. With a policy, checks that return ``Decision.evidence`` (taint
    hits, detector scores) only supply evidence, quarantined tools are
    reported to the policy instead of being denied outright, and the first
    matching policy rule decides. Verdicts from other checks, and the DENY a
    failing or timed-out check produces under ``fail_mode: closed``, still apply:
    the more severe of those and the policy verdict wins.
    """

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
        policy: PolicyProvider | None = None,
        approver: Approver | None = None,
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
        self.policy: PolicyProvider | None = policy
        self.approver: Approver = approver if approver is not None else NoApprover()

    @property
    def mode(self) -> str:
        """``enforce`` or ``shadow``; a policy's ``mode`` overrides the config."""
        if self.policy is not None:
            policy_mode = self.policy.current().policy.mode
            if policy_mode is not None:
                return policy_mode
        return self.config.mode

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

    async def _deny_by_registry(self, call: ToolCall, rule: str, reason: str) -> Decision:
        decision = self._finalize(Decision(verdict=Verdict.DENY, reasons=[reason], rule=rule))
        await self._log(call, "call", decision, latency_ms=0.0)
        return decision

    async def on_tool_call(self, call: ToolCall) -> Decision:
        """Evaluate an outbound tool call through registry status, checks and the policy."""
        session = self.get_or_create_session(call.session_id)
        session.call_count += 1

        # 1. Registry status. Pending and unknown tools are always denied;
        #    quarantine is evidence for the policy when there is one.
        quarantine_reason: str | None = None
        tool_record = self.registry.get_tool(call.server_id, call.tool_name)
        if tool_record is not None:
            status = tool_record["status"]
            if status == "quarantined":
                quarantine_reason = (
                    f"Tool '{call.tool_name}' on server '{call.server_id}' is quarantined: "
                    f"{tool_record.get('status_reason') or 'definition hash changed'}"
                )
                if self.policy is None:
                    return await self._deny_by_registry(
                        call, "registry:quarantined", quarantine_reason
                    )
            elif status == "pending":
                return await self._deny_by_registry(
                    call,
                    "registry:pending",
                    f"Tool '{call.tool_name}' on server '{call.server_id}' is pending approval",
                )
        elif self.registry.is_server_known(call.server_id):
            return await self._deny_by_registry(
                call,
                "registry:unknown",
                f"Tool '{call.tool_name}' is not registered on server '{call.server_id}'",
            )

        # 2. Checks, then the policy.
        decision, evidence = await self._run_checks(self._tool_call_checks, call, session)
        if self.policy is not None:
            start = time.perf_counter()
            decision = self._apply_policy(
                "call", call, session, decision, evidence, quarantine_reason
            )
            decision.latency_ms += (time.perf_counter() - start) * 1000.0
        decision = self._finalize(decision)
        await self._log(call, "call", decision, latency_ms=decision.latency_ms)
        return decision

    async def on_tool_result(self, result: ToolResult) -> Decision:
        """Evaluate an inbound tool execution result through checks and the policy."""
        session = self.get_or_create_session(result.session_id)
        decision, evidence = await self._run_checks(self._tool_result_checks, result, session)
        if self.policy is not None:
            start = time.perf_counter()
            decision = self._apply_policy("result", result, session, decision, evidence, None)
            decision.latency_ms += (time.perf_counter() - start) * 1000.0
        decision = self._finalize(decision)
        await self._log(result, "result", decision, latency_ms=decision.latency_ms)
        return decision

    async def resolve_ask(self, event: ToolCall | ToolResult, decision: Decision) -> Decision:
        """Put an ASK in front of a human and return the final ALLOW or DENY.

        "Allow for this session" answers are remembered, so the same rule on
        the same tool does not ask again in this session. The answer is
        written to the audit log as its own row (rule ``approval:<rule>``).
        Any other verdict is returned unchanged.
        """
        if decision.verdict is not Verdict.ASK:
            return decision
        session = self.get_or_create_session(event.session_id)
        direction: Literal["call", "result"] = "call" if isinstance(event, ToolCall) else "result"
        rule = decision.rule or "ask"
        request = ApprovalRequest(
            direction=direction,
            server=event.server_id,
            tool=event.tool_name,
            rule=rule,
            reasons=tuple(decision.reasons),
            arguments=self._preview(event, decision),
        )
        try:
            outcome = await self.approver.request(request)
        except Exception as exc:
            outcome = ApprovalOutcome(
                Answer.UNAVAILABLE,
                f"asking for approval failed ({type(exc).__name__}); treated as deny",
            )
        if outcome.answer is Answer.ALLOW_SESSION:
            session.approvals.add((direction, event.server_id, event.tool_name, rule))
        allowed = outcome.answer.allowed
        final = Decision(
            verdict=Verdict.ALLOW if allowed else Verdict.DENY,
            reasons=[outcome.detail, *decision.reasons],
            rule=f"approval:{rule}",
            scores=decision.scores,
            modified_payload=None if allowed else decision.evidence.get("blocked_payload"),
        )
        await self._log(event, direction, final, latency_ms=0.0)
        return final

    # -- Policy ---------------------------------------------------------------

    def _apply_policy(
        self,
        direction: Literal["call", "result"],
        event: ToolCall | ToolResult,
        session: Session,
        checks: Decision,
        evidence: dict[str, Any],
        quarantine_reason: str | None,
    ) -> Decision:
        assert self.policy is not None
        compiled = self.policy.current()
        labels = self.labels_for(event.server_id, event.tool_name)
        taint_items: list[dict[str, str]] = evidence.get("taint", [])
        score = evidence.get("score")
        policy_event = PolicyEvent(
            direction=direction,
            server=event.server_id,
            tool=event.tool_name,
            labels=frozenset(label.value for label in labels.labels),
            arguments=event.arguments if isinstance(event, ToolCall) else None,
            taint=tuple(
                TaintSignal(item["path"], item["label"])  # type: ignore[arg-type]
                for item in taint_items
            ),
            score=float(score) if score is not None else None,
            redact_above=float(evidence.get("redact_above", self.config.redact_above)),
            block_above=float(evidence.get("block_above", self.config.block_above)),
            quarantined=quarantine_reason is not None,
        )
        match = compiled.evaluate(policy_event)
        verdict = Verdict(match.verdict.upper())
        rule = match.rule_name if match.rule is not None else "policy:default"
        reasons = self._policy_reasons(match, taint_items, evidence, quarantine_reason)

        payload: Any | None = None
        if verdict is Verdict.REDACT:
            if direction == "call":
                assert isinstance(event, ToolCall)
                payload = redact_arguments(event.arguments, self._redact_paths(match))
            else:
                payload = evidence.get("redacted_payload") or withheld_result(rule)
        elif verdict is Verdict.DENY and direction == "result":
            payload = evidence.get("blocked_payload")

        ask_key = (direction, event.server_id, event.tool_name, rule)
        if verdict is Verdict.ASK and ask_key in session.approvals:
            verdict = Verdict.ALLOW
            reasons = [f"allowed for this session at the terminal earlier (rule `{rule}`)"]

        policy_decision = Decision(
            verdict=verdict,
            reasons=reasons,
            rule=rule,
            scores=checks.scores,
            modified_payload=payload,
            latency_ms=checks.latency_ms,
            evidence={"blocked_payload": evidence.get("blocked_payload"), "taint": taint_items},
        )
        if VERDICT_SEVERITY[checks.verdict] > VERDICT_SEVERITY[verdict]:
            # Another check (or a failing check under fail_mode: closed) is stricter.
            checks.reasons = checks.reasons + [r for r in reasons if r not in checks.reasons]
            return checks
        for reason in checks.reasons:
            if reason not in policy_decision.reasons:
                policy_decision.reasons.append(reason)
        return policy_decision

    @staticmethod
    def _policy_reasons(
        match: PolicyMatch,
        taint_items: list[dict[str, str]],
        evidence: dict[str, Any],
        quarantine_reason: str | None,
    ) -> list[str]:
        reasons: list[str] = []
        if match.message:
            reasons.append(match.message)
        rule = match.rule
        if rule is None:
            if match.verdict == "deny":
                reasons.append("No policy rule matched and the policy default is deny")
            return reasons
        if match.taint:
            wanted = {(signal.arg_path, signal.label) for signal in match.taint}
            shown = [
                item["reason"] for item in taint_items if (item["path"], item["label"]) in wanted
            ]
            reasons.extend(shown[:5])
        if rule.when.quarantined and quarantine_reason:
            reasons.append(quarantine_reason)
        if rule.when.result_score_above is not None:
            reasons.extend(str(reason) for reason in evidence.get("reasons", []))
        return reasons

    @staticmethod
    def _redact_paths(match: PolicyMatch) -> list[str]:
        if match.taint:
            return [signal.arg_path for signal in match.taint]
        if match.rule is not None and match.rule.when.arg is not None:
            return [match.rule.when.arg.path]
        return ["*"]

    def _preview(self, event: ToolCall | ToolResult, decision: Decision) -> str:
        """Masked arguments (or result text) to show a human; secret-tainted arguments hidden."""
        if isinstance(event, ToolCall):
            secret_paths = [
                item["path"]
                for item in decision.evidence.get("taint", [])
                if item["label"] == "secret"
            ]
            arguments = (
                redact_arguments(event.arguments, secret_paths) if secret_paths else event.arguments
            )
            text = json.dumps(arguments, ensure_ascii=False, default=str)
        else:
            text = " ".join(
                str(item.get("text", "")) for item in event.content if isinstance(item, dict)
            )
        return mask_secrets(text)[:2000]

    # -- Internals ------------------------------------------------------------

    def _finalize(self, decision: Decision) -> Decision:
        """Apply shadow mode: log what would have happened, let everything through."""
        if self.mode == "shadow" and decision.verdict is not Verdict.ALLOW:
            decision.would_have = decision.verdict
            decision.verdict = Verdict.ALLOW
            decision.modified_payload = None
        elif self.mode == "shadow":
            decision.would_have = Verdict.ALLOW
            decision.modified_payload = None
        return decision

    async def _log(
        self,
        event: ToolCall | ToolResult,
        direction: str,
        decision: Decision,
        latency_ms: float,
    ) -> None:
        if not self.audit_store:
            return
        if isinstance(event, ToolCall):
            args: Any = event.arguments
            result: Any = None
        else:
            args = None
            result = (
                decision.modified_payload
                if decision.verdict == Verdict.REDACT and decision.modified_payload is not None
                else event.content
            )
        await self.audit_store.log_decision(
            session_id=event.session_id,
            server_id=event.server_id,
            direction=direction,
            tool_name=event.tool_name,
            verdict=decision.verdict.value,
            would_have=decision.would_have.value if decision.would_have else None,
            rule=decision.rule,
            reasons=decision.reasons,
            scores=decision.scores,
            latency_ms=latency_ms,
            args=args,
            result=result,
        )

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
    ) -> tuple[Decision, dict[str, Any]]:
        """Run ordered checks with timeout, exception isolation, and decision merging.

        Returns the merged decision (before shadow mode) and the merged evidence.
        With a policy, a check that returned evidence hands its verdict to the
        policy: its verdict, reasons, rule and payload are left out of the merge.
        """
        start_total = time.perf_counter()
        timeout_sec = self.config.check_timeout_ms / 1000.0

        combined_verdict = Verdict.ALLOW
        combined_reasons: list[str] = []
        combined_scores: dict[str, float] = {}
        combined_rule: str | None = None
        winning_redact_payload: Any | None = None
        winning_redact_rule: str | None = None
        evidence: dict[str, Any] = {}
        policy_active = self.policy is not None

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

            # Merge scores from check
            for k, v in decision.scores.items():
                if k not in combined_scores:
                    combined_scores[k] = v

            if decision.evidence:
                for key, value in decision.evidence.items():
                    if key == "taint":
                        evidence.setdefault("taint", []).extend(value)
                    else:
                        evidence.setdefault(key, value)
                if policy_active:
                    continue

            # Merge reasons preserving order without duplicate entries
            for reason in decision.reasons:
                if reason not in combined_reasons:
                    combined_reasons.append(reason)

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

        merged = Decision(
            verdict=combined_verdict,
            would_have=None,
            reasons=combined_reasons,
            rule=combined_rule,
            scores=combined_scores,
            modified_payload=final_payload,
            latency_ms=total_latency,
        )
        return merged, evidence


__all__ = [
    "VERDICT_SEVERITY",
    "Engine",
    "PolicyProvider",
    "Session",
    "ToolCallCheck",
    "ToolResultCheck",
    "ToolsListedCheck",
]
