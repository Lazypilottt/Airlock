"""AgentDojo pipeline adapter for Airlock result and call checks."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from typing import Any

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage, ChatToolResultMessage, text_content_block_from_string

from airlock.engine import Engine
from airlock.models import Decision, ToolCall, ToolDef, ToolResult, Verdict


def _run(coro: Any) -> Any:
    """Run an Airlock coroutine from AgentDojo's synchronous pipeline."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    raise RuntimeError("AgentDojo pipeline query cannot run inside an active asyncio loop")


class AirlockAgentDojoAdapter(BasePipelineElement):
    """Check tool calls before execution and tool results after execution.

    Place this element immediately before and after ``ToolsExecutor`` in a
    ``ToolsExecutionLoop``.
    """

    def __init__(self, engine: Engine, name: str = "airlock-detect") -> None:
        self.engine = engine
        self.name = name
        self._request_id = 0

    def _next_request_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env | None = None,
        messages: Sequence[ChatMessage] = (),
        extra_args: dict[str, Any] | None = None,
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict[str, Any]]:
        args = dict(extra_args or {})
        env = env or EmptyEnv()
        current = list(messages)
        if current and current[-1]["role"] == "assistant":
            current, blocked = self._check_calls(current, runtime, env)
            if blocked:
                args["_airlock_blocked_calls"] = blocked
        elif current and current[-1]["role"] == "tool":
            current = self._check_results(current, env)
        blocked = args.pop("_airlock_blocked_calls", [])
        if blocked:
            current = [*current, *blocked]
        return query, runtime, env, current, args

    def _check_calls(
        self, messages: list[ChatMessage], runtime: FunctionsRuntime, env: Env
    ) -> tuple[list[ChatMessage], list[ChatToolResultMessage]]:
        del env
        assistant = messages[-1]
        tool_calls = assistant.get("tool_calls") if assistant["role"] == "assistant" else None
        if not tool_calls:
            return messages, []
        allowed: list[Any] = []
        blocked: list[ChatToolResultMessage] = []
        for call in tool_calls:
            function = runtime.functions.get(call.function)
            if (
                function is not None
                and self.engine.registry.get_tool("agentdojo", call.function) is None
            ):
                _run(
                    self.engine.on_tools_listed(
                        "agentdojo",
                        [
                            ToolDef(
                                server_id="agentdojo",
                                name=function.name,
                                description=function.description,
                                input_schema=function.parameters.model_json_schema(),
                            )
                        ],
                    )
                )
            decision = _run(
                self.engine.on_tool_call(
                    ToolCall(
                        session_id="agentdojo",
                        server_id="agentdojo",
                        tool_name=call.function,
                        arguments=dict(call.args),
                        request_id=self._next_request_id(),
                    )
                )
            )
            if decision.verdict in {Verdict.DENY, Verdict.ASK}:
                blocked.append(
                    ChatToolResultMessage(
                        role="tool",
                        content=[
                            text_content_block_from_string(
                                "Airlock blocked this tool call. "
                                "You can continue with another request."
                            )
                        ],
                        tool_call_id=call.id,
                        tool_call=call,
                        error="Airlock blocked tool call",
                    )
                )
            else:
                allowed.append(call)
        if not blocked:
            return messages, []
        updated = [*messages[:-1], {**assistant, "tool_calls": allowed}]
        return updated, blocked

    def _check_results(self, messages: list[ChatMessage], env: Env) -> list[ChatMessage]:
        del env
        updated = list(messages)
        for index in range(len(updated) - 1, -1, -1):
            message = updated[index]
            if message["role"] != "tool":
                break
            text = "\n".join(
                block["content"] for block in message["content"] if block.get("type") == "text"
            )
            call = message["tool_call"]
            decision = _run(
                self.engine.on_tool_result(
                    ToolResult(
                        session_id="agentdojo",
                        server_id="agentdojo",
                        tool_name=call.function,
                        request_id=self._next_request_id(),
                        content=[{"type": "text", "text": text}],
                        is_error=message.get("error") is not None,
                    )
                )
            )
            if decision.verdict == Verdict.DENY:
                message["content"] = [
                    text_content_block_from_string(
                        "Airlock blocked this tool result. You can continue with another request."
                    )
                ]
                message["error"] = "Airlock blocked tool result"
            elif decision.modified_payload is not None:
                payload = decision.modified_payload
                if isinstance(payload, dict) and isinstance(payload.get("content"), list):
                    message["content"] = [
                        text_content_block_from_string(str(item.get("text", "")))
                        for item in payload["content"]
                        if isinstance(item, dict) and item.get("type") == "text"
                    ]
        return updated


class PromptGuardResultCheck:
    """AgentDojo-compatible result check using only Prompt Guard 2."""

    name = "promptguard"

    def __init__(self, classifier: Any, block_threshold: float = 0.85) -> None:
        self.classifier = classifier
        self.block_threshold = block_threshold

    async def check(self, result: ToolResult, session: object) -> Decision:
        del session
        scores = [
            self.classifier.score(item["text"])[0]
            for item in result.content
            if isinstance(item.get("text"), str)
        ]
        score = max(scores, default=0.0)
        if score >= self.block_threshold:
            return Decision(
                verdict=Verdict.DENY,
                rule="promptguard:block",
                reasons=["Prompt Guard classified this tool result as malicious."],
                scores={"promptguard.score": score},
            )
        return Decision(verdict=Verdict.ALLOW, scores={"promptguard.score": score})


__all__ = ["AirlockAgentDojoAdapter", "PromptGuardResultCheck"]
