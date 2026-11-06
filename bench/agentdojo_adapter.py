"""AgentDojo pipeline element that routes tool calls and results through Airlock.

The decisions live in :class:`bench.gate.AirlockToolGate`; this module only
translates AgentDojo messages.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage, ChatToolResultMessage, text_content_block_from_string

from airlock.engine import Engine
from bench.gate import BLOCKED_CALL, BLOCKED_RESULT, AirlockToolGate
from bench.promptguard import PromptGuardResultCheck


class AirlockAgentDojoAdapter(BasePipelineElement):
    """Check tool calls before execution and tool results after execution.

    Place this element immediately before and after ``ToolsExecutor`` in a
    ``ToolsExecutionLoop``. DENY and ASK on a call return an error to the
    agent instead of running the tool; ``gate.stats`` counts both (ASK
    separately).
    """

    def __init__(self, engine: Engine, name: str = "airlock") -> None:
        self.gate = AirlockToolGate(engine)
        self.name = name

    @property
    def engine(self) -> Engine:
        return self.gate.engine

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
            current, blocked = self._check_calls(current, runtime)
            if blocked:
                args["_airlock_blocked_calls"] = blocked
        elif current and current[-1]["role"] == "tool":
            current = self._check_results(current)
        blocked = args.pop("_airlock_blocked_calls", [])
        if blocked:
            current = [*current, *blocked]
        return query, runtime, env, current, args

    def _check_calls(
        self, messages: list[ChatMessage], runtime: FunctionsRuntime
    ) -> tuple[list[ChatMessage], list[ChatToolResultMessage]]:
        assistant = messages[-1]
        tool_calls = assistant.get("tool_calls") if assistant["role"] == "assistant" else None
        if not tool_calls:
            return messages, []
        allowed: list[Any] = []
        blocked: list[ChatToolResultMessage] = []
        changed = False
        self.gate.register(
            [
                (function.name, function.description, function.parameters.model_json_schema())
                for function in runtime.functions.values()
            ]
        )
        for call in tool_calls:
            outcome = self.gate.check_call(call.function, dict(call.args))
            if not outcome.allowed:
                changed = True
                blocked.append(
                    ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string(BLOCKED_CALL)],
                        tool_call_id=call.id,
                        tool_call=call,
                        error="Airlock blocked tool call",
                    )
                )
            elif outcome.arguments != dict(call.args):
                changed = True
                allowed.append(call.model_copy(update={"args": outcome.arguments}))
            else:
                allowed.append(call)
        if not changed:
            return messages, []
        updated = [*messages[:-1], {**assistant, "tool_calls": allowed}]
        return updated, blocked

    def _check_results(self, messages: list[ChatMessage]) -> list[ChatMessage]:
        updated = list(messages)
        for index in range(len(updated) - 1, -1, -1):
            message = updated[index]
            if message["role"] != "tool":
                break
            text = "\n".join(
                block["content"] for block in message["content"] if block.get("type") == "text"
            )
            outcome = self.gate.check_result(
                message["tool_call"].function, text, message.get("error") is not None
            )
            if outcome.blocked:
                message["content"] = [text_content_block_from_string(BLOCKED_RESULT)]
                message["error"] = "Airlock blocked tool result"
            elif outcome.texts is not None:
                message["content"] = [text_content_block_from_string(t) for t in outcome.texts]
        return updated


__all__ = ["AirlockAgentDojoAdapter", "PromptGuardResultCheck"]
