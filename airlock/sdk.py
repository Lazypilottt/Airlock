"""Airlock for agents that call Python functions directly (no MCP).

.. code-block:: python

    from airlock.sdk import Airlock, AirlockBlocked

    firewall = Airlock()

    @firewall.tool(labels=["source_untrusted"])
    def fetch(url: str) -> str: ...

    @firewall.tool(labels=["sink"], args={"to": "destination", "body": "content"})
    def send_email(to: str, body: str) -> str: ...

    with firewall.session(user_prompt="Email bob@corp.example the summary"):
        page = fetch("https://example.com")          # recorded as untrusted
        send_email("bob@corp.example", "summary")   # trusted: the user asked for it

Every call runs ``Engine.on_tool_call`` before the function and
``Engine.on_tool_result`` after it, on the same engine ``airlock wrap`` uses
(:func:`airlock.engine_factory.build_engine`).

- DENY raises :class:`AirlockBlocked` (or returns an error string with
  ``on_deny="return"``, which suits agent frameworks that show tool errors to
  the model).
- REDACT runs the function with redacted arguments, or returns the redacted
  result.
- ASK calls ``approve`` (sync or async, gets an
  :class:`~airlock.approve.ApprovalRequest`, returns True to allow); without
  one, ASK is denied.

The engine runs on a private event loop in a background thread, so decorated
functions work the same from synchronous code and from inside ``asyncio``.
"""

from __future__ import annotations

import asyncio
import atexit
import contextvars
import functools
import inspect
import itertools
import json
import threading
import uuid
from collections.abc import Awaitable, Callable, Coroutine
from concurrent.futures import Future
from typing import Any, Literal, TypeVar, overload

from airlock.approve import Answer, ApprovalOutcome, ApprovalRequest, Approver, NoApprover
from airlock.config import AirlockConfig, ArgRoleName, LabelName, LabelOverride
from airlock.engine import Engine
from airlock.engine_factory import build_engine
from airlock.models import Decision, ToolCall, ToolDef, ToolResult, Verdict

F = TypeVar("F", bound=Callable[..., Any])
T = TypeVar("T")
ApproveCallback = Callable[[ApprovalRequest], "bool | Awaitable[bool]"]

_CURRENT: contextvars.ContextVar[FirewallSession | None] = contextvars.ContextVar(
    "airlock_session", default=None
)


class AirlockBlocked(Exception):
    """A tool call or result was blocked. ``reasons`` says why."""

    def __init__(self, tool: str, decision: Decision) -> None:
        self.tool = tool
        self.decision = decision
        self.reasons = list(decision.reasons)
        self.rule = decision.rule
        super().__init__(f"Blocked by Airlock: {tool}: {'; '.join(self.reasons) or decision.rule}")


class CallbackApprover:
    """Adapts a plain ``approve(request) -> bool`` callback to the :class:`Approver` protocol."""

    def __init__(self, callback: ApproveCallback) -> None:
        self.callback = callback

    async def request(self, request: ApprovalRequest) -> ApprovalOutcome:
        answer = self.callback(request)
        if inspect.isawaitable(answer):
            answer = await answer
        if answer:
            return ApprovalOutcome(Answer.ALLOW_ONCE, "approved by the application")
        return ApprovalOutcome(Answer.DENY, "denied by the application")


class _LoopThread:
    """A private event loop on a daemon thread; the engine lives here."""

    def __init__(self) -> None:
        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self.loop.run_forever, name="airlock-sdk", daemon=True
        )
        self._thread.start()

    def submit(self, coro: Coroutine[Any, Any, T]) -> Future[T]:
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

    def run(self, coro: Coroutine[Any, Any, T]) -> T:
        if threading.current_thread() is self._thread:
            raise RuntimeError("Airlock tools cannot be called from Airlock's own loop")
        return self.submit(coro).result()

    def stop(self) -> None:
        if self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)
            self._thread.join(timeout=5)


class FirewallSession:
    """A conversation: taint is tracked per session, and the user's own words are trusted."""

    def __init__(self, firewall: Airlock, session_id: str, user_prompt: str | None) -> None:
        self.firewall = firewall
        self.id = session_id
        if user_prompt:
            self.trust(user_prompt)

    def trust(self, text: str) -> None:
        """Treat values in ``text`` (addresses, URLs, ids) as the user's own: never tainted."""
        session = self.firewall.engine.get_or_create_session(self.id)
        session.trusted.add(text)

    def __enter__(self) -> FirewallSession:
        self._token = _CURRENT.set(self)
        return self

    def __exit__(self, *exc: object) -> None:
        _CURRENT.reset(self._token)

    async def __aenter__(self) -> FirewallSession:
        return self.__enter__()

    async def __aexit__(self, *exc: object) -> None:
        self.__exit__(*exc)


class Airlock:
    """The SDK firewall.

    Args:
        config: Airlock configuration (defaults, or a loaded ``airlock.yaml``).
        server: Name the tools are registered under (labels, policy, audit log).
        on_deny: ``"raise"`` (default) raises :class:`AirlockBlocked`;
            ``"return"`` returns ``"Blocked by Airlock: <reasons>"`` instead.
        approve: Callback for ASK verdicts; without one, ASK is denied.
        **engine_kwargs: Passed to :func:`~airlock.engine_factory.build_engine`.
    """

    def __init__(
        self,
        config: AirlockConfig | None = None,
        *,
        server: str = "sdk",
        on_deny: Literal["raise", "return"] = "raise",
        approve: ApproveCallback | None = None,
        **engine_kwargs: Any,
    ) -> None:
        cfg = config if config is not None else AirlockConfig()
        # Tools are defined in the application's own code: no first-use review.
        cfg = cfg.model_copy(update={"auto_approve_new_tools": True})
        approver: Approver = (
            CallbackApprover(approve)
            if approve is not None
            else NoApprover("approval required but no approve callback was given to Airlock()")
        )
        self.server = server
        self.on_deny = on_deny
        self._loop = _LoopThread()
        self.engine: Engine = build_engine(cfg, approver=approver, **engine_kwargs)
        self._pending: dict[str, ToolDef] = {}
        self._ids = itertools.count(1)
        self._default = FirewallSession(self, f"sdk-{uuid.uuid4()}", None)
        self._closed = False
        atexit.register(self.close)

    # -- sessions --

    def session(
        self, user_prompt: str | None = None, session_id: str | None = None
    ) -> FirewallSession:
        """A new session; values in ``user_prompt`` are trusted. Use it as a context manager."""
        return FirewallSession(self, session_id or f"sdk-{uuid.uuid4()}", user_prompt)

    @property
    def current_session(self) -> FirewallSession:
        return _CURRENT.get() or self._default

    # -- tools --

    @overload
    def tool(self, fn: F, /) -> F: ...

    @overload
    def tool(
        self,
        fn: None = None,
        /,
        *,
        name: str | None = None,
        labels: list[LabelName] | None = None,
        args: dict[str, ArgRoleName] | None = None,
        description: str | None = None,
    ) -> Callable[[F], F]: ...

    def tool(
        self,
        fn: F | None = None,
        /,
        *,
        name: str | None = None,
        labels: list[LabelName] | None = None,
        args: dict[str, ArgRoleName] | None = None,
        description: str | None = None,
    ) -> F | Callable[[F], F]:
        """Decorator: ``@firewall.tool`` or ``@firewall.tool(labels=[...], args={...})``."""

        def decorate(function: F) -> F:
            return self.wrap_tool(
                function, name=name, labels=labels, args=args, description=description
            )

        return decorate(fn) if fn is not None else decorate

    def wrap_tool(
        self,
        fn: F,
        *,
        name: str | None = None,
        labels: list[LabelName] | None = None,
        args: dict[str, ArgRoleName] | None = None,
        description: str | None = None,
    ) -> F:
        """Return ``fn`` guarded by Airlock; sync and async functions are both supported.

        ``labels`` and ``args`` work like a ``labels:`` entry in ``airlock.yaml``;
        without them, label packs and the name heuristic apply.
        """
        tool_name = name or fn.__name__
        signature = inspect.signature(fn)
        if labels is not None or args is not None:
            self.engine.label_resolver.user_entries.insert(
                0,
                LabelOverride(
                    server=self.server, tool=tool_name, labels=labels or [], args=args or {}
                ),
            )
        self._pending[tool_name] = ToolDef.model_validate(
            {
                "server_id": self.server,
                "name": tool_name,
                "description": description or inspect.getdoc(fn) or "",
                "inputSchema": _schema(signature),
            }
        )

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*call_args: Any, **call_kwargs: Any) -> Any:
                bound = _bind(signature, call_args, call_kwargs)
                session = self.current_session
                request_id = next(self._ids)
                before = await asyncio.wrap_future(
                    self._loop.submit(self._before(tool_name, bound.arguments, session, request_id))
                )
                if isinstance(before, str):
                    return before
                bound.arguments.update(before)
                value = await fn(*bound.args, **bound.kwargs)
                return await asyncio.wrap_future(
                    self._loop.submit(self._after(tool_name, value, session, request_id))
                )

            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(fn)
        def wrapper(*call_args: Any, **call_kwargs: Any) -> Any:
            bound = _bind(signature, call_args, call_kwargs)
            session = self.current_session
            request_id = next(self._ids)
            before = self._loop.run(self._before(tool_name, bound.arguments, session, request_id))
            if isinstance(before, str):
                return before
            bound.arguments.update(before)
            value = fn(*bound.args, **bound.kwargs)
            return self._loop.run(self._after(tool_name, value, session, request_id))

        return wrapper  # type: ignore[return-value]

    # -- engine side (runs on the private loop) --

    async def _register(self) -> None:
        if self._pending:
            tools, self._pending = list(self._pending.values()), {}
            await self.engine.on_tools_listed(self.server, tools)

    def _blocked(self, tool: str, decision: Decision) -> str:
        if self.on_deny == "return":
            return f"Blocked by Airlock: {'; '.join(decision.reasons) or decision.rule}"
        raise AirlockBlocked(tool, decision)

    async def _before(
        self, tool: str, arguments: dict[str, Any], session: FirewallSession, request_id: int
    ) -> dict[str, Any] | str:
        """Arguments to call with (possibly redacted), or the error string to return."""
        await self._register()
        call = ToolCall(
            session_id=session.id,
            server_id=self.server,
            tool_name=tool,
            arguments=dict(arguments),
            request_id=request_id,
        )
        decision = await self.engine.on_tool_call(call)
        if decision.verdict is Verdict.ASK:
            decision = await self.engine.resolve_ask(call, decision)
        if decision.verdict is Verdict.DENY:
            return self._blocked(tool, decision)
        if decision.verdict is Verdict.REDACT and isinstance(decision.modified_payload, dict):
            return decision.modified_payload
        return {}

    async def _after(self, tool: str, value: Any, session: FirewallSession, request_id: int) -> Any:
        text = value if isinstance(value, str) else json.dumps(value, default=str)
        structured = value if isinstance(value, dict) else None
        result = ToolResult(
            session_id=session.id,
            server_id=self.server,
            tool_name=tool,
            request_id=request_id,
            content=[{"type": "text", "text": text}],
            structured_content=structured,
        )
        decision = await self.engine.on_tool_result(result)
        if decision.verdict is Verdict.ASK:
            decision = await self.engine.resolve_ask(result, decision)
        if decision.verdict is Verdict.DENY:
            return self._blocked(tool, decision)
        if decision.verdict is Verdict.REDACT and isinstance(decision.modified_payload, dict):
            return _redacted_value(value, decision.modified_payload)
        return value

    # -- lifecycle --

    def close(self) -> None:
        """Flush the audit log and stop the background loop."""
        if self._closed:
            return
        self._closed = True
        try:
            self._loop.run(self.engine.close())
        finally:
            self._loop.stop()

    def __enter__(self) -> Airlock:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _schema(signature: inspect.Signature) -> dict[str, Any]:
    names = [
        name
        for name, parameter in signature.parameters.items()
        if parameter.kind not in (parameter.VAR_POSITIONAL, parameter.VAR_KEYWORD)
    ]
    return {"type": "object", "properties": {name: {} for name in names}}


def _bind(signature: inspect.Signature, args: tuple[Any, ...], kwargs: dict[str, Any]) -> Any:
    bound = signature.bind(*args, **kwargs)
    bound.apply_defaults()
    return bound


def _redacted_value(original: Any, payload: dict[str, Any]) -> Any:
    if isinstance(original, dict) and isinstance(payload.get("structuredContent"), dict):
        return payload["structuredContent"]
    texts = [
        str(item.get("text", ""))
        for item in payload.get("content", [])
        if isinstance(item, dict) and item.get("type") == "text"
    ]
    text = "\n".join(texts)
    if isinstance(original, str):
        return text
    try:
        return json.loads(text)
    except ValueError:
        return text


__all__ = ["Airlock", "AirlockBlocked", "CallbackApprover", "FirewallSession"]
