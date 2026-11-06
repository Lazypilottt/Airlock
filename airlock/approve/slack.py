"""Ask for approval in a Slack channel, over Socket Mode (no public URL needed).

Built from Slack's current docs (Socket Mode with the Python SDK; the
``block_actions`` payload): the connection uses an app-level token
(``xapp-``, scope ``connections:write``), messages use the bot token
(``xoxb-``). A button click arrives as an ``interactive`` request whose
payload is ``block_actions``; it is acknowledged with its ``envelope_id``
right away (Slack expects that within 3 seconds), then matched to the waiting
approval by the button's ``value``.

Everything shown in Slack is untrusted text, so ``&``, ``<`` and ``>`` are
escaped: a tool argument cannot ping ``@channel`` or render a fake link.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol

from airlock.approve import Answer, ApprovalOutcome, ApprovalRequest

APPROVE = "airlock_approve"
DENY = "airlock_deny"
ActionHandler = Callable[[dict[str, Any]], Coroutine[Any, Any, None]]


class SlackTransport(Protocol):
    """What the approver needs from Slack; tests pass a fake."""

    async def start(self, on_action: ActionHandler) -> None: ...

    async def post_message(
        self, channel: str, text: str, blocks: list[dict[str, Any]]
    ) -> tuple[str, str]:
        """Post; return ``(channel id, message ts)`` (``chat.update`` needs the id)."""
        ...

    async def update_message(
        self, channel: str, ts: str, text: str, blocks: list[dict[str, Any]]
    ) -> None: ...


def escape(text: str, limit: int = 500) -> str:
    """Slack mrkdwn escaping, plus a length limit."""
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return text if len(text) <= limit else text[: limit - 1] + "…"


@dataclass(frozen=True)
class SlackAnswer:
    approved: bool
    user_id: str
    user_name: str
    at: str


class SlackApprover:
    """Approver that posts Approve/Deny buttons to ``channel`` and waits.

    Args:
        transport: The Slack connection (:class:`SocketModeTransport` for real).
        channel: Channel id (or name) to post in.
        timeout: Seconds to wait; no answer denies.
        allowed_users: If set, only these Slack user ids can answer; clicks from
            anyone else are ignored (the request keeps waiting).
    """

    def __init__(
        self,
        transport: SlackTransport,
        channel: str,
        timeout: float = 300.0,
        allowed_users: list[str] | None = None,
    ) -> None:
        self.transport = transport
        self.channel = channel
        self.timeout = timeout
        self.allowed_users = set(allowed_users or [])
        self._waiting: dict[str, asyncio.Future[SlackAnswer]] = {}
        self._started = False

    async def _ensure_started(self) -> None:
        if not self._started:
            await self.transport.start(self.handle_action)
            self._started = True

    def blocks(self, request: ApprovalRequest, approval_id: str) -> list[dict[str, Any]]:
        what = "outgoing call" if request.direction == "call" else "tool result"
        reasons = "\n".join(f"• {escape(reason, 300)}" for reason in request.reasons[:5])
        fields = (
            f"*Tool:* `{escape(request.server, 80)}.{escape(request.tool, 80)}` ({what})\n"
            f"*Rule:* `{escape(request.rule, 80)}`"
        )
        blocks: list[dict[str, Any]] = [
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*Airlock needs your approval*"},
            },
            {"type": "section", "text": {"type": "mrkdwn", "text": fields}},
        ]
        if reasons:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": reasons}})
        if request.arguments:
            blocks.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"```{escape(request.arguments, 600)}```"},
                }
            )
        blocks.append(
            {
                "type": "actions",
                "block_id": f"airlock:{approval_id}",
                "elements": [
                    {
                        "type": "button",
                        "action_id": APPROVE,
                        "style": "primary",
                        "text": {"type": "plain_text", "text": "Approve"},
                        "value": approval_id,
                    },
                    {
                        "type": "button",
                        "action_id": DENY,
                        "style": "danger",
                        "text": {"type": "plain_text", "text": "Deny"},
                        "value": approval_id,
                    },
                ],
            }
        )
        return blocks

    async def handle_action(self, payload: dict[str, Any]) -> None:
        """Feed a ``block_actions`` payload in; resolves the matching approval."""
        if payload.get("type") != "block_actions":
            return
        user = payload.get("user") or {}
        user_id = str(user.get("id", ""))
        if self.allowed_users and user_id not in self.allowed_users:
            return
        for action in payload.get("actions") or []:
            if action.get("action_id") not in {APPROVE, DENY}:
                continue
            future = self._waiting.get(str(action.get("value", "")))
            if future is None or future.done():
                continue
            future.set_result(
                SlackAnswer(
                    approved=action["action_id"] == APPROVE,
                    user_id=user_id,
                    user_name=str(user.get("username") or user.get("name") or user_id),
                    at=datetime.now(UTC).isoformat(timespec="seconds"),
                )
            )

    async def request(self, request: ApprovalRequest) -> ApprovalOutcome:
        try:
            await self._ensure_started()
            approval_id = uuid.uuid4().hex
            future: asyncio.Future[SlackAnswer] = asyncio.get_running_loop().create_future()
            self._waiting[approval_id] = future
            blocks = self.blocks(request, approval_id)
            summary = f"Airlock: approve {request.server}.{request.tool}?"
            channel_id, ts = await self.transport.post_message(self.channel, summary, blocks)
        except Exception as exc:
            return ApprovalOutcome(
                Answer.UNAVAILABLE,
                f"approval required but Slack is unreachable ({type(exc).__name__}); "
                "treated as deny",
            )
        try:
            answer = await asyncio.wait_for(future, timeout=self.timeout)
        except TimeoutError:
            await self._close(
                channel_id, ts, blocks, f"No answer within {self.timeout:g} s: denied."
            )
            return ApprovalOutcome(
                Answer.TIMEOUT, f"no answer in Slack within {self.timeout:g} s; denied"
            )
        finally:
            self._waiting.pop(approval_id, None)
        verb = "approved" if answer.approved else "denied"
        note = f"{verb.capitalize()} by <@{answer.user_id}> at {answer.at}."
        await self._close(channel_id, ts, blocks, note)
        return ApprovalOutcome(
            Answer.ALLOW_ONCE if answer.approved else Answer.DENY,
            f"{verb} in Slack by {answer.user_name} ({answer.user_id}) at {answer.at}",
        )

    async def _close(
        self, channel_id: str, ts: str, blocks: list[dict[str, Any]], note: str
    ) -> None:
        """Replace the buttons with the outcome so nobody clicks a stale request."""
        final = [block for block in blocks if block.get("type") != "actions"]
        final.append({"type": "context", "elements": [{"type": "mrkdwn", "text": note}]})
        try:
            await self.transport.update_message(channel_id, ts, note, final)
        except Exception:
            pass


class SocketModeTransport:
    """The real Slack connection: ``slack_sdk``'s built-in Socket Mode client.

    Install with the ``slack`` extra. The SDK's client runs its own thread; Web
    API calls go through ``asyncio.to_thread`` and button clicks are handed to
    the event loop that started the transport.
    """

    def __init__(self, bot_token: str, app_token: str) -> None:
        self.bot_token = bot_token
        self.app_token = app_token
        self._web: Any = None
        self._client: Any = None

    async def start(self, on_action: ActionHandler) -> None:
        try:
            from slack_sdk.socket_mode import SocketModeClient
            from slack_sdk.socket_mode.response import SocketModeResponse
            from slack_sdk.web import WebClient
        except ImportError as exc:  # pragma: no cover - depends on the optional extra
            raise RuntimeError(
                "Slack approvals need the slack extra: pip install 'airlock-mcp[slack]'"
            ) from exc
        loop = asyncio.get_running_loop()
        self._web = WebClient(token=self.bot_token)
        self._client = SocketModeClient(app_token=self.app_token, web_client=self._web)

        def listener(client: Any, req: Any) -> None:
            # Acknowledge everything at once; Slack expects it within 3 seconds.
            client.send_socket_mode_response(SocketModeResponse(envelope_id=req.envelope_id))
            if req.type == "interactive" and isinstance(req.payload, dict):
                asyncio.run_coroutine_threadsafe(on_action(req.payload), loop)

        self._client.socket_mode_request_listeners.append(listener)
        await asyncio.to_thread(self._client.connect)

    async def post_message(
        self, channel: str, text: str, blocks: list[dict[str, Any]]
    ) -> tuple[str, str]:
        response = await asyncio.to_thread(
            self._web.chat_postMessage, channel=channel, text=text, blocks=blocks
        )
        return str(response["channel"]), str(response["ts"])

    async def update_message(
        self, channel: str, ts: str, text: str, blocks: list[dict[str, Any]]
    ) -> None:
        await asyncio.to_thread(
            self._web.chat_update, channel=channel, ts=ts, text=text, blocks=blocks
        )


__all__ = [
    "APPROVE",
    "DENY",
    "SlackApprover",
    "SlackTransport",
    "SocketModeTransport",
    "escape",
]
