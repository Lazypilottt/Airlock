"""Deny any outbound call that carries a honeytoken."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING, Any, Protocol

from airlock.honeytokens.store import WatchedHoneytokens
from airlock.honeytokens.tokens import Honeytoken
from airlock.models import Decision, ToolCall, Verdict
from airlock.taint.normalize import views
from airlock.taint.tracker import walk_arguments

if TYPE_CHECKING:
    from airlock.engine import Session


class AlertSink(Protocol):
    async def log_alert(
        self,
        *,
        kind: str,
        severity: str,
        message: str,
        session_id: str | None = None,
        server_id: str | None = None,
        tool_name: str | None = None,
    ) -> None: ...


def shown(token: Honeytoken) -> str:
    """How a token appears in reasons: enough to recognise it, never the whole value."""
    return f"{token.needle[:6]}… (honeytoken {token.id})"


def _warn_loudly(lines: list[str]) -> None:
    bar = "!" * 72
    sys.stderr.write("\n".join(["", bar, *(f"!! {line}" for line in lines), bar, ""]) + "\n")
    sys.stderr.flush()


class HoneytokenCheck:
    """Call check: a honeytoken in any argument (plain, base64, hex or URL-encoded) is DENY.

    The verdict is not evidence for the policy: a honeytoken can only leave if
    someone planted it and something is exfiltrating it, so no rule can allow
    it. Every hit is also written to the audit log as a high-severity alert
    and printed to stderr.
    """

    name = "honeytoken"

    def __init__(self, tokens: WatchedHoneytokens, alerts: AlertSink | None = None) -> None:
        self.tokens = tokens
        self.alerts = alerts

    def scan(self, arguments: dict[str, Any]) -> list[tuple[str, Honeytoken, str]]:
        """``(argument path, token, how it was encoded)`` for every token found."""
        planted = self.tokens.tokens()
        if not planted:
            return []
        needles = [(token.needle.lower(), token) for token in planted]
        hits: list[tuple[str, Honeytoken, str]] = []
        seen: set[str] = set()
        for path, value in walk_arguments(arguments):
            for view in views(value):
                for needle, token in needles:
                    if token.id not in seen and needle in view.text:
                        seen.add(token.id)
                        hits.append((path, token, view.how))
        return hits

    async def check(self, call: ToolCall, session: Session) -> Decision:
        del session
        hits = self.scan(call.arguments)
        if not hits:
            return Decision(verdict=Verdict.ALLOW)
        reasons = [
            f"argument `{path}` contains {shown(token)}" + ("" if how == "plain" else f" ({how})")
            for path, token, how in hits
        ]
        message = (
            f"Honeytoken sent to {call.server_id}.{call.tool_name}: {'; '.join(reasons)}. "
            "A planted fake secret is being exfiltrated: an agent or tool on this machine "
            "is compromised or misbehaving."
        )
        _warn_loudly(
            [
                "AIRLOCK ALERT: HONEYTOKEN IN AN OUTGOING TOOL CALL (blocked)",
                f"tool: {call.server_id}.{call.tool_name}",
                *reasons,
                "Something tried to send a planted fake secret. Check `airlock logs`.",
            ]
        )
        if self.alerts is not None:
            await self.alerts.log_alert(
                kind="honeytoken",
                severity="high",
                message=message,
                session_id=call.session_id,
                server_id=call.server_id,
                tool_name=call.tool_name,
            )
        return Decision(
            verdict=Verdict.DENY,
            rule="honeytoken",
            reasons=["A planted honeytoken (fake secret) was about to be sent out.", *reasons],
            scores={"honeytoken.hits": float(len(hits))},
        )


__all__ = ["AlertSink", "HoneytokenCheck", "shown"]
