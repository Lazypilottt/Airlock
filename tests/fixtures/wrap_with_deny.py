"""Wrapper script running run_stdio_proxy with a check denying send_email."""

from __future__ import annotations

import asyncio
import sys

from airlock.engine import Engine, Session
from airlock.models import Decision, ToolCall, Verdict
from airlock.transport.stdio import run_stdio_proxy


class DenyEmailCheck:
    name = "deny_send_email"

    async def check(self, call: ToolCall, session: Session) -> Decision:
        if call.tool_name == "send_email":
            return Decision(
                verdict=Verdict.DENY,
                reasons=["Policy prohibits sending outbound emails"],
                rule="policy:no_email",
            )
        return Decision(verdict=Verdict.ALLOW)


def main() -> None:
    args = sys.argv[1:]
    if "--" in args:
        dash_idx = args.index("--")
        cmd = args[dash_idx + 1 :]
    else:
        cmd = args

    engine = Engine(tool_call_checks=[DenyEmailCheck()])
    exit_code = asyncio.run(run_stdio_proxy(cmd, name="deny-server", engine=engine))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
