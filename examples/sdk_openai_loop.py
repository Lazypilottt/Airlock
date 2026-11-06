"""A plain tool-calling loop against any OpenAI-compatible Chat Completions API.

    export OPENAI_BASE_URL=https://api.openai.com/v1 OPENAI_API_KEY=... MODEL=gpt-4o-mini
    python -m examples.sdk_openai_loop "Read https://news.example, email bob@corp.example"

Airlock's part is three lines: create the firewall, decorate the tools (see
``examples/sdk_tools.py``) and open a session with the user's prompt, so that
addresses the user typed are trusted and addresses found on the web are not.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

import httpx2

from airlock.sdk import Airlock
from examples.sdk_tools import make_tools

TOOL_SPECS = [
    {
        "type": "function",
        "function": {
            "name": "fetch_page",
            "description": "Fetch a web page and return its text.",
            "parameters": {
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "send_email",
            "description": "Send an email.",
            "parameters": {
                "type": "object",
                "properties": {"to": {"type": "string"}, "body": {"type": "string"}},
                "required": ["to", "body"],
            },
        },
    },
]


def run(
    prompt: str,
    client: httpx2.Client,
    model: str,
    firewall: Airlock,
    max_turns: int = 6,
) -> str:
    """Run the agent until the model answers without calling a tool."""
    fetch_page, send_email = make_tools(firewall)
    tools: dict[str, Any] = {"fetch_page": fetch_page, "send_email": send_email}
    messages: list[dict[str, Any]] = [{"role": "user", "content": prompt}]
    with firewall.session(user_prompt=prompt):
        for _ in range(max_turns):
            reply = client.post(
                "/chat/completions",
                json={"model": model, "messages": messages, "tools": TOOL_SPECS},
            )
            reply.raise_for_status()
            message = reply.json()["choices"][0]["message"]
            messages.append(message)
            calls = message.get("tool_calls") or []
            if not calls:
                return str(message.get("content") or "")
            for call in calls:
                function = tools[call["function"]["name"]]
                arguments = json.loads(call["function"]["arguments"] or "{}")
                output = function(**arguments)  # Airlock checks before and after
                messages.append(
                    {"role": "tool", "tool_call_id": call["id"], "content": str(output)}
                )
    return "Stopped after too many turns."


def main() -> None:
    base_url = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
    headers = {"Authorization": f"Bearer {os.environ.get('OPENAI_API_KEY', '')}"}
    prompt = " ".join(sys.argv[1:]) or "Read https://news.example and email bob@corp.example"
    with (
        Airlock(on_deny="return") as firewall,
        httpx2.Client(base_url=base_url, headers=headers, timeout=60) as client,
    ):
        print(run(prompt, client, os.environ.get("MODEL", "gpt-4o-mini"), firewall))


if __name__ == "__main__":
    main()
