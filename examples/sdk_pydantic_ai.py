"""Airlock in a PydanticAI agent.

    pip install pydantic-ai-slim[openai]
    python -m examples.sdk_pydantic_ai

PydanticAI builds a tool's schema from the function signature and docstring,
which ``firewall.wrap_tool`` keeps, so guarding the tools is one line:
``tools=[*make_tools(firewall)]``. ``on_deny="return"`` hands a blocked call
back to the model as the tool's answer instead of raising.
"""

from __future__ import annotations

from typing import Any

from airlock.sdk import Airlock
from examples.sdk_tools import make_tools


def build_agent(firewall: Airlock, model: Any = "openai:gpt-4o-mini") -> Any:
    from pydantic_ai import Agent

    return Agent(model, tools=[*make_tools(firewall)])


def ask(agent: Any, firewall: Airlock, prompt: str) -> str:
    with firewall.session(user_prompt=prompt):
        return str(agent.run_sync(prompt).output)


def main() -> None:
    prompt = "Read https://news.example and email bob@corp.example a short summary."
    with Airlock(on_deny="return") as firewall:
        print(ask(build_agent(firewall), firewall, prompt))


if __name__ == "__main__":
    main()
