"""Prompt Guard 2 on its own, as a benchmark baseline."""

from __future__ import annotations

from typing import Any

from airlock.models import Decision, ToolResult, Verdict


class PromptGuardResultCheck:
    """Result check using only Prompt Guard 2."""

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


__all__ = ["PromptGuardResultCheck"]
