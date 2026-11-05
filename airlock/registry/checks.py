"""Pluggable description checks for MCP tools."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from airlock.detect.rules import L1DescriptionCheck
from airlock.models import ToolDef


@runtime_checkable
class DescriptionCheck(Protocol):
    """Protocol for checking tool descriptions during registration."""

    @property
    def name(self) -> str: ...

    async def check(self, tool: ToolDef) -> tuple[bool, str | None]:
        """Return (is_flagged, reason_if_flagged)."""
        ...


class StubDescriptionCheck:
    """Default stub description check scanning for suspicious injection markers."""

    name = "stub_description_check"

    def __init__(self, suspicious_phrases: list[str] | None = None) -> None:
        self.suspicious_phrases: list[str] = suspicious_phrases or [
            "ignore previous instructions",
            "system prompt override",
            "admin bypass",
            "exfiltrate secrets",
        ]

    async def check(self, tool: ToolDef) -> tuple[bool, str | None]:
        """Flag tools whose description matches suspicious injection markers."""
        desc_lower = (tool.description or "").lower()
        for phrase in self.suspicious_phrases:
            if phrase in desc_lower:
                return (
                    True,
                    f"Suspicious instruction detected in tool description: '{phrase}'",
                )
        return (False, None)


__all__ = [
    "DescriptionCheck",
    "L1DescriptionCheck",
    "StubDescriptionCheck",
]
