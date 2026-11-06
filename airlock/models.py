"""Domain models and typed events for Airlock."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Verdict(StrEnum):
    """Firewall decision verdict."""

    ALLOW = "ALLOW"
    REDACT = "REDACT"
    ASK = "ASK"
    DENY = "DENY"


class ToolDef(BaseModel):
    """Definition of an MCP tool exposed by an MCP server."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)

    server_id: str
    name: str
    description: str
    input_schema: dict[str, Any] = Field(default_factory=dict, alias="inputSchema")
    annotations: dict[str, Any] | None = None


class ToolCall(BaseModel):
    """An outbound tool invocation requested by the client."""

    model_config = ConfigDict(extra="ignore")

    session_id: str
    server_id: str
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    request_id: str | int


class ToolResult(BaseModel):
    """An inbound tool execution result returned by an MCP server."""

    model_config = ConfigDict(extra="ignore")

    session_id: str
    server_id: str
    tool_name: str
    request_id: str | int
    content: list[dict[str, Any]] = Field(default_factory=list)
    is_error: bool = False
    structured_content: dict[str, Any] | None = None


class Decision(BaseModel):
    """The firewall policy decision for a tool call or result."""

    model_config = ConfigDict(extra="ignore")

    verdict: Verdict
    would_have: Verdict | None = None
    reasons: list[str] = Field(default_factory=list)
    rule: str | None = None
    scores: dict[str, float] = Field(default_factory=dict)
    modified_payload: Any | None = None
    latency_ms: float = 0.0
    # What a check observed (taint hits, detector scores...) for the policy to
    # judge. In-process only: never serialised or logged.
    evidence: dict[str, Any] = Field(default_factory=dict, exclude=True, repr=False)


__all__ = [
    "Decision",
    "ToolCall",
    "ToolDef",
    "ToolResult",
    "Verdict",
]
