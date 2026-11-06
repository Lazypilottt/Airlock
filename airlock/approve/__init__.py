"""Human approvals for ASK verdicts."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal, Protocol, runtime_checkable


class Answer(StrEnum):
    """How an approval request ended."""

    ALLOW_ONCE = "allow_once"
    ALLOW_SESSION = "allow_session"
    DENY = "deny"
    TIMEOUT = "timeout"
    UNAVAILABLE = "unavailable"

    @property
    def allowed(self) -> bool:
        return self in {Answer.ALLOW_ONCE, Answer.ALLOW_SESSION}


@dataclass(frozen=True)
class ApprovalRequest:
    """What the human is shown. ``arguments`` is already masked and truncated."""

    direction: Literal["call", "result"]
    server: str
    tool: str
    rule: str
    reasons: tuple[str, ...] = ()
    arguments: str = ""


@dataclass(frozen=True)
class ApprovalOutcome:
    """The human's answer, with a sentence for the audit log and the client."""

    answer: Answer
    detail: str = field(default="")


@runtime_checkable
class Approver(Protocol):
    """Something that can put an ASK in front of a human."""

    async def request(self, request: ApprovalRequest) -> ApprovalOutcome: ...


class NoApprover:
    """Every ASK becomes DENY (no human is reachable, or approvals are turned off)."""

    def __init__(self, detail: str = "approval required but approvals are turned off") -> None:
        self.detail = detail

    async def request(self, request: ApprovalRequest) -> ApprovalOutcome:
        del request
        return ApprovalOutcome(Answer.UNAVAILABLE, f"{self.detail}; treated as deny")


__all__ = ["Answer", "ApprovalOutcome", "ApprovalRequest", "Approver", "NoApprover"]
