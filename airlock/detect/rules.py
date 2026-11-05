"""L1 rule-pack detector."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from airlock.detect.normalize import NormalizedText, normalize
from airlock.models import Decision, ToolDef, ToolResult, Verdict


class Rule(BaseModel):
    """A single L1 detection rule."""

    model_config = ConfigDict(extra="forbid")

    id: str
    description: str
    pattern: str | None = None
    keywords: list[str] | None = None
    applies_to: Literal["result", "description", "both"] = "both"
    severity: Literal["low", "medium", "high"]
    score: float = Field(ge=0, le=1)

    @model_validator(mode="after")
    def validate_matcher(self) -> Rule:
        if self.pattern is None and not self.keywords:
            raise ValueError("rule requires pattern or keywords")
        if self.pattern is not None:
            re.compile(self.pattern)
        return self


class RulePack(BaseModel):
    """Versioned, validated collection of rules."""

    model_config = ConfigDict(extra="forbid")

    version: str
    rules: list[Rule]

    @classmethod
    def load(cls, path: Path | str) -> RulePack:
        """Load a YAML pack and fail loudly for invalid YAML or regexes."""
        with Path(path).open(encoding="utf-8") as stream:
            data = yaml.safe_load(stream)
        return cls.model_validate(data)


class RuleMatch(BaseModel):
    """One rule match with an original-text span."""

    rule_id: str
    start: int
    end: int
    score: float


class DetectionResult(BaseModel):
    """L1 output."""

    matched_rule_ids: list[str] = Field(default_factory=list)
    max_score: float = 0.0
    spans: list[RuleMatch] = Field(default_factory=list)


class RuleDetector:
    """Apply a rule pack to normalized text."""

    def __init__(self, pack: RulePack | None = None, pack_path: Path | str | None = None) -> None:
        default = Path(__file__).parents[2] / "packs" / "rules" / "core-v1.yaml"
        self.pack = pack or RulePack.load(pack_path or default)

    def detect(self, value: str | NormalizedText, applies_to: str) -> DetectionResult:
        normalized = value if isinstance(value, NormalizedText) else normalize(value)
        matches: list[RuleMatch] = []
        ids: list[str] = []
        for rule in self.pack.rules:
            if rule.applies_to not in (applies_to, "both") and applies_to not in ("both",):
                continue
            candidates: list[re.Match[str]] = []
            if rule.pattern:
                candidates.extend(re.finditer(rule.pattern, normalized.text, re.IGNORECASE))
            else:
                for keyword in rule.keywords or []:
                    candidates.extend(
                        re.finditer(re.escape(keyword), normalized.text, re.IGNORECASE)
                    )
            for candidate in candidates:
                start, end = normalized.original_span(candidate.start(), candidate.end())
                matches.append(RuleMatch(rule_id=rule.id, start=start, end=end, score=rule.score))
                if rule.id not in ids:
                    ids.append(rule.id)
        return DetectionResult(
            matched_rule_ids=ids,
            max_score=max((match.score for match in matches), default=0.0),
            spans=matches,
        )


class L1ResultCheck:
    """Engine check that redacts high-confidence matches in result text."""

    name = "l1_rules"

    def __init__(self, detector: RuleDetector | None = None, redact_threshold: float = 0.7) -> None:
        self.detector = detector or RuleDetector()
        self.redact_threshold = redact_threshold

    async def check(self, result: ToolResult, session: object) -> Decision:
        del session
        modified = [dict(item) for item in result.content]
        all_matches: list[RuleMatch] = []
        for item in modified:
            value = item.get("text")
            if not isinstance(value, str):
                continue
            detection = self.detector.detect(value, "result")
            all_matches.extend(detection.spans)
            if detection.max_score >= self.redact_threshold:
                for match in sorted(detection.spans, key=lambda match: match.start, reverse=True):
                    item["text"] = (
                        item["text"][: match.start] + "[REDACTED]" + item["text"][match.end :]
                    )
        if not all_matches:
            return Decision(verdict=Verdict.ALLOW)
        max_score = max(match.score for match in all_matches)
        return Decision(
            verdict=Verdict.REDACT if max_score >= self.redact_threshold else Verdict.ALLOW,
            rule="l1_rules",
            reasons=[
                f"L1 matched rules: {', '.join(dict.fromkeys(m.rule_id for m in all_matches))}"
            ],
            scores={"l1.max_score": max_score},
            modified_payload=modified if max_score >= self.redact_threshold else None,
        )


class L1DescriptionCheck:
    """Registry description check backed by the same L1 rule pack."""

    name = "l1_description_rules"

    def __init__(self, detector: RuleDetector | None = None) -> None:
        self.detector = detector or RuleDetector()

    async def check(self, tool: ToolDef) -> tuple[bool, str | None]:
        detection = self.detector.detect(tool.description, "description")
        if not detection.matched_rule_ids:
            return False, None
        return (
            True,
            f"L1 matched rules in tool description: {', '.join(detection.matched_rule_ids)}",
        )


__all__ = [
    "DetectionResult",
    "L1DescriptionCheck",
    "L1ResultCheck",
    "Rule",
    "RuleDetector",
    "RuleMatch",
    "RulePack",
]
