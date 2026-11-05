"""L0/L1/L2 detector cascade."""

from __future__ import annotations

import re
from copy import deepcopy
from dataclasses import dataclass

from airlock.config import AirlockConfig
from airlock.detect.classifier import ModelUnavailable, PromptGuardClassifier
from airlock.detect.normalize import NormalizedText, normalize
from airlock.detect.rules import RuleDetector
from airlock.models import Decision, ToolResult, Verdict


@dataclass(frozen=True)
class CascadeResult:
    """Combined detector output."""

    score: float
    contributing_layers: tuple[str, ...] = ()
    spans: tuple[tuple[int, int], ...] = ()
    rule_ids: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()
    classifier_unavailable: bool = False


_SPOTLIGHT_MARKER = re.compile(r"<<\/?untrusted_content(?:\s+[^>]*)?>>", re.IGNORECASE)
_REDACTION = "[removed by Airlock: possible prompt injection]"
_BLOCKED = (
    "Airlock blocked this tool result because it may contain prompt injection. "
    "You can continue with another request."
)


class DetectorCascade:
    """Run normalization, rules, then the optional classifier."""

    def __init__(
        self,
        config: AirlockConfig | None = None,
        l1: RuleDetector | None = None,
        l2: PromptGuardClassifier | None = None,
    ) -> None:
        self.config = config or AirlockConfig()
        self.l1 = l1 or RuleDetector()
        self.l2 = l2 or PromptGuardClassifier(self.config.data_dir, self.config.classifier)

    def detect(self, value: str | NormalizedText) -> CascadeResult:
        normalized = value if isinstance(value, NormalizedText) else normalize(value)
        l0_score = 0.2 if normalized.findings else 0.0
        l1 = self.l1.detect(normalized, "result")
        score = max(l0_score, l1.max_score)
        layers = ["l0"] if l0_score else []
        spans = [(match.start, match.end) for match in l1.spans]
        if l1.max_score:
            layers.append("l1")
        rule_ids = tuple(l1.matched_rule_ids)
        reasons = [f"L1 matched rules: {', '.join(rule_ids)}"] if rule_ids else []
        if l1.max_score >= self.config.block_above:
            return CascadeResult(score, tuple(layers), tuple(spans), rule_ids, tuple(reasons))
        try:
            if not self.config.classifier.enabled:
                raise ModelUnavailable("classifier disabled by configuration")
            probability, span = self.l2.score(normalized.text)
        except ModelUnavailable as exc:
            if self.config.classifier.required:
                raise
            return CascadeResult(
                score,
                tuple(layers),
                tuple(spans),
                rule_ids,
                (*reasons, str(exc)),
                True,
            )
        score = max(score, probability)
        if probability:
            layers.append("l2")
        if span is not None:
            spans.append(normalized.original_span(*span))
        return CascadeResult(score, tuple(layers), tuple(spans), rule_ids, tuple(reasons))


class CascadeResultCheck:
    """Engine result check for the detector cascade."""

    name = "detector_cascade"

    def __init__(
        self, config: AirlockConfig | None = None, cascade: DetectorCascade | None = None
    ) -> None:
        self.config = config or AirlockConfig()
        self.cascade = cascade or DetectorCascade(self.config)

    async def check(self, result: ToolResult, session: object) -> Decision:
        del session
        redact_above, block_above = self._thresholds(result.server_id, result.tool_name)
        content = [dict(item) for item in result.content]
        structured_content = (
            deepcopy(result.structured_content) if result.structured_content is not None else None
        )
        text_values: list[tuple[str, str, str]] = []
        for index, item in enumerate(content):
            if isinstance(item.get("text"), str):
                text_values.append(("content", str(index), str(item["text"])))
            elif item.get("type") == "image" and isinstance(item.get("alt"), str):
                text_values.append(("alt", str(index), str(item["alt"])))
        structured_values: list[tuple[tuple[str, ...], str]] = []
        if structured_content is not None:
            self._collect_strings(structured_content, (), structured_values)
            text_values.extend(
                ("structured", ".".join(path), value) for path, value in structured_values
            )
        all_results = [self.cascade.detect(value) for _, _, value in text_values]
        if not all_results:
            return Decision(
                verdict=Verdict.ALLOW,
                modified_payload=self._payload(content, structured_content, result.is_error),
            )
        score = max(item.score for item in all_results)
        reasons = [reason for item in all_results for reason in item.reasons]
        unavailable = any(item.classifier_unavailable for item in all_results)
        if unavailable:
            reasons.append("L2 classifier unavailable; continuing with L0+L1")
        if self.config.classifier.required and unavailable:
            verdict = Verdict.DENY if self.config.fail_mode == "closed" else Verdict.ALLOW
            return Decision(verdict=verdict, rule="l2:unavailable", reasons=reasons)
        if score >= block_above or self._coverage_requires_block(
            text_values, all_results, block_above
        ):
            return Decision(
                verdict=Verdict.DENY,
                rule="detector_cascade:block",
                reasons=[_BLOCKED],
                scores={"cascade.score": score},
                modified_payload=self._blocked_payload(),
            )
        if score < redact_above:
            if self.config.spotlight:
                self._mark_content(content, structured_content, result.tool_name)
            return Decision(
                verdict=Verdict.ALLOW,
                scores={"cascade.score": score},
                reasons=reasons,
                modified_payload=self._payload(content, structured_content, result.is_error),
            )
        for (kind, location, value), detection in zip(text_values, all_results, strict=True):
            spans = self._merge_spans(detection.spans)
            replacement = self._redact(value, spans)
            if kind == "content":
                content[int(location)]["text"] = replacement
            elif kind == "structured":
                self._set_path(structured_content, location.split("."), replacement)
        payload = self._payload(content, structured_content, result.is_error)
        return Decision(
            verdict=Verdict.REDACT,
            rule="detector_cascade",
            reasons=reasons or ["Possible prompt injection removed from tool result."],
            scores={"cascade.score": score},
            modified_payload=payload,
        )

    def _thresholds(self, server_id: str, tool_name: str) -> tuple[float, float]:
        override = self.config.tool_overrides.get(tool_name) or self.config.server_overrides.get(
            server_id
        )
        return (
            override.redact_above
            if override and override.redact_above is not None
            else self.config.redact_above,
            override.block_above
            if override and override.block_above is not None
            else self.config.block_above,
        )

    @staticmethod
    def _collect_strings(
        value: object, path: tuple[str, ...], output: list[tuple[tuple[str, ...], str]]
    ) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                CascadeResultCheck._collect_strings(item, (*path, str(key)), output)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                CascadeResultCheck._collect_strings(item, (*path, str(index)), output)
        elif isinstance(value, str):
            output.append((path, value))

    @staticmethod
    def _set_path(value: object, path: list[str], replacement: str) -> None:
        if not path or not isinstance(value, (dict, list)):
            return
        current: object = value
        for part in path[:-1]:
            current = current[int(part)] if isinstance(current, list) else current[part]  # type: ignore[index]
        if isinstance(current, list):
            current[int(path[-1])] = replacement
        else:
            current[path[-1]] = replacement  # type: ignore[index]

    @staticmethod
    def _merge_spans(spans: tuple[tuple[int, int], ...]) -> list[tuple[int, int]]:
        merged: list[tuple[int, int]] = []
        for start, end in sorted(spans):
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        return merged

    @staticmethod
    def _redact(value: str, spans: list[tuple[int, int]]) -> str:
        for start, end in reversed(spans):
            value = value[:start] + _REDACTION + value[end:]
        return value

    @staticmethod
    def _coverage_requires_block(
        values: list[tuple[str, str, str]], detections: list[CascadeResult], block_above: float
    ) -> bool:
        del block_above
        for (_, _, value), detection in zip(values, detections, strict=True):
            spans = CascadeResultCheck._merge_spans(detection.spans)
            if (
                isinstance(value, str)
                and value
                and sum(end - start for start, end in spans) / len(value) > 0.6
            ):
                return True
        return False

    @staticmethod
    def _payload(
        content: list[dict[str, object]], structured: dict[str, object] | None, is_error: bool
    ) -> dict[str, object]:
        payload: dict[str, object] = {"content": content, "isError": is_error}
        if structured is not None:
            payload["structuredContent"] = structured
        return payload

    @staticmethod
    def _blocked_payload() -> dict[str, object]:
        return {"content": [{"type": "text", "text": _BLOCKED}], "isError": True}

    def _mark_content(
        self, content: list[dict[str, object]], structured: dict[str, object] | None, source: str
    ) -> None:
        marker_start = f"<<untrusted_content source={source}>>"
        marker_end = "<</untrusted_content>>"
        for item in content:
            if isinstance(item.get("text"), str):
                text = str(item["text"])
                item["text"] = f"{marker_start}{_SPOTLIGHT_MARKER.sub('', text)}{marker_end}"
        if structured is not None:
            self._mark_strings(structured, marker_start, marker_end)

    @staticmethod
    def _mark_strings(value: object, marker_start: str, marker_end: str) -> None:
        if isinstance(value, dict):
            for key, item in list(value.items()):
                if isinstance(item, str):
                    value[key] = f"{marker_start}{_SPOTLIGHT_MARKER.sub('', item)}{marker_end}"
                else:
                    CascadeResultCheck._mark_strings(item, marker_start, marker_end)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                if isinstance(item, str):
                    value[index] = f"{marker_start}{_SPOTLIGHT_MARKER.sub('', item)}{marker_end}"
                else:
                    CascadeResultCheck._mark_strings(item, marker_start, marker_end)


__all__ = ["CascadeResult", "CascadeResultCheck", "DetectorCascade"]
