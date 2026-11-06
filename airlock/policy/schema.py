"""Policy file schema, compilation, evaluation and plain-English explanations.

A policy is an ordered list of rules. The first rule whose ``when`` conditions
all hold decides the verdict; if no rule matches, ``default`` applies.

.. code-block:: yaml

    default: allow
    rules:
      - name: ask-untrusted-to-sink
        when:
          direction: call
          labels: {any: [sink]}
          arg_tainted_by: untrusted
        then: ask
        message: Data from an untrusted source is about to leave.
"""

from __future__ import annotations

import fnmatch
import json
import re
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from airlock.taint.normalize import normalize_domain, url_host

Then = Literal["allow", "deny", "redact", "ask"]
Direction = Literal["call", "result"]
LabelName = Literal["source_untrusted", "source_secret", "sink"]
TaintLabel = Literal["untrusted", "secret"]
ThresholdKeyword = Literal["redact_above", "block_above"]


class PolicyError(Exception):
    """Raised when a policy file cannot be read or is invalid."""


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


class LabelsCondition(BaseModel):
    """``labels: {any: [...]}`` or ``labels: {all: [...]}``; a bare list means ``any``."""

    model_config = ConfigDict(extra="forbid")

    any: list[LabelName] | None = None
    all: list[LabelName] | None = None

    @model_validator(mode="before")
    @classmethod
    def _shorthand(cls, value: Any) -> Any:
        if isinstance(value, (list, str)):
            return {"any": [value] if isinstance(value, str) else value}
        return value

    @model_validator(mode="after")
    def _not_empty(self) -> LabelsCondition:
        if not self.any and not self.all:
            raise ValueError("labels needs a non-empty 'any' or 'all' list")
        return self


class ArgCondition(BaseModel):
    """A condition on one argument (``path``) of a tool call.

    ``path`` is a dotted path (``payload.items[0].url``) or ``*`` for every
    string in the arguments. With no other field, the condition only checks
    that the argument exists.
    """

    model_config = ConfigDict(extra="forbid")

    path: str = Field(default="*", min_length=1)
    domain_in: list[str] | None = None
    domain_not_in: list[str] | None = None
    max_length: int | None = Field(default=None, ge=0)
    matches: str | None = None

    @field_validator("matches")
    @classmethod
    def _valid_regex(cls, value: str | None) -> str | None:
        if value is not None:
            try:
                re.compile(value)
            except re.error as exc:
                raise ValueError(f"invalid regular expression: {exc}") from exc
        return value


def _as_list[S: str](value: S | list[S] | None) -> list[S] | None:
    if value is None:
        return None
    return value if isinstance(value, list) else [value]


class When(BaseModel):
    """Conditions of a rule. Every condition that is set must hold."""

    model_config = ConfigDict(extra="forbid")

    tool: str | list[str] | None = None
    server: str | list[str] | None = None
    labels: LabelsCondition | None = None
    direction: Direction | None = None
    arg: ArgCondition | None = None
    arg_tainted_by: TaintLabel | list[TaintLabel] | None = None
    result_score_above: float | ThresholdKeyword | None = None
    quarantined: bool | None = None

    @field_validator("result_score_above")
    @classmethod
    def _score_range(cls, value: float | str | None) -> float | str | None:
        if isinstance(value, float) and not 0 <= value <= 1:
            raise ValueError("result_score_above must be between 0 and 1")
        return value

    @model_validator(mode="after")
    def _consistent_direction(self) -> When:
        call_only = self.arg is not None or self.arg_tainted_by is not None
        if call_only and self.direction == "result":
            raise ValueError("arg and arg_tainted_by only apply to direction: call")
        if self.result_score_above is not None and self.direction == "call":
            raise ValueError("result_score_above only applies to direction: result")
        return self


class Rule(BaseModel):
    """One policy rule."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=r"^[A-Za-z0-9_.:-]+$")
    when: When = Field(default_factory=When)
    then: Then
    message: str | None = None


class Policy(BaseModel):
    """A policy file."""

    model_config = ConfigDict(extra="forbid")

    mode: Literal["enforce", "shadow"] | None = None
    default: Literal["allow", "deny"] = "allow"
    rules: list[Rule] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_names(self) -> Policy:
        seen: set[str] = set()
        for rule in self.rules:
            if rule.name in seen:
                raise ValueError(f"duplicate rule name: {rule.name}")
            seen.add(rule.name)
        return self

    @classmethod
    def load(cls, path: Path | str) -> Policy:
        path = Path(path)
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise PolicyError(f"Cannot read policy {path}: {exc}") from exc
        if raw is None:
            raw = {}
        if not isinstance(raw, dict):
            raise PolicyError(f"Policy {path} must be a YAML mapping")
        try:
            return cls.model_validate(raw)
        except ValidationError as exc:
            raise PolicyError(f"Invalid policy {path}: {exc}") from exc


# ---------------------------------------------------------------------------
# Events and evaluation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TaintSignal:
    """A tainted value in one argument, as the policy sees it."""

    arg_path: str
    label: TaintLabel


@dataclass(frozen=True)
class PolicyEvent:
    """What a rule is evaluated against."""

    direction: Direction
    server: str
    tool: str
    labels: frozenset[str] = frozenset()
    arguments: Mapping[str, Any] | None = None
    taint: Sequence[TaintSignal] = ()
    score: float | None = None
    redact_above: float = 0.5
    block_above: float = 0.85
    quarantined: bool = False


@dataclass(frozen=True)
class PolicyMatch:
    """The outcome of evaluating a policy against an event."""

    verdict: Then
    rule: Rule | None
    message: str | None = None
    taint: tuple[TaintSignal, ...] = ()

    @property
    def rule_name(self) -> str:
        return self.rule.name if self.rule is not None else "default"


Predicate = Callable[[PolicyEvent], bool]


def _glob_any(patterns: list[str]) -> Callable[[str], bool]:
    compiled = [re.compile(fnmatch.translate(pattern.lower())) for pattern in patterns]
    return lambda value: any(pattern.match(value.lower()) for pattern in compiled)


def _path_covers(condition_path: str, arg_path: str) -> bool:
    if condition_path == "*":
        return True
    return (
        arg_path == condition_path
        or arg_path.startswith(condition_path + ".")
        or arg_path.startswith(condition_path + "[")
    )


_PATH_PART = re.compile(r"([^.\[\]]+)|\[(\d+)\]")


def resolve_arg(arguments: Mapping[str, Any], path: str) -> tuple[bool, Any]:
    """Return ``(found, value)`` for a dotted path such as ``payload.items[0].url``."""
    current: Any = arguments
    for name, index in _PATH_PART.findall(path):
        if index:
            if not isinstance(current, list) or int(index) >= len(current):
                return False, None
            current = current[int(index)]
        else:
            if not isinstance(current, Mapping) or name not in current:
                return False, None
            current = current[name]
    return True, current


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)
    elif value is not None:
        yield str(value)


_EMAIL_DOMAIN = re.compile(r"@((?:[\w-]+\.)+[^\W\d_]{2,})")
_URLISH = re.compile(r"(?i)\b(?:[a-z][a-z0-9+.-]*://|www\.)\S+")
_BARE_HOST = re.compile(r"(?<![\w.@/-])(?:[\w-]+\.)+[^\W\d_]{2,}(?![\w-])")


def domains_in(value: str) -> set[str]:
    """Hosts mentioned in a string: URL hosts, email domains and bare domain names."""
    found = {url_host(match.group(0)) for match in _URLISH.finditer(value)}
    found |= {normalize_domain(domain) for domain in _EMAIL_DOMAIN.findall(value)}
    stripped = _EMAIL_DOMAIN.sub(" ", _URLISH.sub(" ", value))
    found |= {normalize_domain(host) for host in _BARE_HOST.findall(stripped)}
    return {domain for domain in found if domain}


def _domain_listed(domain: str, patterns: list[str]) -> bool:
    for pattern in patterns:
        pattern = pattern.lower().strip()
        if any(char in pattern for char in "*?["):
            if fnmatch.fnmatchcase(domain, pattern):
                return True
        else:
            pattern = normalize_domain(pattern)
            if domain == pattern or domain.endswith("." + pattern):
                return True
    return False


def _arg_predicate(condition: ArgCondition) -> Predicate:
    pattern = re.compile(condition.matches) if condition.matches is not None else None

    def _values(event: PolicyEvent) -> list[Any] | None:
        if event.arguments is None:
            return None
        if condition.path == "*":
            return [event.arguments] if event.arguments else None
        found, value = resolve_arg(event.arguments, condition.path)
        return [value] if found else None

    def predicate(event: PolicyEvent) -> bool:
        values = _values(event)
        if values is None:
            return False
        strings = [text for value in values for text in _strings(value)]
        if condition.domain_in is not None:
            domains = set().union(*(domains_in(text) for text in strings)) if strings else set()
            if not domains or not all(_domain_listed(d, condition.domain_in) for d in domains):
                return False
        if condition.domain_not_in is not None:
            domains = set().union(*(domains_in(text) for text in strings)) if strings else set()
            outside = any(not _domain_listed(d, condition.domain_not_in) for d in domains)
            # No recognisable domain at all counts as "not in the list" (fail safe).
            if domains and not outside:
                return False
            if not domains and not any(text.strip() for text in strings):
                return False
        if condition.max_length is not None:
            serialised = [
                value if isinstance(value, str) else json.dumps(value, default=str)
                for value in values
            ]
            if not any(len(text) > condition.max_length for text in serialised):
                return False
        if pattern is not None and not any(pattern.search(text) for text in strings):
            return False
        return True

    return predicate


@dataclass
class CompiledRule:
    """A rule with its conditions turned into ``(condition name, predicate)`` pairs."""

    rule: Rule
    predicates: list[tuple[str, Predicate]] = field(default_factory=list)
    taint_labels: frozenset[str] | None = None
    taint_path: str = "*"

    def matching_taint(self, event: PolicyEvent) -> tuple[TaintSignal, ...]:
        if self.taint_labels is None:
            return ()
        return tuple(
            signal
            for signal in event.taint
            if signal.label in self.taint_labels and _path_covers(self.taint_path, signal.arg_path)
        )

    def first_failure(self, event: PolicyEvent) -> str | None:
        """Name of the first condition that does not hold, or ``None`` if the rule matches."""
        for condition, predicate in self.predicates:
            if not predicate(event):
                return condition
        if self.taint_labels is not None and not self.matching_taint(event):
            return "arg_tainted_by"
        return None

    def matches(self, event: PolicyEvent) -> bool:
        return self.first_failure(event) is None


def compile_rule(rule: Rule) -> CompiledRule:
    """Turn a rule's conditions into predicates, once, at load time."""
    when = rule.when
    compiled = CompiledRule(rule)
    preds = compiled.predicates
    if when.direction is not None:
        direction = when.direction
        preds.append(("direction", lambda event: event.direction == direction))
    if when.arg is not None or when.arg_tainted_by is not None:
        preds.append(("direction", lambda event: event.direction == "call"))
    if when.result_score_above is not None:
        preds.append(("direction", lambda event: event.direction == "result"))
    if (tools := _as_list(when.tool)) is not None:
        tool_match = _glob_any(tools)
        preds.append(("tool", lambda event: tool_match(event.tool)))
    if (servers := _as_list(when.server)) is not None:
        server_match = _glob_any(servers)
        preds.append(("server", lambda event: server_match(event.server)))
    if when.labels is not None:
        any_of = frozenset(when.labels.any or ())
        all_of = frozenset(when.labels.all or ())
        if any_of:
            preds.append(("labels.any", lambda event: bool(event.labels & any_of)))
        if all_of:
            preds.append(("labels.all", lambda event: all_of <= event.labels))
    if when.arg is not None:
        preds.append(("arg", _arg_predicate(when.arg)))
    if when.arg_tainted_by is not None:
        labels = when.arg_tainted_by
        compiled.taint_labels = frozenset([labels] if isinstance(labels, str) else labels)
        if when.arg is not None:
            compiled.taint_path = when.arg.path
    if when.result_score_above is not None:
        threshold = when.result_score_above

        def _above(event: PolicyEvent) -> bool:
            if event.score is None:
                return False
            if threshold == "redact_above":
                limit = event.redact_above
            elif threshold == "block_above":
                limit = event.block_above
            else:
                limit = float(threshold)
            return event.score >= limit

        preds.append(("result_score_above", _above))
    if when.quarantined is not None:
        wanted = when.quarantined
        preds.append(("quarantined", lambda event: event.quarantined == wanted))
    return compiled


class CompiledPolicy:
    """A policy with its rules compiled once."""

    def __init__(self, policy: Policy, origin: str = "") -> None:
        self.policy = policy
        self.origin = origin
        self.rules = [compile_rule(rule) for rule in policy.rules]

    def trace(self, event: PolicyEvent) -> list[tuple[str, str | None]]:
        """``(rule name, first failing condition or None)`` for each rule up to the winner."""
        steps: list[tuple[str, str | None]] = []
        for compiled in self.rules:
            failure = compiled.first_failure(event)
            steps.append((compiled.rule.name, failure))
            if failure is None:
                break
        return steps

    def evaluate(self, event: PolicyEvent) -> PolicyMatch:
        for compiled in self.rules:
            if compiled.matches(event):
                return PolicyMatch(
                    verdict=compiled.rule.then,
                    rule=compiled.rule,
                    message=compiled.rule.message,
                    taint=compiled.matching_taint(event),
                )
        return PolicyMatch(verdict=self.policy.default, rule=None)


# ---------------------------------------------------------------------------
# Plain-English explanations
# ---------------------------------------------------------------------------

_VERB = {"allow": "ALLOW", "deny": "DENY", "redact": "REDACT", "ask": "ASK a human"}
_LABEL_TEXT = {
    "source_untrusted": "untrusted source",
    "source_secret": "secret source",
    "sink": "sink",
}


def _or(items: Sequence[str]) -> str:
    items = list(items)
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + f" or {items[-1]}"


def _and(items: Sequence[str]) -> str:
    items = list(items)
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + f" and {items[-1]}"


def explain_rule(rule: Rule) -> str:
    """Describe a rule in one English sentence."""
    when = rule.when
    clauses: list[str] = []
    if when.direction == "call":
        clauses.append("the event is an outgoing tool call")
    elif when.direction == "result":
        clauses.append("the event is a tool result")
    if (tools := _as_list(when.tool)) is not None:
        clauses.append(f"the tool name matches {_or([repr(t) for t in tools])}")
    if (servers := _as_list(when.server)) is not None:
        clauses.append(f"the server name matches {_or([repr(s) for s in servers])}")
    if when.labels is not None:
        if when.labels.any:
            names = [_LABEL_TEXT[label] for label in when.labels.any]
            clauses.append(f"the tool is labelled {_or(names)}")
        if when.labels.all:
            names = [_LABEL_TEXT[label] for label in when.labels.all]
            clauses.append(f"the tool is labelled {_and(names)}")
    arg_name = "any argument"
    if when.arg is not None:
        arg = when.arg
        arg_name = "any argument" if arg.path == "*" else f"argument `{arg.path}`"
        parts: list[str] = []
        if arg.domain_in is not None:
            parts.append(f"only names domains in {', '.join(arg.domain_in)}")
        if arg.domain_not_in is not None:
            parts.append(
                f"names a domain outside {', '.join(arg.domain_not_in)} (or no domain at all)"
            )
        if arg.max_length is not None:
            parts.append(f"is longer than {arg.max_length} characters")
        if arg.matches is not None:
            parts.append(f"matches the regular expression {arg.matches!r}")
        clauses.append(f"{arg_name} {_and(parts)}" if parts else f"{arg_name} is present")
    if when.arg_tainted_by is not None:
        tainted = _as_list(when.arg_tainted_by) or []
        sources = [f"{'an' if label[0] in 'aeiou' else 'a'} {label} source" for label in tainted]
        clauses.append(f"{arg_name} contains a value from {_or(sources)}")
    if when.result_score_above is not None:
        threshold = when.result_score_above
        limit = (
            f"the configured {threshold} threshold"
            if isinstance(threshold, str)
            else f"{threshold:g}"
        )
        clauses.append(f"the injection score is at least {limit}")
    if when.quarantined is not None:
        clauses.append(
            "the tool is quarantined (its definition changed)"
            if when.quarantined
            else "the tool is not quarantined"
        )
    condition = _and(clauses) if clauses else "always"
    head = f"Rule '{rule.name}': {_VERB[rule.then]}"
    sentence = f"{head} when {condition}." if clauses else f"{head} always."
    if rule.message:
        sentence += f' Message: "{rule.message}"'
    return sentence


def explain_policy(policy: Policy) -> list[str]:
    """One sentence per rule, then the default and the mode."""
    lines = [explain_rule(rule) for rule in policy.rules]
    lines.append(f"If no rule matches: {_VERB[policy.default]}.")
    if policy.mode == "shadow":
        lines.append("Shadow mode: verdicts are logged but not enforced.")
    return lines


def coverage_warnings(policy: Policy) -> list[str]:
    """Protections the policy no longer provides.

    With a policy loaded, taint hits, detector scores and quarantine status are
    evidence: only rules turn them into verdicts. A policy without such a rule
    silently lets that traffic through (or blocks it, with ``default: deny``).
    """
    if policy.default == "deny":
        return []
    rules = policy.rules
    tainted: set[str] = set()
    for rule in rules:
        rule_labels = _as_list(rule.when.arg_tainted_by)
        if rule_labels:
            tainted.update(rule_labels)
    warnings: list[str] = []
    for label in ("secret", "untrusted"):
        if label not in tainted:
            warnings.append(
                f"No rule uses arg_tainted_by: {label}; values from {label} sources "
                "reach sinks unchecked."
            )
    if not any(rule.when.result_score_above is not None for rule in rules):
        warnings.append(
            "No rule uses result_score_above; tool results that look like prompt "
            "injection are passed through."
        )
    if not any(rule.when.quarantined for rule in rules):
        warnings.append(
            "No rule uses quarantined: true; tools whose definition changed can still be called."
        )
    return warnings


__all__ = [
    "ArgCondition",
    "CompiledPolicy",
    "LabelsCondition",
    "Policy",
    "PolicyError",
    "PolicyEvent",
    "PolicyMatch",
    "Rule",
    "TaintSignal",
    "When",
    "compile_rule",
    "coverage_warnings",
    "domains_in",
    "explain_policy",
    "explain_rule",
    "resolve_arg",
]
