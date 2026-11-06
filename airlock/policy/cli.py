"""``airlock policy check`` and ``airlock policy test``."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Annotated, Any, Literal

import typer
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from airlock.config import ConfigError, load_config
from airlock.detect.cascade import thresholds_for
from airlock.models import ToolDef
from airlock.policy.schema import (
    CompiledPolicy,
    LabelName,
    Policy,
    PolicyError,
    PolicyEvent,
    TaintLabel,
    TaintSignal,
    coverage_warnings,
    explain_rule,
)
from airlock.registry.labels import LabelResolver

policy_app = typer.Typer(
    name="policy",
    help="Validate, explain and test policy files.",
    no_args_is_help=True,
)

_VERDICT_TEXT = {"allow": "ALLOW", "deny": "DENY", "redact": "REDACT", "ask": "ASK"}


class TaintItem(BaseModel):
    """A tainted argument in a test event."""

    model_config = ConfigDict(extra="forbid")

    arg: str = Field(min_length=1, description="Argument path, e.g. `to` or `payload.url`.")
    label: TaintLabel


class EventFile(BaseModel):
    """The ``--event`` JSON for ``airlock policy test``."""

    model_config = ConfigDict(extra="forbid")

    direction: Literal["call", "result"]
    server: str
    tool: str
    description: str = ""
    arguments: dict[str, Any] = Field(default_factory=dict)
    labels: list[LabelName] | None = Field(
        default=None, description="Omit to resolve labels from packs, config and the tool name."
    )
    taint: list[TaintItem] = Field(default_factory=list)
    score: float | None = Field(default=None, ge=0, le=1)
    quarantined: bool = False


def _fail(message: str) -> typer.Exit:
    sys.stderr.write(f"Error: {message}\n")
    return typer.Exit(code=1)


def _load_policy(path: Path) -> Policy:
    if not path.is_file():
        raise _fail(f"Policy file not found: {path}")
    try:
        return Policy.load(path)
    except PolicyError as exc:
        raise _fail(str(exc)) from exc


@policy_app.command("check")
def check(
    file: Annotated[Path, typer.Argument(help="Policy file to validate.")],
) -> None:
    """Validate a policy and explain each rule in plain English."""
    policy = _load_policy(file)
    mode = policy.mode or "from airlock.yaml"
    print(f"{file}: valid. {len(policy.rules)} rule(s), default {policy.default}, mode {mode}.")
    print("Rules are checked in order; the first match decides.\n")
    for index, rule in enumerate(policy.rules, start=1):
        print(f"{index}. {explain_rule(rule)}")
    print(f"{len(policy.rules) + 1}. If no rule matches: {_VERDICT_TEXT[policy.default]}.")
    if policy.mode == "shadow":
        print("\nShadow mode: verdicts are logged but not enforced.")
    warnings = coverage_warnings(policy)
    if warnings:
        print()
        for warning in warnings:
            print(f"Warning: {warning}")


@policy_app.command("test")
def test(
    file: Annotated[Path, typer.Argument(help="Policy file.")],
    event: Annotated[
        Path,
        typer.Option("--event", "-e", help="JSON file describing a tool call or result."),
    ],
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="airlock.yaml for thresholds and label overrides."),
    ] = None,
) -> None:
    """Show which rule fires for an event, and why the rules before it did not."""
    policy = _load_policy(file)
    try:
        raw = json.loads(event.read_text(encoding="utf-8"))
        spec = EventFile.model_validate(raw)
    except OSError as exc:
        raise _fail(f"Cannot read event file {event}: {exc}") from exc
    except (json.JSONDecodeError, ValidationError) as exc:
        raise _fail(f"Invalid event file {event}: {exc}") from exc
    try:
        cfg = load_config(config)
    except ConfigError as exc:
        raise _fail(str(exc)) from exc

    if spec.labels is None:
        resolved = LabelResolver(user_entries=cfg.labels).resolve(
            spec.server,
            ToolDef(server_id=spec.server, name=spec.tool, description=spec.description),
        )
        labels = frozenset(label.value for label in resolved.labels)
        label_note = f"{', '.join(sorted(labels)) or 'none'} (resolved: {resolved.origin.value})"
    else:
        labels = frozenset(spec.labels)
        label_note = ", ".join(sorted(labels)) or "none"
    redact_above, block_above = thresholds_for(cfg, spec.server, spec.tool)
    policy_event = PolicyEvent(
        direction=spec.direction,
        server=spec.server,
        tool=spec.tool,
        labels=labels,
        arguments=spec.arguments if spec.direction == "call" else None,
        taint=tuple(TaintSignal(item.arg, item.label) for item in spec.taint),
        score=spec.score,
        redact_above=redact_above,
        block_above=block_above,
        quarantined=spec.quarantined,
    )
    compiled = CompiledPolicy(policy, origin=str(file))

    print(f"Event: {spec.direction} {spec.server}.{spec.tool}")
    print(f"  labels: {label_note}")
    if spec.taint:
        tainted = ", ".join(f"`{item.arg}` ({item.label})" for item in spec.taint)
        print(f"  tainted arguments: {tainted}")
    if spec.score is not None:
        print(
            f"  detector score: {spec.score:g} "
            f"(redact_above {redact_above:g}, block_above {block_above:g})"
        )
    if spec.quarantined:
        print("  quarantined: yes")
    print()
    for name, failure in compiled.trace(policy_event):
        if failure is None:
            print(f"  {name}: MATCH")
        else:
            print(f"  {name}: no ({failure} does not hold)")
    match = compiled.evaluate(policy_event)
    print()
    if match.rule is None:
        print(f"Verdict: {_VERDICT_TEXT[match.verdict]} (no rule matched; policy default)")
        return
    print(f"Verdict: {_VERDICT_TEXT[match.verdict]} (rule {match.rule.name})")
    print(f"  {explain_rule(match.rule)}")


__all__ = ["EventFile", "policy_app"]
