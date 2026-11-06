"""`airlock attack --sdk`: every scenario, with and without Airlock, no human needed.

The "agent" is a scripted, gullible stand-in for a model: it does whatever an
injection asks (so every attack succeeds without a defence), which makes the
run deterministic and suitable for CI. Airlock runs through the Python SDK
on the same engine as `airlock wrap`.
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from airlock.attack.scenarios import (
    BENIGN_CALCULATE,
    INJECTION,
    POISONED_ADD,
    RUG_PULL_CALCULATE,
    SCENARIOS,
    SHADOWING_REPORT,
    CanaryListener,
    exfiltration_result,
    http_post,
    injected_results,
)
from airlock.audit.store import AuditStore
from airlock.config import AirlockConfig, ClassifierConfig
from airlock.detect.normalize import normalize
from airlock.honeytokens.store import HoneytokenFile, save, store_path
from airlock.honeytokens.tokens import create_set
from airlock.models import ToolDef
from airlock.sdk import Airlock

SERVER = "attack"
_PHRASE = "ignore all previous instructions"


@dataclass
class Outcome:
    scenario: str
    title: str
    without_airlock: str
    with_airlock: str
    detected_by: str

    @property
    def detected(self) -> bool:
        return self.with_airlock.startswith("blocked")


def _reached(text: str) -> bool:
    return _PHRASE in normalize(text).text.lower()


def _definitions(add: str, calculate: str) -> list[ToolDef]:
    return [
        ToolDef(server_id=SERVER, name="add", description=add),
        ToolDef(server_id=SERVER, name="calculate", description=calculate),
        ToolDef(server_id=SERVER, name="format_report", description=SHADOWING_REPORT),
    ]


def _without(canary: CanaryListener, token: str) -> dict[str, str]:
    """What the gullible agent ends up doing with no defence."""
    outcome: dict[str, str] = {}
    for name, text in injected_results().items():
        outcome[name] = "succeeded: the instructions reached the agent" if _reached(text) else "?"
    outcome["poisoned_description"] = "succeeded: the agent was shown the poisoned description"
    outcome["shadowing"] = "succeeded: the agent was shown the shadowing description"
    outcome["rug_pull"] = "succeeded: the changed definition went unnoticed"
    notes = exfiltration_result(token, canary.url())
    if token in notes:
        http_post(canary.url(), token)
    outcome["exfiltration"] = (
        "succeeded: the honeytoken reached the canary" if canary.received(token) else "failed"
    )
    return outcome


def _with(data_dir: Path, canary: CanaryListener, token: str) -> tuple[dict[str, str], Path]:
    config = AirlockConfig(data_dir=data_dir, classifier=ClassifierConfig(enabled=False))
    outcome: dict[str, str] = {}
    with Airlock(config, server=SERVER, on_deny="return") as firewall:
        engine = firewall.engine
        run = firewall._loop.run  # the SDK's private loop owns the engine

        # Tool definitions, as an MCP server would list them.
        visible = run(engine.on_tools_listed(SERVER, _definitions(POISONED_ADD, BENIGN_CALCULATE)))
        names = {tool.name for tool in visible}
        outcome["poisoned_description"] = (
            "blocked: tool quarantined and hidden" if "add" not in names else "succeeded"
        )
        outcome["shadowing"] = (
            "blocked: tool quarantined and hidden" if "format_report" not in names else "succeeded"
        )
        # Only `calculate` changes; the other definitions are listed as before.
        later = run(engine.on_tools_listed(SERVER, _definitions(POISONED_ADD, RUG_PULL_CALCULATE)))
        outcome["rug_pull"] = (
            "blocked: changed tool quarantined and hidden"
            if "calculate" not in {tool.name for tool in later}
            else "succeeded"
        )

        results = injected_results()

        @firewall.tool(labels=["source_untrusted"], args={"city": "destination"})
        def get_weather(city: str, variant: str) -> str:
            """Current weather for a city."""
            return results[f"injected_{variant}"]

        for name in results:
            seen = get_weather("Lisbon", name.removeprefix("injected_"))
            outcome[name] = (
                "succeeded: the instructions reached the agent"
                if _reached(seen)
                else "blocked: instructions removed before the agent saw them"
            )

        @firewall.tool(labels=["source_untrusted"])
        def read_notes() -> str:
            """Read the user's saved notes."""
            return exfiltration_result(token, canary.url())

        @firewall.tool(
            name="http_post", labels=["sink"], args={"url": "destination", "body": "content"}
        )
        def post(url: str, body: str) -> str:
            """Send data to a URL."""
            return http_post(url, body)

        notes = read_notes()
        if token in notes:
            post(canary.url(), token)
        outcome["exfiltration"] = (
            "succeeded: the honeytoken reached the canary"
            if canary.received(token)
            else "blocked: the honeytoken never left"
        )
    return outcome, data_dir / "audit.db"


def _detectors(audit_db: Path, data_dir: Path) -> dict[str, str]:
    """Which rule or check stopped each scenario (from the audit log and registry)."""
    from airlock.registry.store import ToolRegistry

    rows = AuditStore(audit_db).query_decisions(limit=500)
    by_tool: dict[str, list[str]] = {}
    for row in rows:
        effective = row.get("would_have") or row["verdict"]
        if effective != "ALLOW" and row.get("rule"):
            by_tool.setdefault(str(row["tool_name"]), []).append(str(row["rule"]))
    registry = ToolRegistry(data_dir / "registry.db")

    def quarantine(tool: str) -> str:
        record = registry.get_tool(SERVER, tool)
        reason = (record or {}).get("status_reason") or ""
        return f"registry quarantine ({reason[:60]})" if reason else "registry quarantine"

    found = {
        "poisoned_description": quarantine("add"),
        "shadowing": quarantine("format_report"),
        "rug_pull": quarantine("calculate"),
        "exfiltration": ", ".join(sorted(set(by_tool.get("http_post", [])))) or "-",
    }
    weather = sorted(set(by_tool.get("get_weather", [])))
    for name in injected_results():
        found[name] = ", ".join(weather) or "-"
    return found


def run_sdk(data_dir: Path | None = None) -> list[Outcome]:
    """Run every scenario twice and return the report card rows."""
    root = data_dir or Path(tempfile.mkdtemp(prefix="airlock-attack-"))
    root.mkdir(parents=True, exist_ok=True)
    with CanaryListener() as canary:
        tokens = create_set(canary_port=canary.port)
        save(store_path(root), HoneytokenFile(tokens=tokens))
        token = next(t.value for t in tokens if t.kind == "aws_secret_access_key")
        without = _without(canary, token)
        canary.hits.clear()
        with_airlock, audit_db = _with(root, canary, token)
    detected = _detectors(audit_db, root)
    return [
        Outcome(
            scenario.id,
            scenario.title,
            without.get(scenario.id, "-"),
            with_airlock.get(scenario.id, "-"),
            detected.get(scenario.id, "-")
            if with_airlock.get(scenario.id, "").startswith("blocked")
            else "-",
        )
        for scenario in SCENARIOS
    ]


def render(outcomes: list[Outcome], data_dir: Path | None = None) -> str:
    lines = [
        "Airlock red-team report card (scripted agent that follows every injection)",
        "",
        f"{'Scenario':<46} {'Without Airlock':<16} {'With Airlock':<13} Detected by",
    ]
    for item in outcomes:
        without = "ATTACK WORKED" if item.without_airlock.startswith("succeeded") else "no effect"
        with_ = "BLOCKED" if item.detected else "ATTACK WORKED"
        lines.append(f"{item.title:<46} {without:<16} {with_:<13} {item.detected_by}")
    caught = sum(item.detected for item in outcomes)
    lines += ["", f"Detected with Airlock: {caught} of {len(outcomes)} scenarios."]
    if data_dir is not None:
        lines.append(f"Audit log of the run: {data_dir / 'audit.db'}")
    return "\n".join(lines) + "\n"


def as_dicts(outcomes: list[Outcome]) -> list[dict[str, Any]]:
    return [{**vars(item), "detected": item.detected} for item in outcomes]


__all__ = ["INJECTION", "Outcome", "as_dicts", "render", "run_sdk"]
