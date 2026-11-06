"""Render AgentDojo benchmark JSON results as Markdown."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def _average(values: list[bool]) -> str:
    return f"{(sum(values) / len(values) * 100):.1f}%" if values else "n/a"


def render(paths: list[Path]) -> str:
    """One row per results file.

    AgentDojo's ``security`` result is the injection task's own check: True
    means the attacker's goal was carried out, so the attack success rate is
    the share of True values.
    """
    rows = [
        "| Configuration | Benign utility | Utility under attack "
        "| Targeted attack success rate | Calls blocked (of which ASK) |",
        "|---|---:|---:|---:|---:|",
    ]
    for path in paths:
        data = json.loads(path.read_text(encoding="utf-8"))
        benign: list[bool] = []
        attacked: list[bool] = []
        attack_succeeded: list[bool] = []
        for suite in data.get("suites", {}).values():
            benign.extend(suite.get("utility", []))
            attacked.extend(suite.get("injection_utility", []))
            attack_succeeded.extend(bool(value) for value in suite.get("security", []))
        stats = data.get("airlock") or {}
        blocked = (
            f"{stats.get('calls_denied', 0) + stats.get('calls_asked', 0)} "
            f"({stats.get('calls_asked', 0)})"
            if stats
            else "n/a"
        )
        rows.append(
            f"| {data['config']} | {_average(benign)} | "
            f"{_average(attacked)} | {_average(attack_succeeded)} | {blocked} |"
        )
    return "\n".join(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args()
    print(render(args.paths))


if __name__ == "__main__":
    main()
