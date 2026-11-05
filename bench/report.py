"""Render AgentDojo benchmark JSON results as Markdown."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def _average(values: list[bool]) -> str:
    return f"{(sum(values) / len(values) * 100):.1f}%" if values else "n/a"


def render(paths: list[Path]) -> str:
    rows = [
        "| Configuration | Benign utility | Utility under attack | Targeted attack success rate |",
        "|---|---:|---:|---:|",
    ]
    for path in paths:
        data = json.loads(path.read_text(encoding="utf-8"))
        benign: list[bool] = []
        attacked: list[bool] = []
        security: list[bool] = []
        for suite in data.get("suites", {}).values():
            benign.extend(suite.get("utility", []))
            attacked.extend(suite.get("injection_utility", []))
            security.extend(not value for value in suite.get("security", []))
        rows.append(
            f"| {data['config']} | {_average(benign)} | "
            f"{_average(attacked)} | {_average(security)} |"
        )
    return "\n".join(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args()
    print(render(args.paths))


if __name__ == "__main__":
    main()
