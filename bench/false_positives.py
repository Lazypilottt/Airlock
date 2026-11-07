"""False-positive rate of Airlock's result checks on benign tool outputs.

    uv run python -m bench.false_positives [--json out.json]

The benign set is built from text already on this machine (nothing is
downloaded), so it is realistic but not identical across machines; the
report prints the counts per source and the package versions used:

- ``readme``: package descriptions (READMEs) of the installed Python packages;
- ``docstring``: documentation of standard-library modules;
- ``synthetic``: tool-output formats (web pages, emails, issues, API JSON) and
  hard negatives (READMEs, recipes, how-tos, articles about prompt injection)
  from ``scripts/classifier_data.py``;
- ``security-docs``: paragraphs of Airlock's own documentation, which talks
  about prompt injection at length (hard negatives).

Every text is fed to the engine as the result of a tool labelled
``source_untrusted``; anything other than ALLOW is a false positive.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import importlib.metadata
import json
import sys
import tempfile
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from airlock.config import AirlockConfig
from airlock.engine_factory import build_engine
from airlock.models import ToolDef, ToolResult, Verdict

REPO = Path(__file__).resolve().parents[1]
CHUNK = 3000


def _chunks(text: str, limit: int = CHUNK) -> Iterator[str]:
    """Paragraph-aligned chunks of at most ``limit`` characters."""
    current = ""
    for paragraph in text.split("\n\n"):
        if len(current) + len(paragraph) + 2 > limit and current.strip():
            yield current.strip()
            current = ""
        current += paragraph[:limit] + "\n\n"
    if current.strip():
        yield current.strip()


def readmes(limit: int) -> list[str]:
    texts: list[str] = []
    for dist in sorted(importlib.metadata.distributions(), key=lambda d: d.metadata["Name"] or ""):
        body = dist.metadata.get_payload() or dist.metadata.get("Description") or ""  # type: ignore[attr-defined]
        texts += [chunk for chunk in _chunks(str(body)) if len(chunk) > 200]
    return texts[:limit]


def docstrings(limit: int) -> list[str]:
    texts: list[str] = []
    for name in sorted(sys.stdlib_module_names):
        if name.startswith("_") or name in {
            "antigravity",
            "this",
            "idlelib",
            "turtledemo",
            "tkinter",
        }:
            continue
        try:
            module = importlib.import_module(name)
        except Exception:
            continue
        doc = getattr(module, "__doc__", None)
        if isinstance(doc, str) and len(doc) > 200:
            texts += list(_chunks(doc))
    return texts[:limit]


def synthetic(limit: int) -> list[str]:
    from scripts.classifier_data import build_synthetic

    return [s.text for s in build_synthetic(limit * 2, seed=7) if s.label == 0][:limit]


def security_docs() -> list[str]:
    texts: list[str] = []
    for path in [REPO / "README.md", *sorted((REPO / "docs").glob("*.md"))]:
        if path.name.startswith("roadmap"):
            continue
        texts += [
            chunk for chunk in _chunks(path.read_text(encoding="utf-8"), 1500) if len(chunk) > 200
        ]
    return texts


def corpus(per_source: int = 200) -> dict[str, list[str]]:
    return {
        "readme": readmes(per_source),
        "docstring": docstrings(per_source),
        "synthetic": synthetic(per_source),
        "security-docs": security_docs(),
    }


async def evaluate(name: str, texts: dict[str, list[str]], data_dir: Path) -> dict[str, Any]:
    """Run every benign text through the engine as an untrusted tool result."""
    from bench.configs import build_bench_engine

    engine = (
        build_bench_engine(name, data_dir)
        if name != "airlock-detect-l1"
        else build_engine(
            AirlockConfig(data_dir=data_dir, classifier={"enabled": False}),  # type: ignore[arg-type]
            flow=False,
            honeytokens=False,
        )
    )
    assert engine is not None
    await engine.on_tools_listed(
        "web", [ToolDef(server_id="web", name="fetch", description="Fetch a URL")]
    )
    flagged: Counter[str] = Counter()
    rules: Counter[str] = Counter()
    unavailable = False
    examples: list[dict[str, str]] = []
    for source, items in texts.items():
        for index, text in enumerate(items):
            decision = await engine.on_tool_result(
                ToolResult(
                    session_id="fp",
                    server_id="web",
                    tool_name="fetch",
                    request_id=index,
                    content=[{"type": "text", "text": text}],
                )
            )
            if decision.rule == "l2:unavailable" or any(
                "L2 classifier unavailable" in r for r in decision.reasons
            ):
                unavailable = True
            if decision.verdict is not Verdict.ALLOW:
                flagged[source] += 1
                rules[decision.rule or "?"] += 1
                if len(examples) < 10:
                    examples.append(
                        {"source": source, "rule": str(decision.rule), "text": text[:160]}
                    )
    await engine.close()
    total = sum(len(items) for items in texts.values())
    return {
        "config": name,
        "total": total,
        "flagged": sum(flagged.values()),
        "rate": sum(flagged.values()) / total if total else 0.0,
        "by_source": {s: {"total": len(t), "flagged": flagged[s]} for s, t in texts.items()},
        "rules": dict(rules.most_common()),
        "l2_available": not unavailable,
        "examples": examples,
    }


def render(results: list[dict[str, Any]], texts: dict[str, list[str]]) -> str:
    sources = ", ".join(f"{name} {len(items)}" for name, items in texts.items())
    lines = [
        f"Benign tool outputs: {sum(len(v) for v in texts.values())} ({sources})",
        "",
        "| Config | Flagged | FP rate | L2 classifier | Rules |",
        "|---|---:|---:|---|---|",
    ]
    for r in results:
        rules = ", ".join(f"{k} {v}" for k, v in r["rules"].items()) or "-"
        lines.append(
            f"| {r['config']} | {r['flagged']} / {r['total']} | {r['rate']:.2%} | "
            f"{'yes' if r['l2_available'] else 'not installed'} | {rules} |"
        )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--per-source", type=int, default=200)
    parser.add_argument("--json", type=Path, default=None)
    args = parser.parse_args()
    texts = corpus(args.per_source)
    results = []
    for name in ("airlock-detect", "airlock-full"):
        with tempfile.TemporaryDirectory(prefix="airlock-fp-") as tmp:
            results.append(asyncio.run(evaluate(name, texts, Path(tmp))))
    print(render(results, texts))
    for r in results:
        for example in r["examples"]:
            print(f"  {r['config']} [{example['source']}] {example['rule']}: {example['text']!r}")
    if args.json:
        args.json.write_text(json.dumps(results, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
