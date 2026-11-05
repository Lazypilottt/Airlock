"""Run small AgentDojo benchmarks with Airlock configurations."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import random
from datetime import date
from pathlib import Path
from typing import Any

from airlock.config import AirlockConfig
from airlock.detect.cascade import CascadeResultCheck
from airlock.detect.classifier import PromptGuardClassifier
from airlock.engine import Engine


def _versions() -> dict[str, str]:
    versions: dict[str, str] = {}
    for package in ("airlock-mcp", "agentdojo"):
        try:
            versions[package] = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            versions[package] = "unknown"
    return versions


def _pipeline(model: str, config_name: str) -> Any:
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline, get_llm
    from agentdojo.agent_pipeline.basic_elements import InitQuery, SystemMessage
    from agentdojo.agent_pipeline.tool_execution import ToolsExecutionLoop, ToolsExecutor
    from agentdojo.models import MODEL_PROVIDERS, ModelsEnum

    from bench.agentdojo_adapter import AirlockAgentDojoAdapter, PromptGuardResultCheck

    model_enum = ModelsEnum(model)
    llm = get_llm(MODEL_PROVIDERS[model_enum], model, None, "tool")
    if config_name == "none":
        elements = [ToolsExecutor(), llm]
    else:
        config = AirlockConfig()
        if config_name == "promptguard":
            engine = Engine(
                config=config,
                tool_result_checks=[
                    PromptGuardResultCheck(
                        PromptGuardClassifier(config.data_dir, config.classifier),
                        block_threshold=config.block_above,
                    )
                ],
            )
        else:
            engine = Engine(config=config, tool_result_checks=[CascadeResultCheck(config)])
        adapter = AirlockAgentDojoAdapter(engine)
        elements = [adapter, ToolsExecutor(), adapter, llm]

    return AgentPipeline(
        [
            SystemMessage("You are a helpful assistant."),
            InitQuery(),
            llm if config_name == "none" else elements[-1],
            ToolsExecutionLoop(elements),
        ]
    )


def run(
    model: str,
    suites: list[str],
    attack: str | None,
    limit: int | None,
    seed: int,
    config_name: str,
) -> dict[str, Any]:
    """Run selected AgentDojo suites and return JSON-serializable results."""
    random.seed(seed)
    from agentdojo.attacks.attack_registry import load_attack
    from agentdojo.benchmark import (
        benchmark_suite_with_injections,
        benchmark_suite_without_injections,
    )
    from agentdojo.task_suite.load_suites import get_suite

    pipeline = _pipeline(model, config_name)
    output: dict[str, Any] = {
        "config": config_name,
        "model": model,
        "attack": attack,
        "suites": {},
        "packages": _versions(),
    }
    for suite_name in suites:
        suite = get_suite("v1.2.2", suite_name)
        user_tasks = list(suite.user_tasks)[:limit] if limit is not None else None
        if attack:
            attack_instance = load_attack(attack, suite, pipeline)
            results = benchmark_suite_with_injections(
                pipeline,
                suite,
                attack_instance,
                logdir=None,
                force_rerun=True,
                user_tasks=user_tasks,
            )
        else:
            results = benchmark_suite_without_injections(
                pipeline, suite, logdir=None, force_rerun=True, user_tasks=user_tasks
            )
        output["suites"][suite_name] = {
            "utility": list(results["utility_results"].values()),
            "security": list(results["security_results"].values()),
            "injection_utility": list(results["injection_tasks_utility_results"].values()),
        }
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config", choices=("none", "promptguard", "airlock-detect"), default="none"
    )
    parser.add_argument("--model", default="gpt-4o-mini-2024-07-18")
    parser.add_argument("--suites", nargs="+", default=["workspace"])
    parser.add_argument("--attack", default=None)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()
    results = run(args.model, args.suites, args.attack, args.limit, args.seed, args.config)
    output_dir = Path("bench/results")
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"{date.today().isoformat()}-{args.config}.json"
    path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(path)


if __name__ == "__main__":
    main()
