"""The benchmark configurations, all built with the default engine factory."""

from __future__ import annotations

from pathlib import Path

from airlock.config import AirlockConfig
from airlock.engine import Engine
from airlock.engine_factory import build_engine

CONFIGS = ("none", "promptguard", "airlock-detect", "airlock-flow", "airlock-full")


def bench_config(data_dir: Path) -> AirlockConfig:
    """Benchmark runs keep their own data directory, never prompt, and approve new tools.

    Nobody is there to approve a tool in a benchmark run; pending tools would
    otherwise be denied and counted as blocked attacks.
    """
    return AirlockConfig(
        data_dir=data_dir,
        approvals={"terminal": False},  # type: ignore[arg-type]
        auto_approve_new_tools=True,
    )


def build_bench_engine(name: str, data_dir: Path) -> Engine | None:
    """The engine for a configuration (``None`` for the undefended baseline).

    - ``promptguard``: Prompt Guard 2 alone on results, no policy.
    - ``airlock-detect``: the L0/L1/L2 detector cascade on results.
    - ``airlock-flow``: taint, policy and honeytokens; no detectors.
    - ``airlock-full``: detectors and flow together.
    """
    if name not in CONFIGS:
        raise ValueError(f"unknown configuration {name!r}; choose from {', '.join(CONFIGS)}")
    if name == "none":
        return None
    config = bench_config(data_dir)
    if name == "promptguard":
        from airlock.detect.classifier import PromptGuardClassifier
        from bench.promptguard import PromptGuardResultCheck

        return build_engine(
            config,
            detectors=False,
            flow=False,
            honeytokens=False,
            policy=False,
            extra_tool_result_checks=[
                PromptGuardResultCheck(
                    PromptGuardClassifier(config.data_dir, config.classifier),
                    block_threshold=config.block_above,
                )
            ],
        )
    if name == "airlock-detect":
        return build_engine(config, detectors=True, flow=False, honeytokens=False)
    if name == "airlock-flow":
        return build_engine(config, detectors=False, flow=True, honeytokens=True)
    return build_engine(config, detectors=True, flow=True, honeytokens=True)


__all__ = ["CONFIGS", "bench_config", "build_bench_engine"]
