"""The one place that decides which checks a default Airlock engine runs.

Every entry point builds its engine here: ``airlock wrap``, ``airlock serve``,
the Python SDK and the AgentDojo benchmark adapter. A new check is registered
by adding it to :func:`build_engine`, so no entry point can silently miss it.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from airlock.config import AirlockConfig
from airlock.detect.cascade import CascadeResultCheck
from airlock.engine import Engine
from airlock.taint.tracker import TaintCheck, TaintRecordCheck


def build_engine(
    config: AirlockConfig | None = None,
    *,
    detectors: bool = True,
    flow: bool = True,
    extra_tool_call_checks: Sequence[Any] = (),
    extra_tool_result_checks: Sequence[Any] = (),
    **engine_kwargs: Any,
) -> Engine:
    """Build an engine with Airlock's default checks.

    Args:
        config: Configuration; defaults are used when omitted.
        detectors: Run the L0/L1/L2 detector cascade on tool results.
        flow: Run data-flow checks: taint recording on results and taint
            matching on calls to sinks.
        extra_tool_call_checks: Additional call checks, run after the defaults.
        extra_tool_result_checks: Additional result checks, run after the defaults.
        **engine_kwargs: Passed to :class:`Engine` (``audit_store``, ``registry``,
            ``label_resolver``, ``description_checks``...).
    """
    cfg = config if config is not None else AirlockConfig()
    engine = Engine(
        config=cfg,
        tool_call_checks=[],
        tool_result_checks=[],
        **engine_kwargs,
    )
    if flow and cfg.taint.enabled:
        # Record before any detector rewrites the result: taint the original text.
        engine.add_tool_result_check(TaintRecordCheck(cfg, engine.labels_for))
        engine.add_tool_call_check(TaintCheck(cfg, engine.labels_for))
    if detectors:
        engine.add_tool_result_check(CascadeResultCheck(cfg))
    for check in extra_tool_call_checks:
        engine.add_tool_call_check(check)
    for check in extra_tool_result_checks:
        engine.add_tool_result_check(check)
    return engine


__all__ = ["build_engine"]
