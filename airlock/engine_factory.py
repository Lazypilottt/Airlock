"""The one place that decides which checks a default Airlock engine runs.

Every entry point builds its engine here: ``airlock wrap``, ``airlock serve``,
the Python SDK and the AgentDojo benchmark adapter. A new check is registered
by adding it to :func:`build_engine`, so no entry point can silently miss it.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from airlock.approve import Approver, NoApprover
from airlock.approve.terminal import TerminalApprover
from airlock.config import AirlockConfig
from airlock.detect.cascade import CascadeResultCheck
from airlock.engine import Engine, PolicyProvider
from airlock.honeytokens.check import HoneytokenCheck
from airlock.honeytokens.store import WatchedHoneytokens, store_path
from airlock.policy.loader import PolicySource, default_policy_path
from airlock.taint.tracker import TaintCheck, TaintRecordCheck


def load_policy(config: AirlockConfig) -> PolicySource:
    """The configured policy, or the bundled default; reloaded when the file changes.

    Raises:
        PolicyError: The file is missing or invalid (startup fails closed).
    """
    return PolicySource(config.policy if config.policy is not None else default_policy_path())


def build_autolabeler(config: AirlockConfig, store: Any) -> Any:
    """The labeller for ``auto_label`` (provider chosen in config)."""
    from airlock.registry.autolabel import (
        AnthropicProvider,
        AutoLabeler,
        OpenAICompatibleProvider,
    )

    settings = config.auto_label
    provider: Any
    if settings.provider == "anthropic":
        provider = AnthropicProvider(
            settings.model or "claude-opus-5-5",
            settings.api_key_env or "ANTHROPIC_API_KEY",
            settings.timeout_seconds,
        )
    else:
        provider = OpenAICompatibleProvider(
            settings.model or "",
            settings.base_url,
            settings.api_key_env or "OPENAI_API_KEY",
            settings.timeout_seconds,
        )
    return AutoLabeler(provider, store, timeout=settings.timeout_seconds)


def default_approver(config: AirlockConfig) -> Approver:
    """Slack when ``slack.channel`` is set, else the terminal (if ``approvals.terminal``).

    Slack tokens come from the environment variables named in the config; if
    either is missing, every ASK is denied with that reason.
    """
    slack = config.slack
    if slack.channel:
        import os

        from airlock.approve.slack import SlackApprover, SocketModeTransport

        bot, app = os.environ.get(slack.bot_token_env), os.environ.get(slack.app_token_env)
        if not bot or not app:
            missing = slack.bot_token_env if not bot else slack.app_token_env
            return NoApprover(f"approval required but Slack token ${missing} is not set")
        return SlackApprover(
            SocketModeTransport(bot, app),
            slack.channel,
            timeout=slack.timeout_seconds,
            allowed_users=slack.allowed_users,
        )
    if not config.approvals.terminal:
        return NoApprover(
            "approval required but terminal approvals are turned off (approvals.terminal: false)"
        )
    return TerminalApprover(
        config.approvals.timeout_seconds, lock_path=config.data_dir / "approvals.lock"
    )


def build_engine(
    config: AirlockConfig | None = None,
    *,
    detectors: bool = True,
    flow: bool = True,
    honeytokens: bool = True,
    policy: PolicyProvider | bool | None = True,
    approver: Approver | None = None,
    extra_tool_call_checks: Sequence[Any] = (),
    extra_tool_result_checks: Sequence[Any] = (),
    **engine_kwargs: Any,
) -> Engine:
    """Build an engine with Airlock's default checks.

    Args:
        config: Configuration; defaults are used when omitted.
        detectors: Run the L0/L1/L2 detector cascade on tool results.
        flow: Run data-flow checks: taint recording on results and taint
            matching on calls.
        honeytokens: Deny calls carrying a token from ``data_dir/honeytokens.json``.
        policy: ``True`` loads ``config.policy`` (or the bundled default
            policy); ``False``/``None`` runs without a policy (each check
            decides its own verdict); or pass a policy provider.
        approver: Who answers ASK verdicts; defaults to the terminal.
        extra_tool_call_checks: Additional call checks, run after the defaults.
        extra_tool_result_checks: Additional result checks, run after the defaults.
        **engine_kwargs: Passed to :class:`Engine` (``audit_store``, ``registry``,
            ``label_resolver``, ``description_checks``...).
    """
    cfg = config if config is not None else AirlockConfig()
    provider: PolicyProvider | None
    if policy is True:
        provider = load_policy(cfg)
    elif policy is False or policy is None:
        provider = None
    else:
        provider = policy
    engine = Engine(
        config=cfg,
        tool_call_checks=[],
        tool_result_checks=[],
        policy=provider,
        approver=approver if approver is not None else default_approver(cfg),
        **engine_kwargs,
    )
    if honeytokens:
        engine.add_tool_call_check(
            HoneytokenCheck(WatchedHoneytokens(store_path(cfg.data_dir)), engine.audit_store)
        )
    if flow and cfg.taint.enabled:
        # Record before any detector rewrites the result: taint the original text.
        engine.add_tool_result_check(TaintRecordCheck(cfg, engine.labels_for))
        engine.add_tool_call_check(TaintCheck(cfg, engine.labels_for))
    if detectors:
        engine.add_tool_result_check(CascadeResultCheck(cfg))
    from airlock.registry.autolabel import LabelStore

    # Reviewed and proposed auto-labels apply whenever they exist; new ones are
    # only requested when auto_label is enabled.
    engine.label_resolver.auto_labels = LabelStore(cfg.data_dir / "auto-labels.json")
    engine.label_resolver.min_confidence = cfg.auto_label.min_confidence
    if cfg.auto_label.enabled:
        engine.autolabeler = build_autolabeler(cfg, engine.label_resolver.auto_labels)
    if cfg.otel.enabled:
        from airlock.telemetry import setup_otlp

        engine.telemetry = setup_otlp(cfg.otel)
    for check in extra_tool_call_checks:
        engine.add_tool_call_check(check)
    for check in extra_tool_result_checks:
        engine.add_tool_result_check(check)
    return engine


__all__ = ["build_autolabeler", "build_engine", "default_approver", "load_policy"]
