"""Measure detector layer latency on representative CPU inputs."""

from __future__ import annotations

import statistics
import time

from airlock.config import AirlockConfig
from airlock.detect.classifier import ModelUnavailable, PromptGuardClassifier
from airlock.detect.normalize import normalize
from airlock.detect.rules import RuleDetector


def _measure(function: object, text: str, repeats: int = 20) -> tuple[float, float]:
    samples: list[float] = []
    for _ in range(repeats):
        started = time.perf_counter()
        function(text)  # type: ignore[operator]
        samples.append((time.perf_counter() - started) * 1000)
    ordered = sorted(samples)
    return statistics.median(ordered), ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))]


def main() -> None:
    config = AirlockConfig()
    l1 = RuleDetector()
    l2 = PromptGuardClassifier(config.data_dir, config.classifier)
    print("| input | L0 p50/p95 ms | L1 p50/p95 ms | L2 p50/p95 ms |")
    print("|---:|---:|---:|---:|")
    for size in (200, 2_000, 20_000):
        text = ("A benign sentence with instructions and system documentation. " * size)[:size]
        l0 = _measure(lambda value: normalize(value), text)
        l1_result = _measure(lambda value: l1.detect(value, "result"), text)
        try:
            l2_result = _measure(lambda value: l2.score(value), text)
            l2_text = f"{l2_result[0]:.2f}/{l2_result[1]:.2f}"
        except ModelUnavailable:
            l2_text = "unavailable"
        print(
            f"| {size} | {l0[0]:.2f}/{l0[1]:.2f} | "
            f"{l1_result[0]:.2f}/{l1_result[1]:.2f} | {l2_text} |"
        )


async def _engine_latency() -> None:
    """End to end through the default engine: honeytokens, taint, policy and detectors."""
    import tempfile
    from pathlib import Path

    from airlock.engine_factory import build_engine
    from airlock.honeytokens.store import HoneytokenFile, save, store_path
    from airlock.honeytokens.tokens import create_set
    from airlock.models import ToolCall, ToolDef, ToolResult

    data_dir = Path(tempfile.mkdtemp(prefix="airlock-latency-"))
    save(store_path(data_dir), HoneytokenFile(tokens=[t for _ in range(10) for t in create_set()]))
    engine = build_engine(AirlockConfig(data_dir=data_dir))
    await engine.on_tools_listed(
        "web",
        [
            ToolDef(server_id="web", name="read_page", description="Fetch a web page"),
            ToolDef(server_id="web", name="send_email", description="Send an email"),
        ],
    )
    # Fill the taint table to its default size (10,000 entries) from web pages.
    words = " ".join(f"https://site{i}.example/page/{i:06d}" for i in range(10_000))
    await engine.on_tool_result(
        ToolResult(
            session_id="s",
            server_id="web",
            tool_name="read_page",
            request_id=0,
            content=[{"type": "text", "text": words}],
        )
    )
    body = ("The quarterly report shows steady growth across all regions. " * 170)[:10_000]
    calls: list[float] = []
    results: list[float] = []
    for index in range(1, 101):
        started = time.perf_counter()
        await engine.on_tool_call(
            ToolCall(
                session_id="s",
                server_id="web",
                tool_name="send_email",
                arguments={"to": "bob@ok.example", "body": body},
                request_id=index,
            )
        )
        calls.append((time.perf_counter() - started) * 1000)
        started = time.perf_counter()
        await engine.on_tool_result(
            ToolResult(
                session_id="s",
                server_id="web",
                tool_name="send_email",
                request_id=index,
                content=[{"type": "text", "text": body}],
            )
        )
        results.append((time.perf_counter() - started) * 1000)
    await engine.close()

    def p50_p95(samples: list[float]) -> str:
        ordered = sorted(samples)
        return f"{statistics.median(ordered):.2f}/{ordered[int(len(ordered) * 0.95)]:.2f}"

    print()
    print("| default engine, 10 KB payload, 10,000 taint entries, 50 honeytokens | p50/p95 ms |")
    print("|---|---:|")
    print(f"| tool call (honeytoken + taint + policy) | {p50_p95(calls)} |")
    print(f"| tool result (taint record + detectors + policy) | {p50_p95(results)} |")


if __name__ == "__main__":
    import asyncio

    main()
    asyncio.run(_engine_latency())
