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


if __name__ == "__main__":
    main()
