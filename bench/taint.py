"""Micro-benchmark for taint matching: 10,000-entry table, 10 KB outbound payload.

Budget (roadmap Task 11): under 2 ms per outbound call.

    uv run python -m bench.taint
"""

from __future__ import annotations

import base64
import random
import statistics
import string
import time
from collections.abc import Callable

from airlock.taint.extract import extract_values
from airlock.taint.table import TaintTable
from airlock.taint.tracker import walk_arguments

ENTRIES = 10_000
PAYLOAD_BYTES = 10_240
REPEATS = 200


def _random_token(rng: random.Random, length: int) -> str:
    return "".join(rng.choices(string.ascii_letters + string.digits, k=length))


def build_table(rng: random.Random) -> TaintTable:
    """Fill a table with a realistic mix: tokens, emails, URLs, numbers."""
    table = TaintTable(max_entries=ENTRIES)
    texts: list[str] = []
    for index in range(ENTRIES):
        kind = index % 4
        if kind == 0:
            texts.append(f"user{index}@example{index % 97}.test")
        elif kind == 1:
            texts.append(f"https://site{index}.example/path/{_random_token(rng, 8)}")
        elif kind == 2:
            texts.append(f"+44 20 {rng.randint(1000, 9999)} {rng.randint(1000, 9999)}")
        else:
            texts.append(_random_token(rng, 24))
    for chunk in range(0, len(texts), 50):
        for value in extract_values(" ".join(texts[chunk : chunk + 50])):
            table.add(
                key=value.key,
                family=value.family,
                kind=value.kind,
                value=value.value,
                label="untrusted",
                source_server="bench",
                source_tool="read",
                call_index=0,
                snippet="",
            )
        table.commit()
    return table


def _payload(rng: random.Random, with_blob: bool) -> dict[str, object]:
    words = [_random_token(rng, rng.randint(3, 10)) for _ in range(2000)]
    text = " ".join(words)
    if with_blob:
        # Put the blob first so truncation to 10 KB keeps it.
        blob = base64.b64encode(" ".join(words[:200]).encode()).decode()
        text = f"{blob} {text}"
    text = text[:PAYLOAD_BYTES]
    return {"to": "someone@nowhere.test", "subject": "Report", "body": text}


def _time(function: Callable[[], object]) -> tuple[float, float]:
    for _ in range(10):
        function()
    samples = []
    for _ in range(REPEATS):
        started = time.perf_counter()
        function()
        samples.append((time.perf_counter() - started) * 1000)
    samples.sort()
    return statistics.median(samples), samples[int(len(samples) * 0.95) - 1]


def main() -> None:
    rng = random.Random(0)
    started = time.perf_counter()
    table = build_table(rng)
    fill_ms = (time.perf_counter() - started) * 1000
    print(f"table entries: {len(table)} (filled in {fill_ms:.0f} ms)")

    def scan(arguments: dict[str, object]) -> Callable[[], object]:
        return lambda: [table.match(value) for _, value in walk_arguments(arguments)]

    print("| payload | p50 ms | p95 ms |")
    print("|---|---:|---:|")
    for name, payload in (
        ("10 KB plain text", _payload(rng, with_blob=False)),
        ("10 KB with base64 blob", _payload(rng, with_blob=True)),
    ):
        p50, p95 = _time(scan(payload))
        print(f"| {name} | {p50:.3f} | {p95:.3f} |")

    def commit_cost() -> None:
        table.add(
            key=_random_token(rng, 20).lower(),
            family="text",
            kind="token",
            value="x",
            label="untrusted",
            source_server="bench",
            source_tool="read",
            call_index=0,
            snippet="",
        )
        table.commit()

    p50, p95 = _time(commit_cost)
    print(f"| add + commit (delta rebuild, result path) | {p50:.3f} | {p95:.3f} |")


if __name__ == "__main__":
    main()
