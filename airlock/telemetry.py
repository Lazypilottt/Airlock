"""OpenTelemetry: one span per decision and a counter per verdict.

Uses only ``opentelemetry-api`` (installed with the ``mcp`` SDK) at runtime.
``setup_otlp`` wires an OTLP/HTTP exporter and needs the ``otel`` extra.

Span ``airlock <direction> <server>.<tool>`` attributes: ``airlock.tool``,
``airlock.server``, ``airlock.direction``, ``airlock.verdict``,
``airlock.would_have`` (shadow mode), ``airlock.rule``, ``airlock.latency_ms``
and the top three scores as ``airlock.score.<name>``. Counter
``airlock.decisions`` with attributes ``verdict`` and ``direction``.
"""

from __future__ import annotations

import sys
import time
from typing import Any

from airlock.config import OtelConfig
from airlock.models import Decision

_TOP_SCORES = 3


class Telemetry:
    """Records engine decisions as spans and counter increments."""

    def __init__(self, tracer: Any = None, meter: Any = None) -> None:
        if tracer is None or meter is None:
            from opentelemetry import metrics, trace

            tracer = tracer or trace.get_tracer("airlock")
            meter = meter or metrics.get_meter("airlock")
        self.tracer = tracer
        self.decisions = meter.create_counter(
            "airlock.decisions", unit="1", description="Airlock decisions by verdict"
        )

    def record(
        self, direction: str, server: str, tool: str, decision: Decision, latency_ms: float
    ) -> None:
        end = time.time_ns()
        start = end - int(max(latency_ms, 0.0) * 1_000_000)
        span = self.tracer.start_span(f"airlock {direction} {server}.{tool}", start_time=start)
        try:
            attributes: dict[str, Any] = {
                "airlock.tool": tool,
                "airlock.server": server,
                "airlock.direction": direction,
                "airlock.verdict": decision.verdict.value,
                "airlock.rule": decision.rule or "",
                "airlock.latency_ms": float(latency_ms),
            }
            if decision.would_have is not None:
                attributes["airlock.would_have"] = decision.would_have.value
            scores = [
                (name, value)
                for name, value in decision.scores.items()
                if not name.startswith("latency.")
            ]
            for name, value in sorted(scores, key=lambda item: -item[1])[:_TOP_SCORES]:
                attributes[f"airlock.score.{name}"] = float(value)
            for key, value in attributes.items():
                span.set_attribute(key, value)
        finally:
            span.end(end_time=end)
        self.decisions.add(1, {"verdict": decision.verdict.value, "direction": direction})


def setup_otlp(config: OtelConfig) -> Telemetry | None:
    """Install OTLP/HTTP trace and metric exporters; ``None`` (with a warning) if unavailable."""
    try:
        from opentelemetry import metrics, trace
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError as exc:
        sys.stderr.write(
            f"airlock: otel.enabled is set but the otel extra is missing ({exc}); "
            "install airlock-mcp[otel]. Continuing without telemetry.\n"
        )
        return None
    endpoint = config.endpoint.rstrip("/")
    resource = Resource.create({"service.name": config.service_name})
    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint=f"{endpoint}/v1/traces"))
    )
    meter_provider = MeterProvider(
        resource=resource,
        metric_readers=[
            PeriodicExportingMetricReader(OTLPMetricExporter(endpoint=f"{endpoint}/v1/metrics"))
        ],
    )
    trace.set_tracer_provider(tracer_provider)
    metrics.set_meter_provider(meter_provider)
    return Telemetry(tracer_provider.get_tracer("airlock"), meter_provider.get_meter("airlock"))


__all__ = ["Telemetry", "setup_otlp"]
