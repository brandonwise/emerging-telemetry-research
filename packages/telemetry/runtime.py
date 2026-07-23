from __future__ import annotations

import os
from contextlib import AbstractContextManager
from typing import Any

from opentelemetry import metrics, trace
from opentelemetry.metrics import Counter, Histogram, Meter
from opentelemetry.trace import Span, Tracer

ALLOWED_STATUSES = {"ok", "degraded", "failed", "blocked", "disabled"}
ALLOWED_RISKS = {"low", "medium", "high", "critical"}


class RadarTelemetry:
    """Telemetry facade that cannot accept source content, URIs, prompts, or credentials."""

    def __init__(self, tracer: Tracer, meter: Meter) -> None:
        self._tracer = tracer
        self._workflow_runs: Counter = meter.create_counter(
            "radar.workflow.runs",
            description="Threat Radar workflow outcomes",
        )
        self._source_fetches: Counter = meter.create_counter(
            "radar.source.fetches",
            description="Safe-fetch outcomes by registered source",
        )
        self._model_requests: Counter = meter.create_counter(
            "radar.model.requests",
            description="Model requests by provider, model, agent, and stage",
        )
        self._model_cost: Counter = meter.create_counter(
            "radar.model.estimated_cost",
            unit="USD",
            description="Estimated model cost",
        )
        self._delivery_attempts: Counter = meter.create_counter(
            "radar.delivery.attempts",
            description="Delivery outcomes by configured channel",
        )
        self._security_events: Counter = meter.create_counter(
            "radar.security.events",
            description="Content and policy security events",
        )
        self._stage_latency: Histogram = meter.create_histogram(
            "radar.stage.duration",
            unit="ms",
            description="Stage latency",
        )

    @classmethod
    def current(cls, service_name: str) -> RadarTelemetry:
        return cls(
            trace.get_tracer(service_name),
            metrics.get_meter(service_name),
        )

    def span(
        self,
        name: str,
        *,
        run_id: str | None = None,
        stage: str | None = None,
    ) -> AbstractContextManager[Span]:
        attributes = _compact(
            {
                "radar.run_id": run_id,
                "radar.stage": stage,
            }
        )
        return self._tracer.start_as_current_span(name, attributes=attributes)

    def workflow_run(self, *, mode: str, status: str) -> None:
        self._workflow_runs.add(1, {"radar.mode": mode, "radar.status": _status(status)})

    def source_fetch(self, *, source_id: str, status: str) -> None:
        self._source_fetches.add(
            1,
            {"radar.source_id": source_id, "radar.status": _status(status)},
        )

    def model_request(
        self,
        *,
        provider: str,
        model: str,
        agent_id: str,
        stage: str,
        status: str,
        estimated_cost: float,
    ) -> None:
        attributes = {
            "gen_ai.system": provider,
            "gen_ai.request.model": model,
            "radar.agent_id": agent_id,
            "radar.stage": stage,
            "radar.status": _status(status),
        }
        self._model_requests.add(1, attributes)
        self._model_cost.add(max(0, estimated_cost), attributes)

    def delivery(self, *, channel: str, status: str) -> None:
        self._delivery_attempts.add(
            1,
            {"radar.channel": channel, "radar.status": _status(status)},
        )

    def security_event(self, *, category: str, risk: str, disposition: str) -> None:
        if risk not in ALLOWED_RISKS:
            raise ValueError("unknown security risk")
        self._security_events.add(
            1,
            {
                "radar.category": category,
                "radar.risk": risk,
                "radar.disposition": disposition,
            },
        )

    def stage_latency(self, *, stage: str, status: str, milliseconds: float) -> None:
        self._stage_latency.record(
            max(0, milliseconds),
            {"radar.stage": stage, "radar.status": _status(status)},
        )


def configure_from_environment(service_name: str) -> RadarTelemetry:
    endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        return RadarTelemetry.current(service_name)

    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor

    resource = Resource.create(
        {
            "service.name": service_name,
            "deployment.environment.name": os.getenv("RADAR_ENVIRONMENT", "development"),
        }
    )
    insecure = endpoint.lower().startswith("http://")
    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(
        BatchSpanProcessor(OTLPSpanExporter(endpoint=endpoint, insecure=insecure))
    )
    meter_provider = MeterProvider(
        resource=resource,
        metric_readers=[
            PeriodicExportingMetricReader(
                OTLPMetricExporter(endpoint=endpoint, insecure=insecure),
            )
        ],
    )
    trace.set_tracer_provider(tracer_provider)
    metrics.set_meter_provider(meter_provider)
    return RadarTelemetry(
        tracer_provider.get_tracer(service_name),
        meter_provider.get_meter(service_name),
    )


def _status(value: str) -> str:
    if value not in ALLOWED_STATUSES:
        raise ValueError("unknown telemetry status")
    return value


def _compact(attributes: dict[str, str | None]) -> dict[str, Any]:
    return {key: value for key, value in attributes.items() if value is not None}
