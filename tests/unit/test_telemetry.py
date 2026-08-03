import pytest

from packages.telemetry.runtime import ResearchTelemetry


def test_telemetry_rejects_unbounded_status_and_risk_labels() -> None:
    telemetry = ResearchTelemetry.current("research-test")
    with pytest.raises(ValueError, match="status"):
        telemetry.workflow_run(mode="fixture", status="secret-bearing-arbitrary-value")
    with pytest.raises(ValueError, match="risk"):
        telemetry.security_event(category="content", risk="unknown", disposition="blocked")


def test_noop_telemetry_records_bounded_events() -> None:
    telemetry = ResearchTelemetry.current("research-test")
    telemetry.workflow_run(mode="fixture", status="ok")
    telemetry.source_fetch(source_id="cisa-kev", status="degraded")
    telemetry.model_request(
        provider="fixture",
        model="deterministic",
        agent_id="specialist",
        stage="review",
        status="ok",
        estimated_cost=0,
    )
    telemetry.delivery(channel="discord", status="disabled")
    telemetry.security_event(category="content", risk="high", disposition="deterministic_only")
    telemetry.stage_latency(stage="render", status="ok", milliseconds=12.5)
