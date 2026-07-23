from pathlib import Path

import yaml


def test_sources_schedules_and_delivery_default_off() -> None:
    sources = yaml.safe_load(Path("config/sources.yaml").read_text(encoding="utf-8"))
    schedules = yaml.safe_load(Path("config/schedules.yaml").read_text(encoding="utf-8"))
    report = yaml.safe_load(Path("config/report.yaml").read_text(encoding="utf-8"))
    assert all(source["enabled"] is False for source in sources["sources"])
    assert sources["defaults"]["collection_approval_required"] is True
    assert schedules["enabled"] is False
    assert report["discord"]["enabled"] is False
    assert report["publication"]["external_delivery_enabled"] is False


def test_migration_covers_required_tables() -> None:
    migration = Path("migrations/0001_initial.sql").read_text(encoding="utf-8")
    required = {
        "runs",
        "workflow_steps",
        "source_registry",
        "source_cursors",
        "source_health",
        "raw_artifacts",
        "sanitized_artifacts",
        "observations",
        "entities",
        "clusters",
        "assessments",
        "evidence_items",
        "reports",
        "model_usage",
        "deliveries",
        "policy_decisions",
        "security_events",
    }
    assert all(f"CREATE TABLE {table}" in migration for table in required)
