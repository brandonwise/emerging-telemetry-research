from pathlib import Path

import yaml


def test_only_approved_sources_schedule_and_delivery_are_enabled() -> None:
    sources = yaml.safe_load(Path("config/sources.yaml").read_text(encoding="utf-8"))
    schedules = yaml.safe_load(Path("config/schedules.yaml").read_text(encoding="utf-8"))
    report = yaml.safe_load(Path("config/report.yaml").read_text(encoding="utf-8"))
    enabled = {source["id"] for source in sources["sources"] if source["enabled"] is True}
    assert enabled == {
        "cisa-kev",
        "cve-list-v5",
        "nvd-cve",
        "first-epss",
        "osv",
        "github-advisories",
        "x-researchers",
        "brave-web",
    }
    assert all(
        source.get("collection_approval_id")
        for source in sources["sources"]
        if source["enabled"] is True
    )
    assert sources["defaults"]["collection_approval_required"] is True
    assert schedules["enabled"] is True
    assert schedules["jobs"]["morning_brief"]["enabled"] is True
    assert report["discord"]["enabled"] is True
    assert report["publication"]["external_delivery_enabled"] is True
    assert report["publication"]["shadow_mode"] is False


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
