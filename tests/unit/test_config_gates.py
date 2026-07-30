from pathlib import Path

import yaml


def test_only_approved_sources_and_schedules_are_enabled() -> None:
    sources = yaml.safe_load(Path("config/sources.yaml").read_text(encoding="utf-8"))
    schedules = yaml.safe_load(Path("config/schedules.yaml").read_text(encoding="utf-8"))
    report = yaml.safe_load(Path("config/report.yaml").read_text(encoding="utf-8"))
    embeddings = yaml.safe_load(Path("config/embeddings.yaml").read_text(encoding="utf-8"))
    enabled = {source["id"] for source in sources["sources"] if source["enabled"] is True}
    assert enabled == {
        "cisa-kev",
        "cve-list-v5",
        "nvd-cve",
        "first-epss",
        "osv",
        "github-advisories",
        "x-researchers",
        "reddit-security-web",
        "tiktok-security",
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
    assert report["discord"]["enabled"] is False
    assert report["publication"]["external_delivery_enabled"] is False
    assert report["publication"]["shadow_mode"] is False
    assert embeddings["semantic_clustering"]["enabled"] is True
    assert embeddings["semantic_clustering"]["mode"] == "shadow"
    assert embeddings["semantic_clustering"]["provider"] == "ollama"


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


def test_lobster_edition_reaches_live_runner() -> None:
    workflow = Path("openclaw/workflows/threat-radar.lobster").read_text(encoding="utf-8")
    runner = Path("scripts/run-live.sh").read_text(encoding="utf-8")
    assert 'default: "morning"' in workflow
    assert 'radar_edition="${LOBSTER_ARG_EDITION:-morning}"' in runner
    assert '--edition "${radar_edition}"' in runner
