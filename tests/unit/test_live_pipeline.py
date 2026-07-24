import json
from datetime import UTC, datetime
from pathlib import Path

from packages.common.canonical import canonical_json_bytes
from packages.delivery.discord import build_discord_delivery_plan
from packages.delivery.local import build_local_delivery_plan
from packages.discovery.clients import DiscoverySignal
from packages.pipeline.frozen import run_frozen_fixture
from packages.pipeline.live import (
    LiveRunSettings,
    _discovery_baselines,
    _existing_morning_result,
)


def test_discovery_baseline_uses_first_current_signal_per_cve() -> None:
    generated_at = datetime(2026, 7, 24, 12, tzinfo=UTC)
    signals = [
        DiscoverySignal(
            source_id="brave-web",
            title="Current report",
            url="https://example.com/one",
            summary="CVE-2026-12345",
            published_at=datetime(2026, 7, 24, 10, tzinfo=UTC),
            identifiers=("CVE-2026-12345",),
        ),
        DiscoverySignal(
            source_id="x-researchers",
            title="Earlier post",
            url="https://x.com/example/status/1",
            summary="CVE-2026-12345",
            published_at=datetime(2026, 7, 24, 9, tzinfo=UTC),
            identifiers=("CVE-2026-12345",),
            source_handle="example",
        ),
    ]
    assert _discovery_baselines(signals, generated_at) == {
        "CVE-2026-12345": datetime(2026, 7, 24, 9, tzinfo=UTC)
    }


def test_existing_morning_run_is_reused_for_same_local_day(tmp_path: Path) -> None:
    run_root = tmp_path / "run_existing"
    frozen = run_frozen_fixture(
        Path("tests/fixtures/vertical_slice/early-manifest.json"),
        run_root,
    )
    plan = build_discord_delivery_plan(
        frozen.report,
        html_path=frozen.rendered.path,
        channel_id="1476897068885872814",
    )
    plan_path = run_root / f"{frozen.report['report_id']}.delivery.json"
    plan_path.write_bytes(canonical_json_bytes(plan) + b"\n")

    existing = _existing_morning_result(
        LiveRunSettings(
            output_root=tmp_path,
            discord_channel_id="1476897068885872814",
        ),
        datetime(2026, 7, 22, 18, tzinfo=UTC),
    )

    assert existing is not None
    assert existing.run_id == "run_existing"
    assert existing.report["report_id"] == frozen.report["report_id"]
    assert existing.summary == plan["summary"]
    assert existing.delivery_plan_path == plan_path


def test_existing_morning_run_is_not_reused_on_next_local_day(tmp_path: Path) -> None:
    run_root = tmp_path / "run_existing"
    frozen = run_frozen_fixture(
        Path("tests/fixtures/vertical_slice/early-manifest.json"),
        run_root,
    )
    plan = build_discord_delivery_plan(
        frozen.report,
        html_path=frozen.rendered.path,
        channel_id="1476897068885872814",
    )
    (run_root / f"{frozen.report['report_id']}.delivery.json").write_text(
        json.dumps(plan),
        encoding="utf-8",
    )

    existing = _existing_morning_result(
        LiveRunSettings(
            output_root=tmp_path,
            discord_channel_id="1476897068885872814",
        ),
        datetime(2026, 7, 23, 18, tzinfo=UTC),
    )

    assert existing is None


def test_existing_portable_morning_run_is_reused_without_discord(tmp_path: Path) -> None:
    run_root = tmp_path / "run_existing"
    frozen = run_frozen_fixture(
        Path("tests/fixtures/vertical_slice/early-manifest.json"),
        run_root,
    )
    plan = build_local_delivery_plan(
        frozen.report,
        html_path=frozen.rendered.path,
    )
    (run_root / f"{frozen.report['report_id']}.delivery.json").write_bytes(
        canonical_json_bytes(plan) + b"\n"
    )

    existing = _existing_morning_result(
        LiveRunSettings(output_root=tmp_path),
        datetime(2026, 7, 22, 18, tzinfo=UTC),
    )

    assert existing is not None
    assert existing.delivery_plan["destination"] == "file:local"
